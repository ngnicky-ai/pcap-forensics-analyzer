using System.Diagnostics;
using System.IO;
using System.Windows;
using System.Windows.Media;
using Microsoft.Win32;
using PcapForensics.App.Converters;
using PcapForensics.Core.Analysis;
using PcapForensics.Core.Detection;
using PcapForensics.Core.Ids;
using PcapForensics.Core.Model;
using PcapForensics.Core.Reporting;
using PcapForensics.Core.Util;

namespace PcapForensics.App.ViewModels;

public sealed class MainViewModel : ObservableObject
{
    public const int TabFindings = 1, TabSessions = 3, TabPackets = 9, TabIds = 10;

    readonly PcapAnalyzer _analyzer = new();
    CancellationTokenSource? _cts;
    AnalysisResult? _result;

    public MainViewModel()
    {
        OpenCommand = new RelayCommand(_ => BrowseAndOpen(), _ => !IsBusy);
        LoadIocCommand = new RelayCommand(_ => LoadIoc(), _ => !IsBusy);
        ReloadRulesCommand = new RelayCommand(_ => ReloadRules(), _ => !IsBusy);
        OpenRulesFolderCommand = new RelayCommand(_ => OpenFolder(Path.Combine(AppContext.BaseDirectory, "rules")));
        ExportHtmlCommand = new RelayCommand(_ => ExportHtml(), _ => HasResult && !IsBusy);
        ExportCsvCommand = new RelayCommand(_ => ExportCsv(), _ => HasResult && !IsBusy);
        ExportFilesCommand = new RelayCommand(_ => ExportFiles(), _ => HasResult && !IsBusy && _result!.Files.Count > 0);
        SaveSelectedFileCommand = new RelayCommand(_ => SaveSelectedFile(), _ => SelectedFile is not null);
        CancelCommand = new RelayCommand(_ => _cts?.Cancel(), _ => IsBusy);
        RunSuricataCommand = new RelayCommand(_ => _ = RunSuricataAsync(), _ => HasResult && !IsBusy);
        ImportEveCommand = new RelayCommand(_ => ImportEve(), _ => HasResult && !IsBusy);
        UpdateRulesCommand = new RelayCommand(_ => _ = UpdateRulesAsync(), _ => !IsBusy);
        ShowAlertSessionCommand = new RelayCommand(_ => ShowSessions(new[] { SelectedAlert!.SessionId!.Value }), _ => SelectedAlert?.SessionId is > 0);
        ShowFindingSessionsCommand = new RelayCommand(_ => ShowFindingSessions(), _ => SelectedFinding?.SessionIds.Count > 0);
        ShowSessionPacketsCommand = new RelayCommand(_ => ShowSessionPackets(), _ => SelectedSession is not null);
        ShowEventSessionCommand = new RelayCommand(_ => ShowSessions(new[] { SelectedTimelineEvent!.SessionId!.Value }), _ => SelectedTimelineEvent?.SessionId is > 0);
        ShowHttpSessionCommand = new RelayCommand(_ => ShowSessions(new[] { SelectedHttp!.SessionId }), _ => SelectedHttp is not null);

        Findings = new FilteredList<Finding>(f => $"{f.SeverityText} {f.Category} {f.Title} {f.SourceIp} {f.TargetIp} {f.Mitre} {f.Description}");
        Timeline = new FilteredList<TimelineEvent>(e => $"{e.Category} {e.SeverityText} {e.Source} {e.Destination} {e.Summary}")
        {
            ExtraFilter = e => _timelineCategory == "전체" || e.Category == _timelineCategory,
        };
        Sessions = new FilteredList<NetworkSession>(s => $"{s.Id} {s.TransportText} {s.AppProtocol} {s.ClientEndpoint} {s.ServerEndpoint} {s.ServerName} {s.State} {s.Summary}")
        {
            TokenMatcher = (s, t) => t.StartsWith("id:", StringComparison.OrdinalIgnoreCase)
                ? t[3..].Split(',').Contains(s.Id.ToString())
                : null,
        };
        Http = new FilteredList<HttpTransaction>(h => $"{h.ClientIp} {h.ServerIp} {h.Method} {h.Url} {h.StatusText} {h.ContentType} {h.UserAgent}");
        Dns = new FilteredList<DnsTransaction>(d => $"{d.ClientIp} {d.ServerIp} {d.QueryName} {d.QueryType} {d.RCodeText} {d.AnswersText}");
        Tls = new FilteredList<TlsHandshakeInfo>(t => $"{t.ClientIp} {t.ServerIp} {t.Sni} {t.Version}");
        Credentials = new FilteredList<CredentialRecord>(c => $"{c.Protocol} {c.ClientIp} {c.ServerIp} {c.Username} {c.ResultText} {c.Detail}");
        Files = new FilteredList<ExtractedFile>(f => $"{f.Source} {f.Host} {f.FileName} {f.Kind} {f.CategoryText} {f.Md5} {f.Sha256} {f.Location}");
        IdsAlerts = new FilteredList<IdsAlert>(a => $"{a.SeverityText} {a.Sid} {a.Signature} {a.Classification} {a.Source} {a.Destination} {a.AppProto} {a.Detail}");
        Packets = new FilteredList<PacketRecord>(p => $"{p.Source} {p.Destination} {p.ProtocolName} {p.Info}")
        {
            TokenMatcher = (p, t) =>
                t.StartsWith("sid:", StringComparison.OrdinalIgnoreCase) ? p.SessionId.ToString() == t[4..]
                : t.StartsWith("no:", StringComparison.OrdinalIgnoreCase) ? p.Index.ToString() == t[3..]
                : null,
        };
    }

    // ---------- 명령 ----------
    public RelayCommand OpenCommand { get; }
    public RelayCommand LoadIocCommand { get; }
    public RelayCommand ReloadRulesCommand { get; }
    public RelayCommand OpenRulesFolderCommand { get; }
    public RelayCommand ExportHtmlCommand { get; }
    public RelayCommand ExportCsvCommand { get; }
    public RelayCommand ExportFilesCommand { get; }
    public RelayCommand SaveSelectedFileCommand { get; }
    public RelayCommand CancelCommand { get; }
    public RelayCommand ShowFindingSessionsCommand { get; }
    public RelayCommand ShowSessionPacketsCommand { get; }
    public RelayCommand ShowEventSessionCommand { get; }
    public RelayCommand ShowHttpSessionCommand { get; }
    public RelayCommand RunSuricataCommand { get; }
    public RelayCommand ImportEveCommand { get; }
    public RelayCommand UpdateRulesCommand { get; }
    public RelayCommand ShowAlertSessionCommand { get; }

    // ---------- 상태 ----------
    bool _isBusy;
    public bool IsBusy { get => _isBusy; set => Set(ref _isBusy, value); }

    double _progress;
    public double ProgressValue { get => _progress; set => Set(ref _progress, value); }

    string _progressText = "";
    public string ProgressText { get => _progressText; set => Set(ref _progressText, value); }

    string _status = "PCAP 파일을 열거나 창에 끌어다 놓으세요.";
    public string StatusText { get => _status; set => Set(ref _status, value); }

    public bool HasResult => _result is not null;
    public PcapForensics.Core.Capture.CaptureSettings CaptureSettings => _analyzer.Settings.Capture;
    public string FileTitle => _result is null ? "" : $"{_result.FileName}  ·  {TimeFormat.Bytes(_result.FileSize)}";
    public string FileHash => _result?.FileSha256 ?? "";
    public string IocStatus => _analyzer.Iocs.Count == 0 ? "IOC 미적용" : $"IOC {_analyzer.Iocs.Count:N0}개 적용 ({Path.GetFileName(_analyzer.Iocs.SourcePath)})";
    public string WarningsText => _result is null ? "" : string.Join("\n", _result.Warnings);

    int _selectedTab;
    public int SelectedTabIndex { get => _selectedTab; set => Set(ref _selectedTab, value); }

    // ---------- 대시보드 ----------
    public string PacketCountText => _result is null ? "-" : $"{_result.Statistics.PacketCount:N0}";
    public string BytesText => _result is null ? "" : TimeFormat.Bytes(_result.Statistics.TotalBytes);
    public string SessionCountText => _result is null ? "-" : $"{_result.Sessions.Count:N0}";
    public string SessionSubText => _result is null ? "" : $"TCP {_result.Statistics.TcpSessionCount:N0} · UDP {_result.Statistics.UdpSessionCount:N0}";
    public string DurationText => _result is null ? "-" : TimeFormat.Duration(_result.Statistics.Duration);
    public string RangeText => _result is null ? "" : $"{TimeFormat.Format(_result.Statistics.Start)} ~ {TimeFormat.Format(_result.Statistics.End)} UTC";
    public string HostCountText => _result is null ? "-" : $"{_result.Statistics.UniqueIpCount:N0}";
    public string ArtifactText => _result is null ? "" : $"HTTP {_result.Http.Count:N0} · DNS {_result.Dns.Count:N0} · 파일 {_result.Files.Count:N0}";
    public bool HasFindings => _result?.Findings.Count > 0;
    public int CriticalCount =>_result?.CountBySeverity(Severity.Critical) ?? 0;
    public int HighCount => _result?.CountBySeverity(Severity.High) ?? 0;
    public int MediumCount => _result?.CountBySeverity(Severity.Medium) ?? 0;
    public int LowCount => (_result?.CountBySeverity(Severity.Low) ?? 0) + (_result?.CountBySeverity(Severity.Info) ?? 0);
    public string Verdict => _result is null ? "" :
        CriticalCount > 0 ? "침해 정황이 확인되었습니다. 심각 등급 탐지를 우선 확인하십시오." :
        HighCount > 0 ? "공격 시도가 확인되었습니다. 높음 등급 탐지를 검토하십시오." :
        MediumCount > 0 ? "주의가 필요한 이벤트가 있습니다." : "탐지 규칙에 해당하는 위협이 발견되지 않았습니다.";
    public Brush VerdictBrush => SeverityBrushConverter.For(
        CriticalCount > 0 ? Severity.Critical : HighCount > 0 ? Severity.High : MediumCount > 0 ? Severity.Medium : Severity.Low);

    public IReadOnlyList<BarItem> ProtocolBars { get; private set; } = Array.Empty<BarItem>();
    public IReadOnlyList<BarItem> TalkerBars { get; private set; } = Array.Empty<BarItem>();
    public IReadOnlyList<BarItem> PortBars { get; private set; } = Array.Empty<BarItem>();
    public IReadOnlyList<BarItem> ExternalBars { get; private set; } = Array.Empty<BarItem>();
    public IReadOnlyList<BarItem> DomainBars { get; private set; } = Array.Empty<BarItem>();
    public IReadOnlyList<BarItem> CategoryBars { get; private set; } = Array.Empty<BarItem>();
    public IReadOnlyList<double>? TrafficValues => _result?.Statistics.TrafficSeries;
    public string TrafficStart => _result?.Statistics.Start is DateTime s ? s.ToString("HH:mm:ss") : "";
    public string TrafficEnd => _result?.Statistics.End is DateTime e ? e.ToString("HH:mm:ss") + " UTC" : "";
    public string TrafficCaption => _result is null ? "" : $"{_result.Statistics.BucketSeconds:F0}초 단위 전송량";

    // ---------- 목록 ----------
    public FilteredList<Finding> Findings { get; }
    public FilteredList<TimelineEvent> Timeline { get; }
    public FilteredList<NetworkSession> Sessions { get; }
    public FilteredList<HttpTransaction> Http { get; }
    public FilteredList<DnsTransaction> Dns { get; }
    public FilteredList<TlsHandshakeInfo> Tls { get; }
    public FilteredList<CredentialRecord> Credentials { get; }
    public FilteredList<ExtractedFile> Files { get; }
    public FilteredList<PacketRecord> Packets { get; }
    public FilteredList<IdsAlert> IdsAlerts { get; }
    public string IdsHeader => $"IDS 경보 ({_result?.IdsAlerts.Count(a => !a.Ignored) ?? 0:N0})";
    public string IdsSourceText => _result is null || _result.IdsSource.Length == 0
        ? $"아직 IDS 검사를 하지 않았습니다. [Suricata 검사] 또는 [eve.json 가져오기]를 사용하십시오.  ·  {EtOpenRules.Status}"
        : $"{_result.IdsSource}  ·  경보 {_result.IdsAlerts.Count(a => !a.Ignored):N0}건, 설정에 따라 제외 {_result.IdsAlerts.Count(a => a.Ignored):N0}건";

    IdsAlert? _selectedAlert;
    public IdsAlert? SelectedAlert
    {
        get => _selectedAlert;
        set
        {
            if (Set(ref _selectedAlert, value)) Raise(nameof(AlertDetailText));
        }
    }

    public string AlertDetailText => _selectedAlert is not { } a ? "경보를 선택하면 전체 내용이 표시됩니다." :
        $"[{a.SeverityText}] {a.Signature}\n" +
        $"룰 {a.RuleId}  ·  분류: {a.Classification}  ·  우선순위 {a.Priority}  ·  {a.Proto}/{a.AppProto}  ·  {a.Source} → {a.Destination}" +
        (a.SessionId is int sid ? $"  ·  세션 #{sid}" : "  ·  연결된 세션 없음") + "\n" +
        (a.Detail.Length > 0 ? $"상세: {a.Detail}\n" : "") +
        (a.Mitre.Length > 0 ? $"MITRE ATT&CK: {a.Mitre}" : "");

    public string FindingsHeader => $"탐지 결과 ({_result?.Findings.Count ?? 0})";
    public string SessionsHeader => $"세션 ({_result?.Sessions.Count ?? 0:N0})";
    public string HttpHeader => $"HTTP ({_result?.Http.Count ?? 0:N0})";
    public string DnsHeader => $"DNS ({_result?.Dns.Count ?? 0:N0})";
    public string TlsHeader => $"TLS ({_result?.Tls.Count ?? 0:N0})";
    public string CredentialsHeader => $"인증 정보 ({_result?.Credentials.Count ?? 0:N0})";
    public string FilesHeader => $"추출 파일 ({_result?.Files.Count ?? 0:N0})";
    public string PacketsHeader => $"패킷 ({_result?.Packets.Count ?? 0:N0})";
    public string TimelineHeader => $"타임라인 ({_result?.Timeline.Count ?? 0:N0})";

    public IReadOnlyList<string> TimelineCategories { get; } = new[] { "전체", "탐지", "HTTP", "DNS", "TLS", "인증", "FTP", "파일" };
    string _timelineCategory = "전체";
    public string TimelineCategory
    {
        get => _timelineCategory;
        set
        {
            if (Set(ref _timelineCategory, value)) Timeline.Refresh();
        }
    }

    // ---------- 선택 상세 ----------
    Finding? _selectedFinding;
    public Finding? SelectedFinding { get => _selectedFinding; set => Set(ref _selectedFinding, value); }

    TimelineEvent? _selectedEvent;
    public TimelineEvent? SelectedTimelineEvent { get => _selectedEvent; set => Set(ref _selectedEvent, value); }

    NetworkSession? _selectedSession;
    public NetworkSession? SelectedSession
    {
        get => _selectedSession;
        set
        {
            if (Set(ref _selectedSession, value)) UpdateStreamView();
        }
    }

    bool _streamHex;
    public bool StreamHex
    {
        get => _streamHex;
        set
        {
            if (Set(ref _streamHex, value)) UpdateStreamView();
        }
    }

    string _streamHeader = "세션을 선택하면 재조립된 스트림이 표시됩니다.";
    public string StreamHeader { get => _streamHeader; set => Set(ref _streamHeader, value); }
    string _clientStream = "";
    public string ClientStreamText { get => _clientStream; set => Set(ref _clientStream, value); }
    string _serverStream = "";
    public string ServerStreamText { get => _serverStream; set => Set(ref _serverStream, value); }

    HttpTransaction? _selectedHttp;
    public HttpTransaction? SelectedHttp
    {
        get => _selectedHttp;
        set
        {
            if (!Set(ref _selectedHttp, value)) return;
            HttpRequestText = value is null ? "" : FormatRequest(value);
            HttpResponseText = value is null ? "" : FormatResponse(value);
        }
    }
    string _httpRequest = "";
    public string HttpRequestText { get => _httpRequest; set => Set(ref _httpRequest, value); }
    string _httpResponse = "";
    public string HttpResponseText { get => _httpResponse; set => Set(ref _httpResponse, value); }

    ExtractedFile? _selectedFile;
    public ExtractedFile? SelectedFile
    {
        get => _selectedFile;
        set
        {
            if (!Set(ref _selectedFile, value)) return;
            FilePreviewText = value is null ? "" : FormatFile(value);
        }
    }
    string _filePreview = "";
    public string FilePreviewText { get => _filePreview; set => Set(ref _filePreview, value); }

    PacketRecord? _selectedPacket;
    public PacketRecord? SelectedPacket
    {
        get => _selectedPacket;
        set
        {
            if (!Set(ref _selectedPacket, value)) return;
            PacketDetailText = value is null ? "" : FormatPacket(value);
        }
    }
    string _packetDetail = "";
    public string PacketDetailText { get => _packetDetail; set => Set(ref _packetDetail, value); }

    // ---------- 동작 ----------
    void BrowseAndOpen()
    {
        var dlg = new OpenFileDialog
        {
            Title = "분석할 캡처 파일 선택",
            Filter = "패킷 캡처 (*.pcap;*.pcapng;*.cap)|*.pcap;*.pcapng;*.cap|모든 파일 (*.*)|*.*",
        };
        if (dlg.ShowDialog() == true) _ = OpenFileAsync(dlg.FileName);
    }

    /// <param name="note">분석 결과 경고 맨 앞에 붙일 설명(예: 실시간 모니터링 중지 사유).</param>
    public async Task OpenFileAsync(string path, string? note = null)
    {
        if (IsBusy) return;
        IsBusy = true;
        _cts = new CancellationTokenSource();
        StatusText = $"분석 중: {Path.GetFileName(path)}";
        var progress = new Progress<AnalysisProgress>(p =>
        {
            ProgressValue = p.Percent;
            ProgressText = p.Stage;
        });

        try
        {
            var token = _cts.Token;
            var result = await Task.Run(() => _analyzer.Analyze(path, progress, token), token);
            if (!string.IsNullOrEmpty(note)) result.Warnings.Insert(0, note);
            Apply(result);
            StatusText = $"분석 완료: 패킷 {result.Packets.Count:N0}개, 세션 {result.Sessions.Count:N0}개, 탐지 {result.Findings.Count}건 ({result.AnalysisTime.TotalSeconds:F1}초)" +
                         (string.IsNullOrEmpty(note) ? "" : "  ·  " + note);
            SelectedTabIndex = result.Findings.Count > 0 ? TabFindings : 0;
            if (_analyzer.Settings.Suricata.AutoRun && SuricataRunner.FindExecutable(_analyzer.Settings.Suricata.ExecutablePath) is not null)
                _suricataPending = true;
        }
        catch (OperationCanceledException)
        {
            StatusText = "분석을 취소했습니다.";
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException or UnauthorizedAccessException)
        {
            StatusText = "분석 실패";
            MessageBox.Show($"파일을 분석할 수 없습니다.\n\n{ex.Message}", "PCAP 침해사고 분석기", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
        finally
        {
            IsBusy = false;
            _cts.Dispose();
            _cts = null;
            CommandManager_Invalidate();
        }
        if (_suricataPending)
        {
            _suricataPending = false;
            await RunSuricataAsync();
        }
    }

    bool _suricataPending;

    async Task RunSuricataAsync()
    {
        if (_result is null || IsBusy) return;
        IsBusy = true;
        _cts = new CancellationTokenSource();
        ProgressValue = 50;
        ProgressText = "Suricata 검사 중 (룰 로딩에 시간이 걸릴 수 있습니다)";
        var log = new Progress<string>(line => ProgressText = "Suricata: " + TextUtil.Truncate(line, 120));
        try
        {
            await _analyzer.RunSuricataAsync(_result, log, _cts.Token);
            ApplyDetection();
            StatusText = $"Suricata 검사 완료: {_result.IdsSource}, 경보 {_result.IdsAlerts.Count(a => !a.Ignored):N0}건";
            SelectedTabIndex = TabIds;
        }
        catch (OperationCanceledException)
        {
            StatusText = "Suricata 검사를 취소했습니다.";
        }
        catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException or InvalidOperationException or TimeoutException or System.ComponentModel.Win32Exception)
        {
            StatusText = "Suricata 검사 실패";
            MessageBox.Show(ex.Message + "\n\n설치 경로와 룰 경로는 [규칙 폴더]의 settings.json → Suricata 항목에서 지정합니다.\n다른 장비에서 실행한 결과가 있다면 [eve.json 가져오기]를 사용하십시오.",
                "Suricata 검사", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
        finally
        {
            IsBusy = false;
            _cts.Dispose();
            _cts = null;
            CommandManager_Invalidate();
        }
    }

    async Task UpdateRulesAsync()
    {
        if (IsBusy) return;
        IsBusy = true;
        _cts = new CancellationTokenSource();
        ProgressValue = 30;
        var log = new Progress<string>(line => ProgressText = line);
        try
        {
            var (files, rules) = await EtOpenRules.DownloadAsync(_analyzer.Settings.Suricata.EtOpenUrl, log, _cts.Token);
            StatusText = $"ET Open 룰 {files}개 파일, 활성 룰 {rules:N0}개를 설치했습니다: {EtOpenRules.RulesDirectory}";
            Raise(nameof(IdsSourceText));
        }
        catch (OperationCanceledException)
        {
            StatusText = "룰 다운로드를 취소했습니다.";
        }
        catch (Exception ex) when (ex is System.Net.Http.HttpRequestException or IOException or InvalidDataException)
        {
            StatusText = "룰 다운로드 실패";
            MessageBox.Show(ex.Message, "ET Open 룰 받기", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
        finally
        {
            IsBusy = false;
            _cts.Dispose();
            _cts = null;
            CommandManager_Invalidate();
        }
    }

    void ImportEve()
    {
        var dlg = new OpenFileDialog
        {
            Title = "Suricata eve.json 가져오기 (이 PCAP 을 검사한 결과)",
            Filter = "EVE JSON (*.json)|*.json|모든 파일 (*.*)|*.*",
        };
        if (dlg.ShowDialog() != true) return;
        try
        {
            _analyzer.ImportEve(_result!, dlg.FileName);
            ApplyDetection();
            StatusText = $"eve.json 경보 {_result!.IdsAlerts.Count:N0}건을 가져왔습니다 (세션 연결 {_result.IdsAlerts.Count(a => a.SessionId.HasValue):N0}건).";
            SelectedTabIndex = TabIds;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            MessageBox.Show(ex.Message, "eve.json 가져오기 실패", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    void Apply(AnalysisResult r)
    {
        _result = r;
        Sessions.SetItems(r.Sessions);
        Http.SetItems(r.Http);
        Dns.SetItems(r.Dns);
        Tls.SetItems(r.Tls);
        Credentials.SetItems(r.Credentials);
        Files.SetItems(r.Files);
        Packets.SetItems(r.Packets);
        ApplyDetection();
        BuildCharts();

        SelectedSession = null;
        SelectedHttp = null;
        SelectedFile = null;
        SelectedPacket = null;
        foreach (var name in new[]
                 {
                     nameof(HasResult), nameof(FileTitle), nameof(FileHash), nameof(WarningsText), nameof(PacketCountText), nameof(BytesText),
                     nameof(SessionCountText), nameof(SessionSubText), nameof(DurationText), nameof(RangeText), nameof(HostCountText),
                     nameof(ArtifactText), nameof(SessionsHeader), nameof(HttpHeader), nameof(DnsHeader), nameof(TlsHeader),
                     nameof(CredentialsHeader), nameof(FilesHeader), nameof(PacketsHeader), nameof(TrafficValues), nameof(TrafficStart),
                     nameof(TrafficEnd), nameof(TrafficCaption),
                 })
            Raise(name);
    }

    /// <summary>탐지 결과가 바뀔 때(최초 분석, IOC 적용, 규칙 재적용) 갱신되는 부분.</summary>
    void ApplyDetection()
    {
        if (_result is null) return;
        Findings.SetItems(_result.Findings);
        Timeline.SetItems(_result.Timeline);
        IdsAlerts.SetItems(_result.IdsAlerts);
        SelectedFinding = _result.Findings.FirstOrDefault();

        var cats = _result.Findings.GroupBy(f => f.Category)
            .Select(g => (Name: g.Key, Count: g.Count(), Max: g.Max(f => f.Severity)))
            .OrderByDescending(x => x.Max).ThenByDescending(x => x.Count).ToList();
        int maxCount = cats.Count == 0 ? 1 : cats.Max(c => c.Count);
        CategoryBars = cats.Select(c => new BarItem(c.Name, c.Name, (double)c.Count / maxCount, $"{c.Count}건", SeverityBrushConverter.For(c.Max))).ToList();

        foreach (var name in new[]
                 {
                     nameof(FindingsHeader), nameof(TimelineHeader), nameof(HasFindings), nameof(CriticalCount), nameof(HighCount), nameof(MediumCount),
                     nameof(LowCount), nameof(Verdict), nameof(VerdictBrush), nameof(CategoryBars), nameof(IocStatus), nameof(WarningsText),
                     nameof(IdsHeader), nameof(IdsSourceText),
                 })
            Raise(name);
    }

    void BuildCharts()
    {
        var st = _result!.Statistics;
        var accent = (Brush)Application.Current.Resources["AccentBrush"];
        var teal = Frozen(new SolidColorBrush(Color.FromRgb(0x0D, 0x94, 0x88)));
        var violet = Frozen(new SolidColorBrush(Color.FromRgb(0x7C, 0x3A, 0xED)));

        ProtocolBars = Bars(st.Protocols, v => $"{v:N0}", accent);
        TalkerBars = Bars(st.TopTalkers, v => TimeFormat.Bytes(v), teal);
        PortBars = Bars(st.TopServerPorts, v => $"{v:N0} 세션", violet);
        ExternalBars = Bars(st.TopExternalHosts, v => TimeFormat.Bytes(v), teal);
        DomainBars = Bars(st.TopDomains, v => $"{v:N0}회", accent);
        Raise(nameof(ProtocolBars));
        Raise(nameof(TalkerBars));
        Raise(nameof(PortBars));
        Raise(nameof(ExternalBars));
        Raise(nameof(DomainBars));
    }

    static Brush Frozen(SolidColorBrush b)
    {
        b.Freeze();
        return b;
    }

    static IReadOnlyList<BarItem> Bars(List<NamedCount> items, Func<long, string> format, Brush brush)
    {
        if (items.Count == 0) return Array.Empty<BarItem>();
        double max = Math.Max(1, items.Max(i => i.Value));
        return items.Select(i =>
        {
            string label = i.Detail.Length > 0 ? $"{i.Name} ({i.Detail})" : i.Name;
            string tip = i.Detail.Length > 0 ? $"{i.Name}\n{i.Detail}" : i.Name;
            return new BarItem(label, tip, i.Value / max, format(i.Value), brush);
        }).ToList();
    }

    void LoadIoc()
    {
        var dlg = new OpenFileDialog
        {
            Title = "IOC 목록 불러오기 (한 줄에 IP / 도메인 / URL / 해시)",
            Filter = "텍스트/CSV (*.txt;*.csv;*.ioc)|*.txt;*.csv;*.ioc|모든 파일 (*.*)|*.*",
        };
        if (dlg.ShowDialog() != true) return;
        try
        {
            _analyzer.Iocs = IocSet.LoadFromFile(dlg.FileName);
            Raise(nameof(IocStatus));
            if (_result is not null)
            {
                _analyzer.RunDetection(_result);
                ApplyDetection();
            }
            StatusText = $"IOC {_analyzer.Iocs.Count:N0}개를 불러왔습니다 (IP {_analyzer.Iocs.Ips.Count}, 도메인 {_analyzer.Iocs.Domains.Count}, 해시 {_analyzer.Iocs.Hashes.Count}, 대역 {_analyzer.Iocs.Networks.Count}).";
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            MessageBox.Show(ex.Message, "IOC 불러오기 실패", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    void ReloadRules()
    {
        try
        {
            _analyzer.Settings = RuleLoader.LoadSettings();
            _analyzer.WebRules = RuleLoader.LoadWebRules();
        }
        catch (Exception ex) when (ex is IOException or System.Text.Json.JsonException or ArgumentException)
        {
            MessageBox.Show($"규칙 파일을 읽을 수 없습니다.\n\n{ex.Message}", "규칙 다시 불러오기", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }
        if (_result is not null)
        {
            _analyzer.RunDetection(_result);
            ApplyDetection();
        }
        StatusText = $"탐지 규칙을 다시 적용했습니다. (탐지 {_result?.Findings.Count ?? 0}건)";
    }

    void ExportHtml()
    {
        var dlg = new SaveFileDialog
        {
            Title = "HTML 보고서 저장",
            Filter = "HTML 보고서 (*.html)|*.html",
            FileName = Path.GetFileNameWithoutExtension(_result!.FileName) + "_침해사고분석보고서.html",
        };
        if (dlg.ShowDialog() != true) return;
        HtmlReportWriter.Write(_result, dlg.FileName);
        StatusText = $"보고서를 저장했습니다: {dlg.FileName}";
        Process.Start(new ProcessStartInfo(dlg.FileName) { UseShellExecute = true });
    }

    void ExportCsv()
    {
        var dlg = new OpenFolderDialog { Title = "CSV 를 저장할 폴더 선택" };
        if (dlg.ShowDialog() != true) return;
        var files = CsvExporter.ExportAll(_result!, dlg.FolderName);
        StatusText = $"CSV {files.Count}개를 저장했습니다: {dlg.FolderName}";
        OpenFolder(dlg.FolderName);
    }

    void ExportFiles()
    {
        if (MessageBox.Show(
                "추출 파일에는 악성코드가 포함될 수 있습니다.\n실행 파일과 알 수 없는 형식은 '.infected' 확장자를 붙여 저장합니다.\n\n격리된 분석 환경에서 다루십시오. 계속하시겠습니까?",
                "파일 추출", MessageBoxButton.OKCancel, MessageBoxImage.Warning) != MessageBoxResult.OK) return;
        var dlg = new OpenFolderDialog { Title = "추출 파일을 저장할 폴더 선택" };
        if (dlg.ShowDialog() != true) return;
        int n = ObjectExporter.ExportAll(_result!.Files, dlg.FolderName);
        StatusText = $"파일 {n}개와 manifest.csv 를 저장했습니다: {dlg.FolderName}";
        OpenFolder(dlg.FolderName);
    }

    void SaveSelectedFile()
    {
        var f = SelectedFile!;
        var dlg = new SaveFileDialog { Title = "추출 파일 저장", FileName = ObjectExporter.SafeName(f), Filter = "모든 파일 (*.*)|*.*" };
        if (dlg.ShowDialog() != true) return;
        File.WriteAllBytes(dlg.FileName, f.Data);
        StatusText = $"저장했습니다: {dlg.FileName}";
    }

    void ShowFindingSessions() => ShowSessions(SelectedFinding!.SessionIds);

    void ShowSessions(IEnumerable<int> ids)
    {
        var list = ids.Where(i => i > 0).Distinct().Take(300).ToList();
        if (list.Count == 0) return;
        Sessions.SetFilterNow("id:" + string.Join(",", list));
        SelectedTabIndex = TabSessions;
        if (list.Count == 1) SelectedSession = _result?.Sessions.FirstOrDefault(s => s.Id == list[0]);
    }

    void ShowSessionPackets()
    {
        Packets.SetFilterNow($"sid:{SelectedSession!.Id}");
        SelectedTabIndex = TabPackets;
    }

    static void OpenFolder(string path)
    {
        if (Directory.Exists(path)) Process.Start(new ProcessStartInfo(path) { UseShellExecute = true });
    }

    static void CommandManager_Invalidate() => System.Windows.Input.CommandManager.InvalidateRequerySuggested();

    // ---------- 상세 표시 ----------
    void UpdateStreamView()
    {
        var s = _selectedSession;
        if (s is null)
        {
            StreamHeader = "세션을 선택하면 재조립된 스트림이 표시됩니다.";
            ClientStreamText = ServerStreamText = "";
            return;
        }
        StreamHeader = $"세션 #{s.Id}  {s.TransportText} {s.ClientEndpoint} → {s.ServerEndpoint}  [{s.AppProtocol}]  {s.State}" +
                       (s.ServerName.Length > 0 ? $"  ·  {s.ServerName}" : "") +
                       (s.ClientData.Gaps + s.ServerData.Gaps > 0 ? $"  ·  패킷 손실 구간 {s.ClientData.Gaps + s.ServerData.Gaps}개" : "");
        ClientStreamText = Render(s.ClientData.Data);
        ServerStreamText = Render(s.ServerData.Data);
    }

    string Render(byte[] data)
    {
        if (data.Length == 0) return "(데이터 없음)";
        const int max = 256 * 1024;
        string body = _streamHex ? TextUtil.HexDump(data, max) : TextUtil.ToPrintable(data, max);
        return data.Length > max ? body + $"\n… (전체 {TimeFormat.Bytes(data.Length)} 중 {TimeFormat.Bytes(max)}만 표시)" : body;
    }

    static string FormatRequest(HttpTransaction h)
    {
        var sb = new System.Text.StringBuilder();
        sb.AppendLine($"# 요청  {h.TimeText} UTC   {h.ClientIp}:{h.ClientPort} → {h.ServerIp}:{h.ServerPort}   세션 #{h.SessionId}");
        sb.AppendLine(h.RequestLine);
        foreach (var kv in h.RequestHeaders) sb.AppendLine($"{kv.Key}: {kv.Value}");
        if (h.RequestBody.Length > 0)
        {
            sb.AppendLine().AppendLine($"# 본문 {TimeFormat.Bytes(h.RequestBody.Length)}");
            sb.AppendLine(Preview(h.RequestBody));
        }
        return sb.ToString();
    }

    static string FormatResponse(HttpTransaction h)
    {
        var sb = new System.Text.StringBuilder();
        if (h.StatusCode is null) return "(응답이 캡처되지 않았습니다)";
        sb.AppendLine($"# 응답  {TimeFormat.Format(h.ResponseTime)} UTC");
        sb.AppendLine(h.StatusLine);
        foreach (var kv in h.ResponseHeaders) sb.AppendLine($"{kv.Key}: {kv.Value}");
        if (h.ResponseBody.Length > 0)
        {
            var (kind, _) = FileTypeDetector.Detect(h.ResponseBody, h.ContentType);
            sb.AppendLine().AppendLine($"# 본문 {TimeFormat.Bytes(h.ResponseBody.Length)} (압축 해제 후), 실제 형식: {kind}");
            sb.AppendLine(Preview(h.ResponseBody));
        }
        return sb.ToString();
    }

    static string Preview(byte[] d) =>
        TextUtil.LooksLikeText(d) ? TextUtil.ToPrintable(d, 64 * 1024) : TextUtil.HexDump(d, 4096);

    static string FormatFile(ExtractedFile f)
    {
        var sb = new System.Text.StringBuilder();
        sb.AppendLine($"파일명      : {f.FileName}");
        sb.AppendLine($"위치        : {f.Location}");
        sb.AppendLine($"출처        : {f.Source}  {f.ServerIp} → {f.ClientIp}  (세션 #{f.SessionId})");
        sb.AppendLine($"선언 형식   : {(f.DeclaredType.Length > 0 ? f.DeclaredType : "-")}");
        sb.AppendLine($"실제 형식   : {f.Kind} [{f.CategoryText}]");
        sb.AppendLine($"크기        : {f.Size:N0} bytes ({f.SizeText}),  엔트로피 {f.Entropy:F3}");
        sb.AppendLine($"MD5         : {f.Md5}");
        sb.AppendLine($"SHA1        : {f.Sha1}");
        sb.AppendLine($"SHA256      : {f.Sha256}");
        if (f.Referer.Length > 0) sb.AppendLine($"Referer     : {f.Referer}");
        sb.AppendLine();
        sb.AppendLine(TextUtil.LooksLikeText(f.Data) ? TextUtil.ToPrintable(f.Data, 32 * 1024) : TextUtil.HexDump(f.Data, 4096));
        return sb.ToString();
    }

    static string FormatPacket(PacketRecord p)
    {
        var sb = new System.Text.StringBuilder();
        sb.AppendLine($"프레임 #{p.Index}   {p.TimeText} UTC   길이 {p.Length} (캡처 {p.CapturedLength})" + (p.IsDuplicate ? "   [중복 프레임]" : ""));
        if (p.SrcMac is not null) sb.AppendLine($"Ethernet   {p.SrcMac} → {p.DstMac}");
        if (p.SrcIp is not null) sb.AppendLine($"{p.Network,-10} {p.SrcIp} → {p.DstIp}   TTL {p.Ttl}  프로토콜 {p.IpProtocol}" + (p.IsFragment ? "  [조각]" : ""));
        if (p.Transport == TransportProtocol.Tcp)
            sb.AppendLine($"TCP        {p.SrcPort} → {p.DstPort}  [{p.Flags.ToText()}]  Seq {p.Seq}  Ack {p.Ack}  Win {p.Window}");
        else if (p.Transport == TransportProtocol.Udp)
            sb.AppendLine($"UDP        {p.SrcPort} → {p.DstPort}");
        else if (p.Arp is not null)
            sb.AppendLine($"ARP        op={p.Arp.Operation}  {p.Arp.SenderIp} ({p.Arp.SenderMac}) → {p.Arp.TargetIp} ({p.Arp.TargetMac})");
        sb.AppendLine($"정보       {p.Info}");
        if (p.SessionId > 0) sb.AppendLine($"세션       #{p.SessionId}");
        if (p.Payload.Length > 0)
        {
            sb.AppendLine().AppendLine($"페이로드 {p.Payload.Length} bytes");
            sb.Append(TextUtil.HexDump(p.Payload, 16 * 1024));
        }
        return sb.ToString();
    }
}
