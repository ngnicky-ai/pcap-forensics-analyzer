using System.Diagnostics;
using System.Security.Cryptography;
using PcapForensics.Core.Decoding;
using PcapForensics.Core.Detection;
using PcapForensics.Core.Ids;
using PcapForensics.Core.Pcap;
using PcapForensics.Core.Protocols;
using PcapForensics.Core.Sessions;

namespace PcapForensics.Core.Analysis;

/// <summary>
/// 분석 파이프라인: 읽기/디코딩 → 세션 재조립 → 프로토콜 해석 → 파일 추출 → 통계 → 탐지 → 타임라인.
/// </summary>
public sealed class PcapAnalyzer
{
    public DetectionSettings Settings { get; set; } = RuleLoader.LoadSettings();
    public WebAttackRules WebRules { get; set; } = RuleLoader.LoadWebRules();
    public IocSet Iocs { get; set; } = IocSet.Empty;

    public List<IDetector> Detectors { get; } = new()
    {
        new IocMatchDetector(),
        new MalwareDeliveryDetector(),
        new WebShellDetector(),
        new WebAttackDetector(),
        new BruteForceDetector(),
        new PortScanDetector(),
        new DnsAnomalyDetector(),
        new BeaconDetector(),
        new ArpSpoofDetector(),
        new CleartextCredentialDetector(),
        new IdsAlertDetector(),
    };

    /// <summary>설치된 Suricata 로 원본 PCAP 을 검사하고 경보를 결과에 합친다.</summary>
    public async Task<SuricataRunResult> RunSuricataAsync(AnalysisResult result, IProgress<string>? log = null, CancellationToken ct = default)
    {
        var run = await SuricataRunner.RunAsync(result.FilePath, Settings.Suricata, log, ct);
        var source = $"Suricata {run.Version}".Trim() + (run.RulesSummary.Length > 0 ? $", {run.RulesSummary}" : "") + $" ({run.Elapsed.TotalSeconds:F1}초)";
        if (run.RulesSummary.StartsWith("룰 0개", StringComparison.Ordinal))
            result.Warnings.Add("Suricata 에 로드된 룰이 없습니다. rules\\settings.json 의 Suricata.RulesPath 에 ET Open 등 룰 경로를 지정하십시오.");
        ImportEve(result, run.EvePath, source);
        return run;
    }

    /// <summary>eve.json 의 alert 이벤트를 불러와 세션과 연결하고 탐지를 다시 실행한다.</summary>
    public void ImportEve(AnalysisResult result, string evePath, string? source = null)
    {
        result.IdsAlerts = EveJsonReader.Read(evePath, result.Warnings).OrderBy(a => a.Time).ToList();
        result.IdsSource = source ?? $"eve.json 가져옴: {Path.GetFileName(evePath)}";
        IdsAlertProcessor.LinkSessions(result);
        int unlinked = result.IdsAlerts.Count(a => a.SessionId is null && a.Proto is "TCP" or "UDP");
        if (result.IdsAlerts.Count > 0 && unlinked == result.IdsAlerts.Count)
            result.Warnings.Add("IDS 경보가 이 PCAP 의 세션과 하나도 일치하지 않습니다. 다른 캡처의 eve.json 인지 확인하십시오.");
        RunDetection(result);
    }

    public AnalysisResult Analyze(string path, IProgress<AnalysisProgress>? progress = null, CancellationToken ct = default)
    {
        var sw = Stopwatch.StartNew();
        var result = new AnalysisResult { FilePath = Path.GetFullPath(path), FileSize = new FileInfo(path).Length };

        progress?.Report(new("파일 해시 계산 중", 1));
        result.FileSha256 = HashUtil.Sha256File(path);

        var tracker = new SessionTracker();
        var seen = new HashSet<(long Ticks, Guid Digest)>();
        // 여러 인터페이스 동시 캡처: 가상 스위치/브리지가 같은 패킷을 두 어댑터로 전달하는 경우를 걸러 낸다
        var lastByPayload = new Dictionary<Guid, (long Ticks, int Interface)>();
        int duplicates = 0, crossInterface = 0;
        using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 1 << 20))
        {
            int n = 0;
            foreach (var frame in PcapFileReader.Read(fs, result.Warnings))
            {
                var p = PacketDecoder.Decode(frame);
                result.Packets.Add(p);
                bool duplicate = !seen.Add((frame.Timestamp.Ticks, new Guid(MD5.HashData(frame.Data))));
                if (duplicate) duplicates++;
                else
                {
                    var payload = new Guid(MD5.HashData(frame.Data.AsSpan(Math.Min(frame.Data.Length, LinkHeaderLength(frame.LinkType)))));
                    if (lastByPayload.TryGetValue(payload, out var prev) && prev.Interface != frame.InterfaceId
                        && Math.Abs(frame.Timestamp.Ticks - prev.Ticks) <= 100 * TimeSpan.TicksPerMillisecond)
                    {
                        duplicate = true;
                        crossInterface++;
                    }
                    else lastByPayload[payload] = (frame.Timestamp.Ticks, frame.InterfaceId);
                }

                if (duplicate)
                {
                    p.IsDuplicate = true;
                    p.Info = "[중복 프레임] " + p.Info;
                }
                else tracker.Add(p);
                if (++n % 5000 == 0)
                {
                    ct.ThrowIfCancellationRequested();
                    progress?.Report(new($"패킷 디코딩 중 ({n:N0}개)", 3 + 50.0 * fs.Position / Math.Max(1, fs.Length)));
                }
            }
        }

        if (duplicates > 0)
            result.Warnings.Add($"시각과 내용이 완전히 같은 중복 프레임 {duplicates:N0}개를 세션 분석에서 제외했습니다. (캡처 파일 병합 또는 중복 미러링 가능성)");
        if (crossInterface > 0)
            result.Warnings.Add($"여러 인터페이스에서 같은 패킷이 중복 캡처된 {crossInterface:N0}개를 세션 분석에서 제외했습니다. (가상 스위치/브리지 구성)");

        progress?.Report(new("TCP 스트림 재조립 중", 55));
        result.Sessions = tracker.Complete();
        ct.ThrowIfCancellationRequested();

        progress?.Report(new("응용 프로토콜 분석 중", 65));
        foreach (var s in result.Sessions) s.AppProtocol = ProtocolClassifier.Classify(s);
        ExtractProtocols(result);
        LinkFtpData(result);
        LabelPackets(result);
        BuildHostNames(result);
        ct.ThrowIfCancellationRequested();

        progress?.Report(new("파일 추출 중", 78));
        FileExtractor.Extract(result);

        progress?.Report(new("통계 계산 중", 85));
        result.Statistics = StatisticsBuilder.Build(result);

        progress?.Report(new("위협 탐지 중", 90));
        RunDetection(result);

        result.AnalysisTime = sw.Elapsed;
        progress?.Report(new("완료", 100));
        return result;
    }

    /// <summary>링크 계층 헤더 길이(인터페이스마다 링크 타입이 달라도 IP 패킷 이후만 비교하기 위함).</summary>
    static int LinkHeaderLength(int linkType) => linkType switch
    {
        1 => 14,          // Ethernet
        0 or 108 => 4,    // Null / Loop (Npcap 루프백)
        113 => 16,        // Linux SLL
        276 => 20,        // Linux SLL2
        _ => 0,
    };

    /// <summary>설정/IOC 변경 후 탐지와 타임라인만 다시 계산한다.</summary>
    public void RunDetection(AnalysisResult result)
    {
        IdsAlertProcessor.Classify(result.IdsAlerts, Settings.Suricata);
        var ctx = new DetectionContext(result, Settings, WebRules, Iocs);
        var findings = new List<Finding>();
        foreach (var d in Detectors)
        {
            try
            {
                findings.AddRange(d.Detect(ctx));
            }
            catch (Exception ex)
            {
                result.Warnings.Add($"탐지 규칙 '{d.Name}' 실행 중 오류: {ex.Message}");
            }
        }

        result.Findings = findings
            .OrderByDescending(f => f.Severity)
            .ThenBy(f => f.FirstSeen)
            .ToList();
        for (int i = 0; i < result.Findings.Count; i++) result.Findings[i].Id = i + 1;
        result.Timeline = TimelineBuilder.Build(result);
    }

    static void ExtractProtocols(AnalysisResult r)
    {
        // DNS over UDP (패킷 단위)
        var pending = new Dictionary<(string Client, int Port, string Server, int Id), DnsTransaction>();
        foreach (var p in r.Packets)
        {
            if (p.IsDuplicate || p.Transport != TransportProtocol.Udp || (p.SrcPort != 53 && p.DstPort != 53) || p.Payload.Length < 12) continue;
            var msg = DnsParser.TryParse(p.Payload);
            if (msg is null) continue;
            p.ProtocolName = "DNS";
            p.Info = msg.Summary;
            if (!msg.IsResponse && p.SessionId > 0 && p.SessionId <= r.Sessions.Count && r.Sessions[p.SessionId - 1].Summary.Length == 0)
                r.Sessions[p.SessionId - 1].Summary = $"{msg.QueryType} {msg.QueryName}";
            AddDns(r, pending, msg, p.Timestamp, p.SrcIp!, p.SrcPort, p.DstIp!, p.DstPort, "UDP", p.SessionId);
        }

        foreach (var s in r.Sessions)
        {
            switch (s.AppProtocol)
            {
                case "DNS" when s.Transport == TransportProtocol.Tcp:
                    foreach (var (msg, time, fromClient) in TcpDnsMessages(s))
                    {
                        if (fromClient) AddDns(r, pending, msg, time, s.ClientIp, s.ClientPort, s.ServerIp, s.ServerPort, "TCP", s.Id);
                        else AddDns(r, pending, msg, time, s.ServerIp, s.ServerPort, s.ClientIp, s.ClientPort, "TCP", s.Id);
                    }
                    break;
                case "HTTP":
                    r.Http.AddRange(HttpParser.Parse(s));
                    break;
                case "TLS":
                {
                    var (sni, version) = TlsParser.ParseClientHello(s.ClientData.Data);
                    if (sni is not null || version.Length > 0)
                    {
                        r.Tls.Add(new TlsHandshakeInfo
                        {
                            Time = s.ClientData.TimeAt(0) ?? s.Start, SessionId = s.Id,
                            ClientIp = s.ClientIp, ClientPort = s.ClientPort, ServerIp = s.ServerIp, ServerPort = s.ServerPort,
                            Sni = sni ?? "", Version = version,
                        });
                    }
                    break;
                }
                default:
                    CleartextAuthParser.Parse(s, r.Credentials, r.FtpCommands);
                    break;
            }
        }

        r.Http.Sort((a, b) => a.Time.CompareTo(b.Time));
        for (int i = 0; i < r.Http.Count; i++) r.Http[i].Id = i + 1;
        foreach (var h in r.Http) CleartextAuthParser.ParseHttp(h, r.Credentials);
        r.Credentials.Sort((a, b) => a.Time.CompareTo(b.Time));
        r.Tls.Sort((a, b) => a.Time.CompareTo(b.Time));
        r.Dns.Sort((a, b) => a.Time.CompareTo(b.Time));
        for (int i = 0; i < r.Dns.Count; i++) r.Dns[i].Id = i + 1;
    }

    static void AddDns(AnalysisResult r, Dictionary<(string, int, string, int), DnsTransaction> pending, DnsMessage msg,
        DateTime time, string src, int srcPort, string dst, int dstPort, string transport, int sessionId)
    {
        if (!msg.IsResponse)
        {
            var tx = new DnsTransaction
            {
                Time = time, ClientIp = src, ClientPort = srcPort, ServerIp = dst, TransactionId = msg.Id,
                QueryName = msg.QueryName, QueryType = msg.QueryType, Transport = transport,
            };
            pending[(src, srcPort, dst, msg.Id)] = tx;
            r.Dns.Add(tx);
            return;
        }

        if (pending.TryGetValue((dst, dstPort, src, msg.Id), out var q) && q.RCode is null)
        {
            q.RCode = msg.RCode;
            q.ResponseTime = time;
            q.Answers = msg.Answers;
            return;
        }
        // 질의 없이 응답만 캡처된 경우
        r.Dns.Add(new DnsTransaction
        {
            Time = time, ResponseTime = time, ClientIp = dst, ClientPort = dstPort, ServerIp = src, TransactionId = msg.Id,
            QueryName = msg.QueryName, QueryType = msg.QueryType, RCode = msg.RCode, Answers = msg.Answers, Transport = transport,
        });
    }

    static IEnumerable<(DnsMessage, DateTime, bool)> TcpDnsMessages(NetworkSession s)
    {
        foreach (var (stream, fromClient) in new[] { (s.ClientData, true), (s.ServerData, false) })
        {
            var d = stream.Data;
            int pos = 0;
            while (pos + 2 <= d.Length)
            {
                int len = (d[pos] << 8) | d[pos + 1];
                if (len == 0 || pos + 2 + len > d.Length) break;
                var msg = DnsParser.TryParse(d.AsSpan(pos + 2, len));
                if (msg is not null) yield return (msg, stream.TimeAt(pos) ?? s.Start, fromClient);
                pos += 2 + len;
            }
        }
    }

    /// <summary>FTP PASV/PORT 정보로 데이터 채널 세션을 찾아 명령과 연결한다.</summary>
    static void LinkFtpData(AnalysisResult r)
    {
        var byServer = r.Sessions.Where(s => s.Transport == TransportProtocol.Tcp)
            .GroupBy(s => (s.ServerIp, s.ServerPort))
            .ToDictionary(g => g.Key, g => g.ToList());
        var used = new HashSet<int>();

        foreach (var cmd in r.FtpCommands.Where(c => c.DataPort > 0))
        {
            // PASV 응답의 IP 가 NAT 내부 주소일 수 있어 제어 채널 서버 IP 로도 찾는다
            var keys = new[] { (cmd.DataIp, cmd.DataPort), (cmd.Passive ? cmd.ServerIp : cmd.ClientIp, cmd.DataPort) };
            NetworkSession? best = null;
            foreach (var key in keys.Distinct())
            {
                if (!byServer.TryGetValue(key, out var list)) continue;
                best = list.Where(s => !used.Contains(s.Id) && s.Start >= cmd.Time.AddSeconds(-30) && s.Start <= cmd.Time.AddSeconds(120))
                    .OrderBy(s => Math.Abs((s.Start - cmd.Time).TotalSeconds))
                    .FirstOrDefault();
                if (best is not null) break;
            }
            if (best is null) continue;

            used.Add(best.Id);
            best.AppProtocol = "FTP-DATA";
            best.Summary = $"{cmd.Command} {cmd.Argument}".Trim();
            cmd.DataSessionId = best.Id;
            cmd.DataBytes = FtpPayload(best, cmd).Length;
        }
    }

    /// <summary>데이터 채널에서 FTP 서버가 보낸(RETR/LIST) 또는 받은(STOR) 바이트.</summary>
    public static byte[] FtpPayload(NetworkSession data, FtpCommandRecord cmd)
    {
        bool ftpServerIsDataServer = data.ServerIp == cmd.ServerIp || cmd.Passive;
        bool download = cmd.Command is "RETR" or "LIST" or "NLST" or "MLSD";
        var fromFtpServer = ftpServerIsDataServer ? data.ServerData : data.ClientData;
        var toFtpServer = ftpServerIsDataServer ? data.ClientData : data.ServerData;
        return (download ? fromFtpServer : toFtpServer).Data;
    }

    static void LabelPackets(AnalysisResult r)
    {
        var sessions = r.Sessions.ToDictionary(s => s.Id);
        foreach (var p in r.Packets)
        {
            if (p.SessionId <= 0 || p.ProtocolName == "DNS" || !sessions.TryGetValue(p.SessionId, out var s)) continue;
            string app = s.AppProtocol;
            bool generic = app is "TCP" or "UDP";
            if (!generic && (p.Payload.Length > 0 || p.Transport == TransportProtocol.Udp)) p.ProtocolName = app;

            if (p.Payload.Length == 0) continue;
            if (app == "HTTP" && (HttpParser.LooksLikeRequest(p.Payload, 0) || ByteUtil.StartsWithAscii(p.Payload, 0, "HTTP/1.")))
                p.Info = FirstLine(p.Payload);
            else if (app is "FTP" or "SMTP" or "POP3" or "IMAP")
                p.Info = FirstLine(p.Payload);
        }
    }

    static string FirstLine(byte[] d)
    {
        int n = Math.Min(d.Length, 300);
        int end = Array.IndexOf(d, (byte)'\n', 0, n);
        return TextUtil.Latin1.GetString(d, 0, end < 0 ? n : end).TrimEnd('\r');
    }

    static void BuildHostNames(AnalysisResult r)
    {
        void Add(string ip, string name)
        {
            if (string.IsNullOrWhiteSpace(name) || NetUtil.IsIpLiteral(name)) return;
            if (!r.HostNames.TryGetValue(ip, out var set)) r.HostNames[ip] = set = new SortedSet<string>(StringComparer.OrdinalIgnoreCase);
            set.Add(DomainUtil.Normalize(name.Split(':')[0]));
        }

        foreach (var d in r.Dns)
            foreach (var a in d.Answers.Where(a => a.Type is "A" or "AAAA"))
                Add(a.Data, d.QueryName);
        foreach (var h in r.Http) Add(h.ServerIp, h.Host);
        foreach (var t in r.Tls) Add(t.ServerIp, t.Sni);

        var httpBySession = r.Http.GroupBy(h => h.SessionId).ToDictionary(g => g.Key, g => g.ToList());
        var tlsBySession = r.Tls.ToDictionary(t => t.SessionId);
        foreach (var s in r.Sessions)
        {
            if (httpBySession.TryGetValue(s.Id, out var hs))
            {
                s.ServerName = hs[0].Host;
                s.Summary = hs.Count == 1 ? $"{hs[0].Method} {TextUtil.Truncate(hs[0].Uri, 120)}" : $"HTTP 요청 {hs.Count}건";
            }
            else if (tlsBySession.TryGetValue(s.Id, out var t))
            {
                s.ServerName = t.Sni;
                if (s.Summary.Length == 0) s.Summary = $"{t.Version} SNI={t.Sni}";
            }
            else if (r.HostNames.TryGetValue(s.ServerIp, out var names))
            {
                s.ServerName = names.First();
            }
        }
    }
}
