using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Windows;
using System.Windows.Media;
using System.Windows.Threading;
using PcapForensics.App.Converters;
using PcapForensics.Core.Capture;
using PcapForensics.Core.Model;
using PcapForensics.Core.Util;

namespace PcapForensics.App.ViewModels;

public sealed class DeviceItem : ObservableObject
{
    bool _selected;

    public DeviceItem(CaptureDevice device, bool selected)
    {
        Device = device;
        _selected = selected;
    }

    public CaptureDevice Device { get; }
    public bool IsSelected { get => _selected; set => Set(ref _selected, value); }
}

public sealed record InterfaceRow(string Name, string Kind, string Packets, string Bytes, string Dropped, string Error);

/// <summary>실시간 모니터링 창: 인터페이스 선택 → 캡처(제한 경고) → 중지 시 자동 분석.</summary>
public sealed class CaptureViewModel : ObservableObject
{
    // 측정값: 분석 최대 메모리 ≈ 80MB + 캡처 파일 크기 × 3 (여유를 두어 3.5배로 계산)
    const double MemoryPerCaptureByte = 3.5;
    const long BaseMemoryBytes = 80L * 1024 * 1024;

    readonly CaptureSettings _settings;
    readonly DispatcherTimer _timer;
    LiveCapture? _live;
    long _lastBytes;
    DateTime _lastSample;
    int _secondsTick;

    public CaptureViewModel(CaptureSettings settings)
    {
        _settings = settings;
        _maxSizeMB = settings.MaxSizeMB;
        _maxMinutes = settings.MaxDurationMinutes;
        _promiscuous = settings.Promiscuous;
        OutputDirectory = settings.ResolveOutputDirectory();

        StartCommand = new RelayCommand(_ => Start(), _ => !IsCapturing && !IsFinishing && IsAvailable && Devices.Any(d => d.IsSelected));
        StopCommand = new RelayCommand(_ => _ = FinishAsync(), _ => IsCapturing);
        SelectAllCommand = new RelayCommand(_ => SetSelection(_ => true), _ => !IsCapturing);
        SelectConnectedCommand = new RelayCommand(_ => SetSelection(d => d.IsConnected && d.Kind != "WAN 미니포트"), _ => !IsCapturing);
        SelectNoneCommand = new RelayCommand(_ => SetSelection(_ => false), _ => !IsCapturing);
        RefreshCommand = new RelayCommand(_ => LoadDevices(), _ => !IsCapturing);
        AnalyzeLastCommand = new RelayCommand(_ => AnalyzeLast(), _ => HasLastCapture && !IsCapturing);
        OpenFolderCommand = new RelayCommand(_ =>
        {
            Directory.CreateDirectory(OutputDirectory);
            Process.Start(new ProcessStartInfo(OutputDirectory) { UseShellExecute = true });
        });

        _timer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(500) };
        _timer.Tick += (_, _) => Tick();
        LoadDevices();
    }

    /// <summary>캡처가 끝나고 자동 분석할 파일이 준비되면 발생(창을 닫고 본창에서 분석).</summary>
    public event Action<string>? CaptureCompleted;

    public RelayCommand StartCommand { get; }
    public RelayCommand StopCommand { get; }
    public RelayCommand SelectAllCommand { get; }
    public RelayCommand SelectConnectedCommand { get; }
    public RelayCommand SelectNoneCommand { get; }
    public RelayCommand RefreshCommand { get; }
    public RelayCommand OpenFolderCommand { get; }
    public RelayCommand AnalyzeLastCommand { get; }

    public ObservableCollection<DeviceItem> Devices { get; } = new();
    public ObservableCollection<PacketRecord> RecentPackets { get; } = new();
    public ObservableCollection<InterfaceRow> InterfaceStats { get; } = new();
    public string OutputDirectory { get; }

    bool _available;
    public bool IsAvailable { get => _available; private set => Set(ref _available, value); }
    string _libraryText = "";
    public string LibraryText { get => _libraryText; private set => Set(ref _libraryText, value); }
    string _availabilityError = "";
    public string AvailabilityError { get => _availabilityError; private set => Set(ref _availabilityError, value); }

    int _maxSizeMB;
    public int MaxSizeMB
    {
        get => _maxSizeMB;
        set
        {
            if (Set(ref _maxSizeMB, Math.Max(1, value))) RaiseMemory();
        }
    }

    int _maxMinutes;
    public int MaxMinutes { get => _maxMinutes; set => Set(ref _maxMinutes, Math.Max(0, value)); }

    bool _promiscuous;
    public bool Promiscuous { get => _promiscuous; set => Set(ref _promiscuous, value); }

    bool _autoAnalyze = true;
    public bool AutoAnalyze { get => _autoAnalyze; set => Set(ref _autoAnalyze, value); }

    bool _capturing;
    public bool IsCapturing
    {
        get => _capturing;
        private set
        {
            if (Set(ref _capturing, value)) Raise(nameof(IsIdle));
        }
    }
    public bool IsIdle => !IsCapturing && !IsFinishing;

    bool _finishing;
    public bool IsFinishing
    {
        get => _finishing;
        private set
        {
            if (Set(ref _finishing, value)) Raise(nameof(IsIdle));
        }
    }

    // ---------- 메모리 기준 권장 용량 ----------
    static long AvailableMemory()
    {
        var info = GC.GetGCMemoryInfo();
        long avail = info.TotalAvailableMemoryBytes - info.MemoryLoadBytes;
        return avail > 0 ? avail : info.TotalAvailableMemoryBytes / 2;
    }

    /// <summary>이 PC 의 가용 메모리 60% 안에서 분석할 수 있는 최대 캡처 크기(MB).</summary>
    public int RecommendedMaxMB => (int)Math.Max(20, (AvailableMemory() * 0.6 - BaseMemoryBytes) / MemoryPerCaptureByte / (1024 * 1024));

    public bool MemoryRisk => MaxSizeMB > RecommendedMaxMB;

    public string MemoryText
    {
        get
        {
            long need = BaseMemoryBytes + (long)(MaxSizeMB * 1024.0 * 1024 * MemoryPerCaptureByte);
            return MemoryRisk
                ? $"용량 제한 {MaxSizeMB:N0} MB 를 분석하려면 메모리가 약 {TimeFormat.Bytes(need)} 필요합니다. 이 PC 에서는 {RecommendedMaxMB:N0} MB 이하를 권장합니다. 초과하면 분석이 느려지거나 실패할 수 있습니다."
                : $"분석 예상 메모리 약 {TimeFormat.Bytes(need)} (이 PC 권장 최대 {RecommendedMaxMB:N0} MB)";
        }
    }

    void RaiseMemory()
    {
        Raise(nameof(MemoryText));
        Raise(nameof(MemoryRisk));
    }

    // ---------- 진행 상태 ----------
    string _elapsed = "00:00:00";
    public string ElapsedText { get => _elapsed; private set => Set(ref _elapsed, value); }
    string _packets = "0";
    public string PacketsText { get => _packets; private set => Set(ref _packets, value); }
    string _rate = "-";
    public string RateText { get => _rate; private set => Set(ref _rate, value); }
    string _fileSize = "0 B";
    public string FileSizeText { get => _fileSize; private set => Set(ref _fileSize, value); }
    string _drops = "0";
    public string DropsText { get => _drops; private set => Set(ref _drops, value); }

    double _sizeRatio, _timeRatio;
    public double SizeRatio { get => _sizeRatio; private set => Set(ref _sizeRatio, value); }
    public double TimeRatio { get => _timeRatio; private set => Set(ref _timeRatio, value); }
    string _sizeLabel = "", _timeLabel = "";
    public string SizeLabel { get => _sizeLabel; private set => Set(ref _sizeLabel, value); }
    public string TimeLabel { get => _timeLabel; private set => Set(ref _timeLabel, value); }
    Brush _sizeBrush = SeverityBrushConverter.For(Severity.Low), _timeBrush = SeverityBrushConverter.For(Severity.Low);
    public Brush SizeBrush { get => _sizeBrush; private set => Set(ref _sizeBrush, value); }
    public Brush TimeBrush { get => _timeBrush; private set => Set(ref _timeBrush, value); }

    string _warning = "";
    public string WarningText { get => _warning; private set => Set(ref _warning, value); }
    string _status = "캡처할 인터페이스를 고르고 [모니터링 시작]을 누르세요.";
    public string StatusText { get => _status; private set => Set(ref _status, value); }

    IReadOnlyList<double> _traffic = Array.Empty<double>();
    public IReadOnlyList<double> TrafficValues { get => _traffic; private set => Set(ref _traffic, value); }
    readonly List<double> _series = new();

    // ---------- 동작 ----------
    void LoadDevices()
    {
        Devices.Clear();
        if (!CaptureDevices.IsAvailable(out var error))
        {
            IsAvailable = false;
            AvailabilityError = error;
            LibraryText = "";
            return;
        }
        try
        {
            LibraryText = CaptureDevices.LibraryVersion();
            foreach (var d in CaptureDevices.List()) Devices.Add(new DeviceItem(d, true)); // 기본값: 모든 인터페이스
            IsAvailable = true;
            AvailabilityError = Devices.Count == 0 ? "캡처할 수 있는 네트워크 인터페이스가 없습니다. Npcap 설치 상태를 확인하십시오." : "";
            StatusText = $"인터페이스 {Devices.Count}개를 찾았습니다(실제·가상·루프백 포함). 기본으로 모두 선택되어 있습니다.";
        }
        catch (InvalidOperationException ex)
        {
            IsAvailable = false;
            AvailabilityError = ex.Message;
        }
        RaiseMemory();
    }

    void SetSelection(Func<CaptureDevice, bool> predicate)
    {
        foreach (var d in Devices) d.IsSelected = predicate(d.Device);
    }

    void Start()
    {
        if (MemoryRisk && MessageBox.Show(MemoryText + "\n\n그래도 이 용량으로 시작할까요?", "실시간 모니터링",
                MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes) return;

        var options = new CaptureOptions
        {
            Devices = Devices.Where(d => d.IsSelected).Select(d => d.Device).ToList(),
            Promiscuous = Promiscuous,
            SnapLength = _settings.SnapLength,
            MaxBytes = (long)MaxSizeMB * 1024 * 1024,
            MaxDuration = TimeSpan.FromMinutes(MaxMinutes),
            OutputPath = Path.Combine(OutputDirectory, $"capture_{DateTime.Now:yyyyMMdd_HHmmss}.pcapng"),
        };

        var live = new LiveCapture(options);
        live.LimitReached += reason => Application.Current.Dispatcher.InvokeAsync(() => _ = FinishAsync());
        try
        {
            live.Start();
        }
        catch (Exception ex) when (ex is InvalidOperationException or IOException or UnauthorizedAccessException or DllNotFoundException)
        {
            live.Dispose();
            MessageBox.Show(ex.Message, "모니터링을 시작할 수 없습니다", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        _live = live;
        RecentPackets.Clear();
        _series.Clear();
        TrafficValues = Array.Empty<double>();
        _lastBytes = 0;
        _lastSample = DateTime.UtcNow;
        _secondsTick = 0;
        WarningText = live.OpenErrors.Count > 0 ? "열지 못한 인터페이스: " + string.Join(" / ", live.OpenErrors) : "";
        IsCapturing = true;
        StatusText = $"모니터링 중: 인터페이스 {live.Interfaces.Count}개 → {options.OutputPath}";
        _timer.Start();
        Tick();
    }

    void Tick()
    {
        var live = _live;
        if (live is null) return;

        // 미리보기 패킷: 최신 것이 위로
        var batch = new List<PacketRecord>();
        while (batch.Count < 3000 && live.Preview.TryDequeue(out var p)) batch.Add(p);
        foreach (var p in batch.Skip(Math.Max(0, batch.Count - 300))) RecentPackets.Insert(0, p);
        while (RecentPackets.Count > 300) RecentPackets.RemoveAt(RecentPackets.Count - 1);

        var elapsed = live.Elapsed;
        ElapsedText = elapsed.ToString(@"hh\:mm\:ss");
        PacketsText = live.Packets.ToString("N0");
        FileSizeText = TimeFormat.Bytes(live.FileBytes);
        DropsText = live.Interfaces.Sum(c => (long)c.Dropped).ToString("N0");

        // 1초마다 전송률과 그래프
        if (++_secondsTick % 2 == 0)
        {
            var now = DateTime.UtcNow;
            double seconds = Math.Max(0.1, (now - _lastSample).TotalSeconds);
            long bytes = live.Interfaces.Sum(c => c.Bytes);
            double rate = (bytes - _lastBytes) / seconds;
            _lastBytes = bytes;
            _lastSample = now;
            RateText = $"{TimeFormat.Bytes((long)rate)}/s";
            _series.Add(rate);
            if (_series.Count > 120) _series.RemoveAt(0);
            TrafficValues = _series.ToArray();

            InterfaceStats.Clear();
            foreach (var c in live.Interfaces.OrderByDescending(c => c.Packets))
                InterfaceStats.Add(new InterfaceRow(c.Device.DisplayName, c.Device.Kind, c.Packets.ToString("N0"), TimeFormat.Bytes(c.Bytes), c.Dropped.ToString("N0"), c.Error));
        }

        long maxBytes = (long)MaxSizeMB * 1024 * 1024;
        SizeRatio = maxBytes > 0 ? Math.Min(1, (double)live.FileBytes / maxBytes) : 0;
        TimeRatio = MaxMinutes > 0 ? Math.Min(1, elapsed.TotalMinutes / MaxMinutes) : 0;
        SizeLabel = $"용량 {TimeFormat.Bytes(live.FileBytes)} / {MaxSizeMB:N0} MB ({SizeRatio:P0})";
        TimeLabel = MaxMinutes > 0 ? $"시간 {elapsed:hh\\:mm\\:ss} / {MaxMinutes}분 ({TimeRatio:P0})" : $"시간 {elapsed:hh\\:mm\\:ss} (제한 없음)";
        SizeBrush = SeverityBrushConverter.For(SizeRatio >= 1 ? Severity.Critical : SizeRatio >= _settings.WarnRatio ? Severity.High : Severity.Low);
        TimeBrush = SeverityBrushConverter.For(TimeRatio >= 1 ? Severity.Critical : TimeRatio >= _settings.WarnRatio ? Severity.High : Severity.Low);

        double ratio = Math.Max(SizeRatio, TimeRatio);
        if (ratio >= _settings.WarnRatio && live.IsRunning)
        {
            string which = SizeRatio >= TimeRatio ? "용량" : "시간";
            var remain = SizeRatio >= TimeRatio && live.FileBytes > 0 && elapsed.TotalSeconds > 1
                ? TimeSpan.FromSeconds((maxBytes - live.FileBytes) / (live.FileBytes / elapsed.TotalSeconds))
                : TimeSpan.FromMinutes(MaxMinutes) - elapsed;
            WarningText = $"{which} 제한의 {ratio:P0}에 도달했습니다. 약 {TimeFormat.Duration(remain < TimeSpan.Zero ? TimeSpan.Zero : remain)} 뒤 자동으로 중지하고 분석합니다.";
        }
    }

    public async Task FinishAsync()
    {
        var live = _live;
        if (live is null || IsFinishing) return;
        IsFinishing = true;
        StatusText = "캡처를 멈추고 파일을 저장하는 중…";
        await Task.Run(live.Stop);
        _timer.Stop();
        Tick();
        IsCapturing = false;
        _live = null;

        var summary = $"{live.StopReason} 패킷 {live.Packets:N0}개, {TimeFormat.Bytes(live.FileBytes)} 저장 ({live.OutputPath})";
        StatusText = summary;
        WarningText = live.LimitReachedFlag ? live.StopReason + " 제한을 늘리려면 아래 설정을 바꾸십시오." : WarningText;
        IsFinishing = false;
        live.Dispose();

        if (live.Packets == 0)
        {
            MessageBox.Show("캡처된 패킷이 없어 분석하지 않습니다. 선택한 인터페이스에 트래픽이 있는지 확인하십시오.", "실시간 모니터링",
                MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        CaptureNote = $"실시간 모니터링({live.StartedAt.ToLocalTime():yyyy-MM-dd HH:mm:ss} 시작, 인터페이스 {live.Interfaces.Count}개): {summary}" +
                      (live.Interfaces.Sum(i => (long)i.Dropped) is > 0 and var d ? $" 캡처 중 손실(드롭)된 패킷 {d:N0}개가 있어 일부 트래픽이 빠졌을 수 있습니다." : "");
        if (AutoAnalyze) CaptureCompleted?.Invoke(live.OutputPath);
        else LastCapturePath = live.OutputPath;
        System.Windows.Input.CommandManager.InvalidateRequerySuggested();
    }

    /// <summary>분석 결과의 경고로 함께 표시할 캡처 요약(중지 사유, 손실).</summary>
    public string CaptureNote { get; private set; } = "";

    string _lastPath = "";
    public string LastCapturePath
    {
        get => _lastPath;
        private set
        {
            if (Set(ref _lastPath, value)) Raise(nameof(HasLastCapture));
        }
    }
    public bool HasLastCapture => LastCapturePath.Length > 0;

    public void AnalyzeLast()
    {
        if (HasLastCapture) CaptureCompleted?.Invoke(LastCapturePath);
    }

    /// <summary>창을 닫을 때 캡처 중이면 멈춘다.</summary>
    public void StopIfRunning()
    {
        _timer.Stop();
        _live?.Stop();
    }
}
