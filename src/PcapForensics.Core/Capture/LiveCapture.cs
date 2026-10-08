using System.Collections.Concurrent;
using System.Diagnostics;
using System.Runtime.InteropServices;
using PcapForensics.Core.Decoding;
using PcapForensics.Core.Pcap;

namespace PcapForensics.Core.Capture;

/// <summary>rules\settings.json 의 "Capture" 항목.</summary>
public sealed class CaptureSettings
{
    /// <summary>저장 파일 최대 크기(MB). 분석은 파일 크기의 수 배 메모리를 쓰므로 너무 크게 잡지 않는다.</summary>
    public int MaxSizeMB { get; set; } = 200;
    /// <summary>최대 캡처 시간(분). 0 이면 제한 없음.</summary>
    public int MaxDurationMinutes { get; set; } = 30;
    /// <summary>제한의 이 비율에 도달하면 경고한다.</summary>
    public double WarnRatio { get; set; } = 0.8;
    public bool Promiscuous { get; set; } = true;
    public int SnapLength { get; set; } = 65535;
    /// <summary>캡처 파일 저장 폴더. 비우면 %LocalAppData%\PcapForensics\captures.</summary>
    public string OutputDirectory { get; set; } = "";

    public string ResolveOutputDirectory() => string.IsNullOrWhiteSpace(OutputDirectory)
        ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "PcapForensics", "captures")
        : OutputDirectory;

    public string NewCapturePath() =>
        Path.Combine(ResolveOutputDirectory(), $"capture_{DateTime.Now:yyyyMMdd_HHmmss}.pcapng");
}

public sealed class CaptureOptions
{
    public List<CaptureDevice> Devices { get; set; } = new();
    public bool Promiscuous { get; set; } = true;
    public int SnapLength { get; set; } = 65535;
    public long MaxBytes { get; set; }
    public TimeSpan MaxDuration { get; set; }
    public string OutputPath { get; set; } = "";
    /// <summary>화면 미리보기용으로 보관할 최근 패킷 수.</summary>
    public int PreviewCapacity { get; set; } = 2000;
}

/// <summary>인터페이스별 캡처 현황.</summary>
public sealed class InterfaceCounter
{
    internal long PacketsField, BytesField;

    public CaptureDevice Device { get; init; } = new();
    public int LinkType { get; init; }
    public long Packets => Interlocked.Read(ref PacketsField);
    public long Bytes => Interlocked.Read(ref BytesField);
    public uint Dropped { get; internal set; }
    public string Error { get; internal set; } = "";
}

/// <summary>
/// 여러 네트워크 인터페이스를 동시에 캡처해 하나의 pcapng 파일로 저장한다.
/// 인터페이스마다 스레드 하나가 패킷을 읽고, 용량·시간 제한에 도달하면 스스로 멈춘다.
/// </summary>
public sealed class LiveCapture : IDisposable
{
    readonly CaptureOptions _o;
    readonly List<(IntPtr Handle, InterfaceCounter Counter, int Index)> _open = new();
    readonly List<Thread> _threads = new();
    readonly object _writeLock = new();
    readonly Stopwatch _clock = new();
    PcapNgWriter? _writer;
    volatile bool _stop;
    int _limitHit, _stopped;
    long _packets;

    public LiveCapture(CaptureOptions options) => _o = options;

    public string OutputPath => _o.OutputPath;
    public ConcurrentQueue<PacketRecord> Preview { get; } = new();
    public List<InterfaceCounter> Interfaces { get; } = new();
    /// <summary>열지 못한 인터페이스와 이유.</summary>
    public List<string> OpenErrors { get; } = new();
    public string StopReason { get; private set; } = "";
    public bool LimitReachedFlag => Volatile.Read(ref _limitHit) == 1;
    public bool IsRunning => _clock.IsRunning && !_stop;
    public DateTime StartedAt { get; private set; }
    public TimeSpan Elapsed => _clock.Elapsed;
    public long Packets => Interlocked.Read(ref _packets);
    public long FileBytes => _writer?.BytesWritten ?? 0;

    /// <summary>용량/시간 제한에 도달해 스스로 멈췄을 때(캡처 스레드에서 호출). 인수는 이유.</summary>
    public event Action<string>? LimitReached;

    public void Start()
    {
        if (!NativePcap.TryLoad(out var loadError)) throw new InvalidOperationException(loadError);
        if (_o.Devices.Count == 0) throw new InvalidOperationException("캡처할 네트워크 인터페이스를 하나 이상 선택하십시오.");

        foreach (var dev in _o.Devices)
        {
            var errbuf = new byte[NativePcap.ErrBufSize];
            var h = NativePcap.pcap_create(dev.Name, errbuf);
            if (h == IntPtr.Zero)
            {
                OpenErrors.Add($"{dev.DisplayName}: {NativePcap.ErrorText(errbuf)}");
                continue;
            }
            NativePcap.pcap_set_snaplen(h, _o.SnapLength);
            NativePcap.pcap_set_promisc(h, _o.Promiscuous ? 1 : 0);
            NativePcap.pcap_set_timeout(h, 250); // 중지 요청을 0.25초 안에 확인
            NativePcap.pcap_set_buffer_size(h, 8 * 1024 * 1024);
            int rc = NativePcap.pcap_activate(h);
            if (rc < 0 && _o.Promiscuous)
            {
                // 일부 무선/가상 어댑터는 무차별 모드를 지원하지 않는다 → 일반 모드로 재시도
                NativePcap.pcap_close(h);
                h = NativePcap.pcap_create(dev.Name, errbuf);
                if (h != IntPtr.Zero)
                {
                    NativePcap.pcap_set_snaplen(h, _o.SnapLength);
                    NativePcap.pcap_set_timeout(h, 250);
                    NativePcap.pcap_set_buffer_size(h, 8 * 1024 * 1024);
                    rc = NativePcap.pcap_activate(h);
                    if (rc >= 0) OpenErrors.Add($"{dev.DisplayName}: 무차별 모드를 지원하지 않아 일반 모드로 캡처합니다.");
                }
            }
            if (h == IntPtr.Zero || rc < 0)
            {
                string err = h != IntPtr.Zero ? Marshal.PtrToStringAnsi(NativePcap.pcap_geterr(h)) ?? $"오류 {rc}" : NativePcap.ErrorText(errbuf);
                if (h != IntPtr.Zero) NativePcap.pcap_close(h);
                OpenErrors.Add($"{dev.DisplayName}: {err}");
                continue;
            }
            var counter = new InterfaceCounter { Device = dev, LinkType = NativePcap.pcap_datalink(h) };
            Interfaces.Add(counter);
            _open.Add((h, counter, -1));
        }

        if (_open.Count == 0)
            throw new InvalidOperationException("열 수 있는 네트워크 인터페이스가 없습니다.\n" + string.Join("\n", OpenErrors));

        _writer = new PcapNgWriter(_o.OutputPath);
        for (int i = 0; i < _open.Count; i++)
        {
            var (h, c, _) = _open[i];
            int idx = _writer.AddInterface(c.LinkType, _o.SnapLength, c.Device.Name, c.Device.DisplayName);
            _open[i] = (h, c, idx);
        }

        StartedAt = DateTime.UtcNow;
        _clock.Start();
        foreach (var entry in _open)
        {
            var t = new Thread(() => Loop(entry)) { IsBackground = true, Name = "capture:" + entry.Counter.Device.DisplayName };
            _threads.Add(t);
            t.Start();
        }
    }

    void Loop((IntPtr Handle, InterfaceCounter Counter, int Index) e)
    {
        while (!_stop)
        {
            int r = NativePcap.pcap_next_ex(e.Handle, out var hdr, out var dataPtr);
            if (r == 0) { CheckLimits(); continue; }
            if (r < 0)
            {
                if (!_stop && r != -2) e.Counter.Error = Marshal.PtrToStringAnsi(NativePcap.pcap_geterr(e.Handle)) ?? $"오류 {r}";
                break;
            }

            var (time, caplen, len) = NativePcap.ReadHeader(hdr);
            var data = new byte[Math.Max(0, caplen)];
            if (caplen > 0) Marshal.Copy(dataPtr, data, 0, caplen);

            lock (_writeLock)
            {
                if (_writer is null) break;
                _writer.WritePacket(e.Index, time, data, len);
            }
            Interlocked.Increment(ref e.Counter.PacketsField);
            Interlocked.Add(ref e.Counter.BytesField, len);
            long n = Interlocked.Increment(ref _packets);

            if (Preview.Count < _o.PreviewCapacity)
                Preview.Enqueue(PacketDecoder.Decode(new RawFrame((int)n, time, e.Counter.LinkType, len, data, e.Index)));

            CheckLimits();
        }
    }

    void CheckLimits()
    {
        string? reason = null;
        if (_o.MaxBytes > 0 && FileBytes >= _o.MaxBytes)
            reason = $"용량 제한({TimeFormat.Bytes(_o.MaxBytes)})";
        else if (_o.MaxDuration > TimeSpan.Zero && _clock.Elapsed >= _o.MaxDuration)
            reason = $"시간 제한({TimeFormat.Duration(_o.MaxDuration)})";
        if (reason is null || Interlocked.Exchange(ref _limitHit, 1) == 1) return;

        StopReason = $"{reason}에 도달해 자동으로 중지했습니다.";
        _stop = true;
        ThreadPool.QueueUserWorkItem(_ => LimitReached?.Invoke(reason));
    }

    /// <summary>캡처를 멈추고 파일을 닫는다. 여러 번 호출해도 안전하다.</summary>
    public void Stop()
    {
        if (Interlocked.Exchange(ref _stopped, 1) == 1) return;
        _stop = true;
        foreach (var (h, _, _) in _open) NativePcap.pcap_breakloop(h);
        foreach (var t in _threads) t.Join(TimeSpan.FromSeconds(3));
        _clock.Stop();

        foreach (var (h, c, _) in _open)
        {
            var st = new NativePcap.PcapStat();
            if (NativePcap.pcap_stats(h, ref st) == 0) c.Dropped = st.Dropped + st.InterfaceDropped;
            NativePcap.pcap_close(h);
        }
        lock (_writeLock)
        {
            _writer?.Dispose();
        }
        if (StopReason.Length == 0) StopReason = "사용자가 중지했습니다.";
    }

    public void Dispose() => Stop();
}
