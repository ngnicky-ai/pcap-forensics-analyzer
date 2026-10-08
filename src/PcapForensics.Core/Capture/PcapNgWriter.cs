namespace PcapForensics.Core.Capture;

/// <summary>
/// pcapng 파일 작성기. 인터페이스마다 링크 타입이 달라도(이더넷, 루프백 등) 한 파일에 담을 수 있다.
/// 모든 인터페이스(IDB)를 패킷(EPB)보다 먼저 추가해야 한다.
/// </summary>
public sealed class PcapNgWriter : IDisposable
{
    readonly FileStream _fs;
    readonly BinaryWriter _w;
    int _interfaces;
    long _written;
    bool _packetsStarted;

    public PcapNgWriter(string path, string application = "PcapForensics")
    {
        Directory.CreateDirectory(System.IO.Path.GetDirectoryName(System.IO.Path.GetFullPath(path))!);
        _fs = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.Read, 1 << 20);
        _w = new BinaryWriter(_fs);
        FilePath = path;

        // Section Header Block (+ shb_userappl 옵션)
        var opts = Options((4, Encoding.UTF8.GetBytes(application)));
        int len = 28 + opts.Length;
        _w.Write(0x0A0D0D0Au);
        _w.Write((uint)len);
        _w.Write(0x1A2B3C4Du);
        _w.Write((ushort)1);
        _w.Write((ushort)0);
        _w.Write(-1L); // 섹션 길이 미정
        _w.Write(opts);
        _w.Write((uint)len);
        _written = len;
    }

    public string FilePath { get; }
    public long BytesWritten => Interlocked.Read(ref _written);
    public int InterfaceCount => _interfaces;

    /// <summary>인터페이스를 등록하고 패킷 기록에 쓸 번호를 돌려준다.</summary>
    public int AddInterface(int linkType, int snapLength, string name, string description)
    {
        if (_packetsStarted) throw new InvalidOperationException("패킷을 기록한 뒤에는 인터페이스를 추가할 수 없습니다.");
        var opts = Options(
            (2, Encoding.UTF8.GetBytes(name)),
            (3, Encoding.UTF8.GetBytes(description)),
            (9, new byte[] { 6 })); // if_tsresol: 마이크로초
        int len = 20 + opts.Length;
        _w.Write(1u);
        _w.Write((uint)len);
        _w.Write((ushort)linkType);
        _w.Write((ushort)0);
        _w.Write((uint)snapLength);
        _w.Write(opts);
        _w.Write((uint)len);
        Interlocked.Add(ref _written, len);
        return _interfaces++;
    }

    /// <summary>Enhanced Packet Block 기록. 호출자가 동시 호출을 직렬화해야 한다.</summary>
    public void WritePacket(int interfaceId, DateTime timestampUtc, ReadOnlySpan<byte> data, int originalLength)
    {
        if ((uint)interfaceId >= (uint)_interfaces) throw new ArgumentOutOfRangeException(nameof(interfaceId));
        _packetsStarted = true;
        ulong us = (ulong)Math.Max(0, (timestampUtc.Ticks - DateTime.UnixEpoch.Ticks) / 10);
        int pad = (4 - data.Length % 4) % 4;
        int len = 32 + data.Length + pad;
        _w.Write(6u);
        _w.Write((uint)len);
        _w.Write((uint)interfaceId);
        _w.Write((uint)(us >> 32));
        _w.Write((uint)us);
        _w.Write((uint)data.Length);
        _w.Write((uint)Math.Max(originalLength, data.Length));
        _w.Write(data);
        for (int i = 0; i < pad; i++) _w.Write((byte)0);
        _w.Write((uint)len);
        Interlocked.Add(ref _written, len);
    }

    public void Flush() => _w.Flush();

    public void Dispose()
    {
        _w.Flush();
        _w.Dispose();
    }

    static byte[] Options(params (ushort Code, byte[] Value)[] options)
    {
        using var ms = new MemoryStream();
        var w = new BinaryWriter(ms);
        foreach (var (code, value) in options)
        {
            if (value.Length == 0 || value.Length > ushort.MaxValue) continue;
            w.Write(code);
            w.Write((ushort)value.Length);
            w.Write(value);
            for (int i = 0; i < (4 - value.Length % 4) % 4; i++) w.Write((byte)0);
        }
        w.Write((ushort)0); // opt_endofopt
        w.Write((ushort)0);
        return ms.ToArray();
    }
}
