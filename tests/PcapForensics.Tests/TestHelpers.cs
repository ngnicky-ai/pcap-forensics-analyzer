using System.Buffers.Binary;
using PcapForensics.Core.Analysis;

namespace PcapForensics.Tests;

/// <summary>테스트용 패킷/캡처 파일을 바이트 단위로 만든다.</summary>
internal static class Bytes
{
    public static byte[] Ethernet(ushort etherType, byte[] payload, int vlan = -1)
    {
        var list = new List<byte>();
        list.AddRange(new byte[] { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 }); // dst
        list.AddRange(new byte[] { 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb }); // src
        if (vlan >= 0)
        {
            list.AddRange(Be16(0x8100));
            list.AddRange(Be16((ushort)vlan));
        }
        list.AddRange(Be16(etherType));
        list.AddRange(payload);
        return list.ToArray();
    }

    public static byte[] IPv4(string src, string dst, byte proto, byte[] l4)
    {
        var h = new byte[20];
        h[0] = 0x45;
        BinaryPrimitives.WriteUInt16BigEndian(h.AsSpan(2), (ushort)(20 + l4.Length));
        h[8] = 64;
        h[9] = proto;
        System.Net.IPAddress.Parse(src).GetAddressBytes().CopyTo(h, 12);
        System.Net.IPAddress.Parse(dst).GetAddressBytes().CopyTo(h, 16);
        return h.Concat(l4).ToArray();
    }

    public static byte[] IPv6(string src, string dst, byte next, byte[] l4)
    {
        var h = new byte[40];
        h[0] = 0x60;
        BinaryPrimitives.WriteUInt16BigEndian(h.AsSpan(4), (ushort)l4.Length);
        h[6] = next;
        h[7] = 64;
        System.Net.IPAddress.Parse(src).GetAddressBytes().CopyTo(h, 8);
        System.Net.IPAddress.Parse(dst).GetAddressBytes().CopyTo(h, 24);
        return h.Concat(l4).ToArray();
    }

    public static byte[] Tcp(int sport, int dport, uint seq, uint ack, TcpFlags flags, byte[]? payload = null)
    {
        var h = new byte[20];
        BinaryPrimitives.WriteUInt16BigEndian(h, (ushort)sport);
        BinaryPrimitives.WriteUInt16BigEndian(h.AsSpan(2), (ushort)dport);
        BinaryPrimitives.WriteUInt32BigEndian(h.AsSpan(4), seq);
        BinaryPrimitives.WriteUInt32BigEndian(h.AsSpan(8), ack);
        h[12] = 5 << 4;
        h[13] = (byte)flags;
        BinaryPrimitives.WriteUInt16BigEndian(h.AsSpan(14), 65535);
        return h.Concat(payload ?? Array.Empty<byte>()).ToArray();
    }

    public static byte[] Udp(int sport, int dport, byte[] payload)
    {
        var h = new byte[8];
        BinaryPrimitives.WriteUInt16BigEndian(h, (ushort)sport);
        BinaryPrimitives.WriteUInt16BigEndian(h.AsSpan(2), (ushort)dport);
        BinaryPrimitives.WriteUInt16BigEndian(h.AsSpan(4), (ushort)(8 + payload.Length));
        return h.Concat(payload).ToArray();
    }

    public static byte[] Be16(ushort v) => new[] { (byte)(v >> 8), (byte)v };

    /// <summary>클래식 pcap (리틀 엔디언, 마이크로초).</summary>
    public static byte[] ClassicPcap(int linkType, params (uint Sec, uint Usec, byte[] Data)[] frames)
    {
        using var ms = new MemoryStream();
        var w = new BinaryWriter(ms);
        w.Write(0xA1B2C3D4u);
        w.Write((ushort)2);
        w.Write((ushort)4);
        w.Write(0);
        w.Write(0u);
        w.Write(65535u);
        w.Write((uint)linkType);
        foreach (var (sec, usec, data) in frames)
        {
            w.Write(sec);
            w.Write(usec);
            w.Write((uint)data.Length);
            w.Write((uint)data.Length);
            w.Write(data);
        }
        return ms.ToArray();
    }

    public static byte[] Ascii(string s) => Encoding.ASCII.GetBytes(s);
}

/// <summary>각 줄의 도착 시각을 지정해 재조립 스트림을 만든다.</summary>
internal static class Streams
{
    public static ReassembledStream Of(params (DateTime Time, string Text)[] parts)
    {
        var data = new List<byte>();
        var marks = new List<StreamMark>();
        foreach (var (time, text) in parts)
        {
            marks.Add(new StreamMark(data.Count, time));
            data.AddRange(Encoding.UTF8.GetBytes(text));
        }
        return new ReassembledStream(data.ToArray(), marks, 0);
    }

    public static ReassembledStream Of(byte[] data) =>
        new(data, new[] { new StreamMark(0, new DateTime(2020, 1, 1, 0, 0, 0, DateTimeKind.Utc)) }, 0);
}

/// <summary>저장소의 samples 폴더 위치와, 샘플별 분석 결과(테스트 간 공유).</summary>
public sealed class SampleFixture
{
    readonly Dictionary<string, AnalysisResult> _cache = new();

    public static string SamplesDir
    {
        get
        {
            var dir = new DirectoryInfo(AppContext.BaseDirectory);
            while (dir is not null && !Directory.Exists(Path.Combine(dir.FullName, "samples"))) dir = dir.Parent;
            return dir is null ? throw new DirectoryNotFoundException("samples 폴더를 찾을 수 없습니다.") : Path.Combine(dir.FullName, "samples");
        }
    }

    public static string Sample(string name) => Path.Combine(SamplesDir, name);

    /// <summary>샘플 경로. 저장소에 포함되지 않은 샘플이면 테스트를 건너뛴다.</summary>
    public static string Require(string name)
    {
        var path = Sample(name);
        Skip.IfNot(File.Exists(path), $"samples\\{name} 없음 (저장소에는 2015-08-31-traffic-analysis-exercise.pcap 만 포함)");
        return path;
    }

    public AnalysisResult Analyze(string name)
    {
        lock (_cache)
        {
            if (!_cache.TryGetValue(name, out var r)) _cache[name] = r = new PcapAnalyzer().Analyze(Require(name));
            return r;
        }
    }
}
