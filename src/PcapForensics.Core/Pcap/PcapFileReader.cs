using System.Buffers.Binary;

namespace PcapForensics.Core.Pcap;

/// <summary>캡처 파일에서 읽은 원시 프레임.</summary>
public sealed record RawFrame(int Index, DateTime Timestamp, int LinkType, int OriginalLength, byte[] Data);

/// <summary>
/// pcap(마이크로초/나노초, 리틀/빅 엔디언)과 pcapng 형식을 외부 라이브러리 없이 읽는다.
/// 파일 끝이 잘린 경우 읽을 수 있는 데까지 읽고 경고를 남긴다.
/// </summary>
public static class PcapFileReader
{
    const uint PcapMagicMicro = 0xA1B2C3D4;
    const uint PcapMagicNano = 0xA1B23C4D;
    const uint PcapNgSectionHeader = 0x0A0D0D0A;
    const uint PcapNgByteOrderMagic = 0x1A2B3C4D;
    const int MaxBlockSize = 64 * 1024 * 1024;

    public static IEnumerable<RawFrame> Read(Stream stream, ICollection<string>? warnings = null)
    {
        var head = new byte[4];
        if (!ReadExact(stream, head))
            throw new InvalidDataException("파일이 너무 작아 PCAP 형식이 아닙니다.");

        uint le = BinaryPrimitives.ReadUInt32LittleEndian(head);
        uint be = BinaryPrimitives.ReadUInt32BigEndian(head);
        if (le == PcapNgSectionHeader)
            return ReadPcapNg(stream, head, warnings);
        if (le is PcapMagicMicro or PcapMagicNano)
            return ReadPcap(stream, bigEndian: false, nano: le == PcapMagicNano, warnings);
        if (be is PcapMagicMicro or PcapMagicNano)
            return ReadPcap(stream, bigEndian: true, nano: be == PcapMagicNano, warnings);

        throw new InvalidDataException("지원하지 않는 파일 형식입니다. (pcap / pcapng 만 지원)");
    }

    static IEnumerable<RawFrame> ReadPcap(Stream s, bool bigEndian, bool nano, ICollection<string>? warnings)
    {
        var global = new byte[20];
        if (!ReadExact(s, global))
            throw new InvalidDataException("PCAP 전역 헤더가 손상되었습니다.");
        int linkType = (int)(U32(global, 16, bigEndian) & 0x0FFFFFFF);

        var rec = new byte[16];
        int index = 0;
        while (true)
        {
            int got = ReadUpTo(s, rec);
            if (got == 0) yield break;
            if (got < rec.Length)
            {
                warnings?.Add("파일 끝의 레코드 헤더가 잘려 있습니다.");
                yield break;
            }

            uint sec = U32(rec, 0, bigEndian);
            uint frac = U32(rec, 4, bigEndian);
            uint incl = U32(rec, 8, bigEndian);
            uint orig = U32(rec, 12, bigEndian);
            if (incl > MaxBlockSize)
            {
                warnings?.Add($"비정상적인 패킷 길이({incl} bytes)로 인해 #{index + 1} 에서 읽기를 중단했습니다.");
                yield break;
            }

            var data = new byte[incl];
            if (ReadUpTo(s, data) < data.Length)
            {
                warnings?.Add($"마지막 패킷(#{index + 1})이 잘려 있어 제외했습니다.");
                yield break;
            }

            long ticks = sec * TimeSpan.TicksPerSecond + (nano ? frac / 100 : frac * 10L);
            index++;
            yield return new RawFrame(index, ToDate(ticks), linkType, (int)Math.Max(orig, incl), data);
        }
    }

    static IEnumerable<RawFrame> ReadPcapNg(Stream s, byte[] firstType, ICollection<string>? warnings)
    {
        bool be = false;
        var interfaces = new List<(int LinkType, ulong UnitsPerSecond)>();
        var typeBytes = firstType;
        var lenBytes = new byte[4];
        bool first = true;
        int index = 0;
        DateTime lastTime = DateTime.UnixEpoch;

        while (true)
        {
            if (!first)
            {
                typeBytes = new byte[4];
                int got = ReadUpTo(s, typeBytes);
                if (got == 0) yield break;
                if (got < 4) { warnings?.Add("pcapng 블록 헤더가 잘려 있습니다."); yield break; }
            }
            first = false;

            if (!ReadExact(s, lenBytes)) { warnings?.Add("pcapng 블록 길이가 잘려 있습니다."); yield break; }

            uint typeLe = BinaryPrimitives.ReadUInt32LittleEndian(typeBytes);
            if (typeLe == PcapNgSectionHeader)
            {
                var bom = new byte[4];
                if (!ReadExact(s, bom)) yield break;
                uint bomLe = BinaryPrimitives.ReadUInt32LittleEndian(bom);
                if (bomLe == PcapNgByteOrderMagic) be = false;
                else if (BinaryPrimitives.ReverseEndianness(bomLe) == PcapNgByteOrderMagic) be = true;
                else throw new InvalidDataException("pcapng 섹션 헤더의 바이트 순서 값이 올바르지 않습니다.");

                uint shbLen = U32(lenBytes, 0, be);
                if (shbLen < 28 || shbLen > MaxBlockSize) { warnings?.Add("pcapng 섹션 헤더 길이가 비정상입니다."); yield break; }
                if (!ReadExact(s, new byte[shbLen - 12])) yield break;
                interfaces.Clear();
                continue;
            }

            uint type = U32(typeBytes, 0, be);
            uint blockLen = U32(lenBytes, 0, be);
            if (blockLen < 12 || blockLen > MaxBlockSize)
            {
                warnings?.Add($"비정상적인 pcapng 블록 길이({blockLen})로 읽기를 중단했습니다.");
                yield break;
            }

            var blk = new byte[blockLen - 8]; // 본문 + 끝 길이 필드(4)
            if (!ReadExact(s, blk)) { warnings?.Add("마지막 pcapng 블록이 잘려 있습니다."); yield break; }
            int bodyLen = blk.Length - 4;

            switch (type)
            {
                case 1: // Interface Description Block
                {
                    if (bodyLen < 8) break;
                    int link = U16(blk, 0, be);
                    ulong ups = 1_000_000;
                    int p = 8;
                    while (p + 4 <= bodyLen)
                    {
                        int code = U16(blk, p, be), olen = U16(blk, p + 2, be);
                        p += 4;
                        if (code == 0) break;
                        if (code == 9 && olen >= 1 && p < bodyLen)
                        {
                            byte v = blk[p];
                            ups = (v & 0x80) == 0 ? Pow10(v) : 1UL << Math.Min(63, v & 0x7F);
                        }
                        p += (olen + 3) & ~3;
                    }
                    interfaces.Add((link, ups));
                    break;
                }
                case 6: // Enhanced Packet Block
                case 2: // Obsolete Packet Block
                {
                    if (bodyLen < 20) break;
                    int ifId = type == 6 ? (int)U32(blk, 0, be) : U16(blk, 0, be);
                    ulong ts = ((ulong)U32(blk, 4, be) << 32) | U32(blk, 8, be);
                    int cap = (int)Math.Min(U32(blk, 12, be), (uint)Math.Max(0, bodyLen - 20));
                    int orig = (int)U32(blk, 16, be);
                    var (link, ups) = ifId < interfaces.Count ? interfaces[ifId] : (1, 1_000_000UL);
                    lastTime = ToDate(ToTicks(ts, ups));
                    index++;
                    yield return new RawFrame(index, lastTime, link, Math.Max(orig, cap), blk.AsSpan(20, cap).ToArray());
                    break;
                }
                case 3: // Simple Packet Block (타임스탬프 없음)
                {
                    if (bodyLen < 4) break;
                    int orig = (int)U32(blk, 0, be);
                    int cap = Math.Min(orig, bodyLen - 4);
                    int link = interfaces.Count > 0 ? interfaces[0].LinkType : 1;
                    index++;
                    yield return new RawFrame(index, lastTime, link, orig, blk.AsSpan(4, cap).ToArray());
                    break;
                }
            }
        }
    }

    static ulong Pow10(int e)
    {
        ulong v = 1;
        for (int i = 0; i < Math.Min(e, 19); i++) v *= 10;
        return v;
    }

    static long ToTicks(ulong ts, ulong unitsPerSecond)
    {
        const ulong T = 10_000_000;
        if (unitsPerSecond == 0) return 0;
        if (T % unitsPerSecond == 0) return (long)(ts * (T / unitsPerSecond));
        if (unitsPerSecond % T == 0) return (long)(ts / (unitsPerSecond / T));
        return (long)((double)ts / unitsPerSecond * T);
    }

    static DateTime ToDate(long ticks)
    {
        if (ticks < 0 || ticks > DateTime.MaxValue.Ticks - DateTime.UnixEpoch.Ticks) return DateTime.UnixEpoch;
        return DateTime.UnixEpoch.AddTicks(ticks);
    }

    static uint U32(byte[] b, int o, bool be) =>
        be ? BinaryPrimitives.ReadUInt32BigEndian(b.AsSpan(o)) : BinaryPrimitives.ReadUInt32LittleEndian(b.AsSpan(o));

    static ushort U16(byte[] b, int o, bool be) =>
        be ? BinaryPrimitives.ReadUInt16BigEndian(b.AsSpan(o)) : BinaryPrimitives.ReadUInt16LittleEndian(b.AsSpan(o));

    static int ReadUpTo(Stream s, byte[] buf)
    {
        int total = 0;
        while (total < buf.Length)
        {
            int n = s.Read(buf, total, buf.Length - total);
            if (n <= 0) break;
            total += n;
        }
        return total;
    }

    static bool ReadExact(Stream s, byte[] buf) => ReadUpTo(s, buf) == buf.Length;
}
