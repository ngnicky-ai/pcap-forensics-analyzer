using System.Buffers.Binary;
using System.Net;

namespace PcapForensics.Core.Protocols;

public sealed class DnsMessage
{
    public int Id { get; init; }
    public bool IsResponse { get; init; }
    public int RCode { get; init; }
    public string QueryName { get; init; } = "";
    public string QueryType { get; init; } = "";
    public List<DnsAnswer> Answers { get; } = new();

    public string Summary => IsResponse
        ? $"응답 0x{Id:X4} {QueryType} {QueryName} → " + (RCode != 0 ? RCodeName(RCode) : string.Join(", ", Answers.Select(a => a.Data)))
        : $"질의 0x{Id:X4} {QueryType} {QueryName}";

    static string RCodeName(int r) => r switch { 1 => "FORMERR", 2 => "SERVFAIL", 3 => "NXDOMAIN", 4 => "NOTIMP", 5 => "REFUSED", _ => $"RCODE {r}" };
}

/// <summary>DNS 메시지 파서(이름 압축 포인터 처리, 루프 방지 포함).</summary>
public static class DnsParser
{
    public static DnsMessage? TryParse(ReadOnlySpan<byte> span)
    {
        var m = span.ToArray();
        try
        {
            if (m.Length < 12) return null;
            int id = BinaryPrimitives.ReadUInt16BigEndian(m);
            ushort flags = BinaryPrimitives.ReadUInt16BigEndian(m.AsSpan(2));
            int qd = BinaryPrimitives.ReadUInt16BigEndian(m.AsSpan(4));
            int an = BinaryPrimitives.ReadUInt16BigEndian(m.AsSpan(6));
            if (qd == 0 || qd > 16 || an > 512) return null;

            int pos = 12;
            string qname = ReadName(m, ref pos);
            if (pos + 4 > m.Length) return null;
            int qtype = BinaryPrimitives.ReadUInt16BigEndian(m.AsSpan(pos));
            pos += 4;
            for (int i = 1; i < qd; i++)
            {
                ReadName(m, ref pos);
                pos += 4;
            }

            var msg = new DnsMessage
            {
                Id = id,
                IsResponse = (flags & 0x8000) != 0,
                RCode = flags & 0x000F,
                QueryName = qname,
                QueryType = TypeName(qtype),
            };

            for (int i = 0; i < an && pos < m.Length; i++)
            {
                string name = ReadName(m, ref pos);
                if (pos + 10 > m.Length) break;
                int type = BinaryPrimitives.ReadUInt16BigEndian(m.AsSpan(pos));
                uint ttl = BinaryPrimitives.ReadUInt32BigEndian(m.AsSpan(pos + 4));
                int rdlen = BinaryPrimitives.ReadUInt16BigEndian(m.AsSpan(pos + 8));
                pos += 10;
                if (pos + rdlen > m.Length) break;
                msg.Answers.Add(new DnsAnswer(name, TypeName(type), RData(m, pos, rdlen, type), ttl));
                pos += rdlen;
            }
            return msg;
        }
        catch (FormatException) { return null; }
        catch (ArgumentOutOfRangeException) { return null; }
        catch (IndexOutOfRangeException) { return null; }
    }

    static string RData(byte[] m, int pos, int len, int type)
    {
        switch (type)
        {
            case 1 when len == 4:
                return $"{m[pos]}.{m[pos + 1]}.{m[pos + 2]}.{m[pos + 3]}";
            case 28 when len == 16:
                return new IPAddress(m.AsSpan(pos, 16)).ToString();
            case 2: case 5: case 12:
            {
                int p = pos;
                return ReadName(m, ref p);
            }
            case 15 when len > 2:
            {
                int p = pos + 2;
                return $"{BinaryPrimitives.ReadUInt16BigEndian(m.AsSpan(pos))} {ReadName(m, ref p)}";
            }
            case 16:
            {
                var sb = new StringBuilder();
                int p = pos, end = pos + len;
                while (p < end)
                {
                    int l = m[p++];
                    if (p + l > end) break;
                    if (sb.Length > 0) sb.Append(' ');
                    sb.Append('"').Append(TextUtil.Latin1.GetString(m, p, l)).Append('"');
                    p += l;
                }
                return sb.ToString();
            }
            default:
                return $"({len} bytes)";
        }
    }

    public static string ReadName(byte[] m, ref int pos)
    {
        var sb = new StringBuilder();
        int p = pos, jumps = 0;
        bool jumped = false;
        while (true)
        {
            if (p >= m.Length) throw new FormatException();
            int len = m[p];
            if (len == 0) { p++; break; }
            if ((len & 0xC0) == 0xC0)
            {
                if (p + 1 >= m.Length) throw new FormatException();
                int ptr = ((len & 0x3F) << 8) | m[p + 1];
                if (!jumped) pos = p + 2;
                jumped = true;
                if (++jumps > 32 || ptr >= m.Length) throw new FormatException();
                p = ptr;
                continue;
            }
            if ((len & 0xC0) != 0) throw new FormatException();
            p++;
            if (p + len > m.Length) throw new FormatException();
            if (sb.Length > 0) sb.Append('.');
            for (int i = 0; i < len; i++)
            {
                byte b = m[p + i];
                if (b is > 0x20 and < 0x7F) sb.Append((char)b);
                else sb.Append($"\\x{b:x2}");
            }
            p += len;
            if (sb.Length > 1024) throw new FormatException();
        }
        if (!jumped) pos = p;
        return sb.ToString();
    }

    public static string TypeName(int t) => t switch
    {
        1 => "A", 2 => "NS", 5 => "CNAME", 6 => "SOA", 10 => "NULL", 12 => "PTR", 13 => "HINFO", 15 => "MX",
        16 => "TXT", 28 => "AAAA", 33 => "SRV", 35 => "NAPTR", 41 => "OPT", 43 => "DS", 46 => "RRSIG",
        47 => "NSEC", 48 => "DNSKEY", 64 => "SVCB", 65 => "HTTPS", 99 => "SPF", 252 => "AXFR", 255 => "ANY",
        _ => $"TYPE{t}",
    };
}
