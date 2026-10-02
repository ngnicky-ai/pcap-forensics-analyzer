using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;

namespace PcapForensics.Core.Util;

public static class TimeFormat
{
    /// <summary>모든 시각은 UTC 기준으로 표시한다.</summary>
    public static string Format(DateTime t) => t.ToString("yyyy-MM-dd HH:mm:ss.fff", CultureInfo.InvariantCulture);
    public static string Format(DateTime? t) => t.HasValue ? Format(t.Value) : "-";
    public static string Precise(DateTime t) => t.ToString("yyyy-MM-dd HH:mm:ss.ffffff", CultureInfo.InvariantCulture);

    public static string Duration(TimeSpan d)
    {
        if (d.TotalHours >= 1) return $"{(int)d.TotalHours}시간 {d.Minutes}분 {d.Seconds}초";
        if (d.TotalMinutes >= 1) return $"{d.Minutes}분 {d.Seconds}초";
        return $"{d.TotalSeconds:F1}초";
    }

    public static string Bytes(long b)
    {
        if (b >= 1L << 30) return $"{b / (double)(1L << 30):F2} GB";
        if (b >= 1L << 20) return $"{b / (double)(1L << 20):F2} MB";
        if (b >= 1024) return $"{b / 1024.0:F1} KB";
        return $"{b} B";
    }
}

public static class NetUtil
{
    public static string Endpoint(string ip, int port) => ip.Contains(':') ? $"[{ip}]:{port}" : $"{ip}:{port}";

    /// <summary>사설/루프백/링크로컬/멀티캐스트 등 인터넷 라우팅 대상이 아닌 주소인지 확인.</summary>
    public static bool IsInternal(string ip)
    {
        if (!IPAddress.TryParse(ip, out var a)) return false;
        if (a.AddressFamily == AddressFamily.InterNetwork)
        {
            var b = a.GetAddressBytes();
            return b[0] == 10 || b[0] == 127 || b[0] == 0 || b[0] >= 224
                || (b[0] == 172 && b[1] >= 16 && b[1] <= 31)
                || (b[0] == 192 && b[1] == 168)
                || (b[0] == 169 && b[1] == 254)
                || (b[0] == 100 && b[1] >= 64 && b[1] <= 127);
        }
        if (a.AddressFamily == AddressFamily.InterNetworkV6)
        {
            var b = a.GetAddressBytes();
            return IPAddress.IsLoopback(a) || a.IsIPv6LinkLocal || a.IsIPv6SiteLocal || a.IsIPv6Multicast
                || (b[0] & 0xFE) == 0xFC || a.Equals(IPAddress.IPv6None);
        }
        return false;
    }

    public static bool IsExternal(string ip) => !IsInternal(ip) && IPAddress.TryParse(ip, out _);

    public static bool IsIpLiteral(string host)
    {
        host = host.Trim();
        if (host.StartsWith('[')) return true;
        int colon = host.LastIndexOf(':');
        if (colon > 0 && host.IndexOf(':') == colon) host = host[..colon];
        return IPAddress.TryParse(host, out _);
    }
}

public static class DomainUtil
{
    static readonly HashSet<string> SecondLevel = new(StringComparer.OrdinalIgnoreCase)
    {
        "co.kr", "or.kr", "go.kr", "ac.kr", "ne.kr", "re.kr", "pe.kr", "ms.kr", "hs.kr", "es.kr",
        "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.jp", "ne.jp", "or.jp",
        "com.cn", "net.cn", "org.cn", "com.br", "com.tw", "co.in", "co.nz", "com.mx", "com.sg",
        "com.hk", "co.za", "com.tr", "com.ru", "com.ua",
    };

    public static string Normalize(string name) => name.Trim().TrimEnd('.').ToLowerInvariant();

    /// <summary>등록 도메인(근사치). 예: a.b.example.co.kr → example.co.kr</summary>
    public static string BaseDomain(string name)
    {
        name = Normalize(name);
        var labels = name.Split('.', StringSplitOptions.RemoveEmptyEntries);
        if (labels.Length <= 2) return name;
        string last2 = labels[^2] + "." + labels[^1];
        return SecondLevel.Contains(last2) ? labels[^3] + "." + last2 : last2;
    }

    public static string SubdomainPart(string name, string baseDomain)
    {
        name = Normalize(name);
        return name.Length > baseDomain.Length && name.EndsWith("." + baseDomain, StringComparison.Ordinal)
            ? name[..^(baseDomain.Length + 1)]
            : "";
    }

    public static bool MatchesSuffix(string name, string domain)
    {
        name = Normalize(name);
        return name == domain || name.EndsWith("." + domain, StringComparison.Ordinal);
    }
}

public static class EntropyUtil
{
    public static double Shannon(ReadOnlySpan<byte> data)
    {
        if (data.IsEmpty) return 0;
        Span<int> counts = stackalloc int[256];
        foreach (var b in data) counts[b]++;
        double e = 0, n = data.Length;
        foreach (var c in counts)
        {
            if (c == 0) continue;
            double p = c / n;
            e -= p * Math.Log2(p);
        }
        return e;
    }

    public static double Shannon(string s)
    {
        if (s.Length == 0) return 0;
        var counts = new Dictionary<char, int>();
        foreach (var ch in s) counts[ch] = counts.GetValueOrDefault(ch) + 1;
        double e = 0;
        foreach (var c in counts.Values)
        {
            double p = (double)c / s.Length;
            e -= p * Math.Log2(p);
        }
        return e;
    }
}

public static class HashUtil
{
    public static string Md5(byte[] d) => Convert.ToHexString(MD5.HashData(d)).ToLowerInvariant();
    public static string Sha1(byte[] d) => Convert.ToHexString(SHA1.HashData(d)).ToLowerInvariant();
    public static string Sha256(byte[] d) => Convert.ToHexString(SHA256.HashData(d)).ToLowerInvariant();

    public static string Sha256File(string path)
    {
        using var fs = File.OpenRead(path);
        return Convert.ToHexString(SHA256.HashData(fs)).ToLowerInvariant();
    }
}

public static class TextUtil
{
    public static readonly Encoding Latin1 = Encoding.Latin1;

    /// <summary>바이트를 사람이 읽을 수 있는 텍스트로 변환(제어 문자는 '.').</summary>
    public static string ToPrintable(ReadOnlySpan<byte> data, int max = 256 * 1024)
    {
        if (data.Length > max) data = data[..max];
        var s = Encoding.UTF8.GetString(data);
        var sb = new StringBuilder(s.Length);
        foreach (var ch in s)
        {
            if (ch is '\r' or '\n' or '\t') sb.Append(ch);
            else if (char.IsControl(ch) || ch == '�') sb.Append('.');
            else sb.Append(ch);
        }
        return sb.ToString();
    }

    /// <summary>텍스트로 보기 적합한지(출력 가능한 바이트 비율).</summary>
    public static bool LooksLikeText(ReadOnlySpan<byte> data)
    {
        if (data.IsEmpty) return true;
        var sample = data.Length > 4096 ? data[..4096] : data;
        int printable = 0;
        foreach (var b in sample)
            if (b is (>= 0x20 and < 0x7F) or 0x0D or 0x0A or 0x09 or >= 0x80) printable++;
        int zeros = sample.Count((byte)0);
        return zeros == 0 && printable >= sample.Length * 0.9;
    }

    public static string HexDump(ReadOnlySpan<byte> data, int max = 64 * 1024)
    {
        if (data.Length > max) data = data[..max];
        var sb = new StringBuilder(data.Length * 4 + 64);
        for (int i = 0; i < data.Length; i += 16)
        {
            sb.Append(i.ToString("X6")).Append("  ");
            for (int j = 0; j < 16; j++)
            {
                if (i + j < data.Length) sb.Append(data[i + j].ToString("X2")).Append(' ');
                else sb.Append("   ");
                if (j == 7) sb.Append(' ');
            }
            sb.Append(" |");
            for (int j = 0; j < 16 && i + j < data.Length; j++)
            {
                byte b = data[i + j];
                sb.Append(b is >= 0x20 and < 0x7F ? (char)b : '.');
            }
            sb.Append("|\n");
        }
        return sb.ToString();
    }

    public static string Truncate(string s, int max) => s.Length <= max ? s : s[..max] + "…";

    public static string SafeFileName(string name, int max = 80)
    {
        var invalid = Path.GetInvalidFileNameChars();
        var sb = new StringBuilder();
        foreach (var ch in name) sb.Append(invalid.Contains(ch) ? '_' : ch);
        var s = sb.ToString().Trim(' ', '.');
        if (s.Length == 0) s = "file";
        return s.Length > max ? s[..max] : s;
    }

    public static string Base64DecodeText(string s)
    {
        try { return Encoding.UTF8.GetString(Convert.FromBase64String(s.Trim())); }
        catch (FormatException) { return s; }
    }
}

public static class ByteUtil
{
    public static bool StartsWithAscii(byte[] d, int pos, string token)
    {
        if (pos < 0 || pos + token.Length > d.Length) return false;
        for (int i = 0; i < token.Length; i++)
            if (d[pos + i] != (byte)token[i]) return false;
        return true;
    }

    public static int IndexOf(byte[] d, ReadOnlySpan<byte> pattern, int start, int maxSearch = int.MaxValue)
    {
        if (start >= d.Length) return -1;
        int len = (int)Math.Min((long)d.Length - start, maxSearch);
        int i = d.AsSpan(start, len).IndexOf(pattern);
        return i < 0 ? -1 : start + i;
    }
}
