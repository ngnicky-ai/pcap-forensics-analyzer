using System.Net;
using System.Text.RegularExpressions;

namespace PcapForensics.Core.Detection;

/// <summary>
/// 침해 지표(IOC) 목록. 한 줄에 하나의 값(IP, CIDR, 도메인, URL, MD5/SHA1/SHA256)을 적고
/// '#' 또는 ',' 뒤에 설명을 붙일 수 있다. 무력화 표기(hxxp, [.])도 인식한다.
/// </summary>
public sealed class IocSet
{
    public static IocSet Empty { get; } = new();

    public Dictionary<string, string> Ips { get; } = new();
    public Dictionary<string, string> Domains { get; } = new();
    public Dictionary<string, string> Hashes { get; } = new();
    public List<(IPAddress Network, int Prefix, string Text, string Comment)> Networks { get; } = new();
    public string SourcePath { get; private set; } = "";

    public int Count => Ips.Count + Domains.Count + Hashes.Count + Networks.Count;

    static readonly Regex HexHash = new("^[0-9a-fA-F]{32}$|^[0-9a-fA-F]{40}$|^[0-9a-fA-F]{64}$");

    public static IocSet LoadFromFile(string path)
    {
        var set = Parse(File.ReadAllLines(path));
        set.SourcePath = path;
        return set;
    }

    public static IocSet Parse(IEnumerable<string> lines)
    {
        var set = new IocSet();
        foreach (var raw in lines)
        {
            var line = raw.Trim();
            if (line.Length == 0 || line.StartsWith('#') || line.StartsWith("//")) continue;

            string value = line, comment = "";
            int cut = line.IndexOfAny(new[] { '#', ',', '\t', ' ' });
            if (cut > 0)
            {
                value = line[..cut].Trim();
                comment = line[(cut + 1)..].Trim().TrimStart('#', ',').Trim();
            }

            value = value.Replace("[.]", ".").Replace("(.)", ".").Replace("[:]", ":");
            if (value.StartsWith("hxxp", StringComparison.OrdinalIgnoreCase)) value = "http" + value[4..];
            set.Add(value, comment);
        }
        return set;
    }

    void Add(string value, string comment)
    {
        if (HexHash.IsMatch(value)) { Hashes[value.ToLowerInvariant()] = comment; return; }

        int slash = value.IndexOf('/');
        if (slash > 0 && !value.Contains("://") && IPAddress.TryParse(value[..slash], out var net)
            && int.TryParse(value[(slash + 1)..], out int prefix))
        {
            Networks.Add((net, prefix, value, comment));
            return;
        }

        // URL → 호스트
        if (value.Contains("://"))
        {
            if (!Uri.TryCreate(value, UriKind.Absolute, out var uri)) return;
            value = uri.Host;
        }
        else if (slash > 0) value = value[..slash];

        // IPv4:포트 → IP
        int colon = value.LastIndexOf(':');
        if (colon > 0 && value.IndexOf(':') == colon) value = value[..colon];

        if (IPAddress.TryParse(value.Trim('[', ']'), out var ip)) Ips[ip.ToString()] = comment;
        else if (value.Contains('.')) Domains[DomainUtil.Normalize(value)] = comment;
    }

    public bool TryMatchIp(string ip, out string matched, out string comment)
    {
        if (Ips.TryGetValue(ip, out comment!)) { matched = ip; return true; }
        if (Networks.Count > 0 && IPAddress.TryParse(ip, out var addr))
        {
            foreach (var (network, prefix, text, c) in Networks)
            {
                if (InNetwork(addr, network, prefix)) { matched = text; comment = c; return true; }
            }
        }
        matched = comment = "";
        return false;
    }

    /// <summary>정확히 일치하거나 IOC 도메인의 하위 도메인이면 일치로 본다.</summary>
    public bool TryMatchDomain(string name, out string matched, out string comment)
    {
        var n = DomainUtil.Normalize(name);
        while (n.Length > 0)
        {
            if (Domains.TryGetValue(n, out comment!)) { matched = n; return true; }
            int dot = n.IndexOf('.');
            if (dot < 0) break;
            n = n[(dot + 1)..];
        }
        matched = comment = "";
        return false;
    }

    public bool TryMatchHash(string hash, out string comment) =>
        Hashes.TryGetValue(hash.ToLowerInvariant(), out comment!);

    static bool InNetwork(IPAddress addr, IPAddress network, int prefix)
    {
        var a = addr.GetAddressBytes();
        var n = network.GetAddressBytes();
        if (a.Length != n.Length || prefix < 0 || prefix > a.Length * 8) return false;
        int full = prefix / 8, rem = prefix % 8;
        for (int i = 0; i < full; i++) if (a[i] != n[i]) return false;
        if (rem == 0) return true;
        int mask = 0xFF << (8 - rem) & 0xFF;
        return (a[full] & mask) == (n[full] & mask);
    }
}
