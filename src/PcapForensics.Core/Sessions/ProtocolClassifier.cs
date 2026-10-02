using PcapForensics.Core.Protocols;

namespace PcapForensics.Core.Sessions;

/// <summary>페이로드 시그니처를 우선하고, 실패하면 포트 번호로 응용 계층 프로토콜을 추정한다.</summary>
public static class ProtocolClassifier
{
    static readonly Dictionary<int, string> TcpPorts = new()
    {
        [20] = "FTP-DATA", [21] = "FTP", [22] = "SSH", [23] = "Telnet", [25] = "SMTP", [53] = "DNS",
        [80] = "HTTP", [88] = "Kerberos", [110] = "POP3", [111] = "RPC", [135] = "MSRPC", [139] = "NetBIOS-SSN",
        [143] = "IMAP", [389] = "LDAP", [443] = "TLS", [445] = "SMB", [465] = "SMTPS", [587] = "SMTP",
        [636] = "LDAPS", [993] = "IMAPS", [995] = "POP3S", [1433] = "MSSQL", [1521] = "Oracle", [3128] = "HTTP-Proxy",
        [3306] = "MySQL", [3389] = "RDP", [4444] = "TCP/4444", [5432] = "PostgreSQL", [5900] = "VNC",
        [5985] = "WinRM", [5986] = "WinRM-TLS", [6379] = "Redis", [6667] = "IRC", [8080] = "HTTP-Alt",
        [8443] = "TLS", [9200] = "Elasticsearch", [27017] = "MongoDB",
    };

    static readonly Dictionary<int, string> UdpPorts = new()
    {
        [53] = "DNS", [67] = "DHCP", [68] = "DHCP", [69] = "TFTP", [123] = "NTP", [137] = "NBNS",
        [138] = "NetBIOS-DGM", [161] = "SNMP", [162] = "SNMP-Trap", [500] = "IKE", [514] = "Syslog",
        [1900] = "SSDP", [3702] = "WS-Discovery", [4500] = "IPsec-NAT", [5353] = "mDNS", [5355] = "LLMNR",
        [443] = "QUIC", [1194] = "OpenVPN", [51820] = "WireGuard",
    };

    public static string Classify(NetworkSession s)
    {
        var c = s.ClientData.Data;
        var sv = s.ServerData.Data;

        if (s.Transport == TransportProtocol.Tcp)
        {
            if (HttpParser.LooksLikeRequest(c, 0) || ByteUtil.StartsWithAscii(sv, 0, "HTTP/1.")) return "HTTP";
            if (IsTls(c) || IsTls(sv)) return "TLS";
            if (ByteUtil.StartsWithAscii(c, 0, "SSH-") || ByteUtil.StartsWithAscii(sv, 0, "SSH-")) return "SSH";
            if (IsSmb(c) || IsSmb(sv)) return "SMB";
            if (ByteUtil.StartsWithAscii(c, 0, "\u0003\u0000") && s.ServerPort == 3389) return "RDP";

            if (ByteUtil.StartsWithAscii(sv, 0, "220"))
            {
                string firstClient = FirstLine(c).ToUpperInvariant();
                string banner = FirstLine(sv).ToUpperInvariant();
                if (firstClient.StartsWith("EHLO") || firstClient.StartsWith("HELO")) return "SMTP";
                if (firstClient.StartsWith("USER") || firstClient.StartsWith("AUTH TLS") || firstClient.StartsWith("FEAT")) return "FTP";
                if (s.ServerPort == 21 || banner.Contains("FTP")) return "FTP";
                if (s.ServerPort is 25 or 587 || banner.Contains("SMTP")) return "SMTP";
            }
            if (ByteUtil.StartsWithAscii(sv, 0, "+OK")) return "POP3";
            if (ByteUtil.StartsWithAscii(sv, 0, "* OK")) return "IMAP";
            if (s.ServerPort == 53 && c.Length > 14) return "DNS";

            if (TcpPorts.TryGetValue(s.ServerPort, out var name))
            {
                // 포트만으로 추정한 HTTP/TLS 는 실제 페이로드가 없을 때만 사용
                if (name is "HTTP" or "TLS" or "HTTP-Alt" && c.Length > 0) return "TCP";
                return name;
            }
            return "TCP";
        }

        if (UdpPorts.TryGetValue(s.ServerPort, out var u)) return u;
        if (UdpPorts.TryGetValue(s.ClientPort, out u) && s.ClientPort < 1024) return u;
        return "UDP";
    }

    static bool IsTls(byte[] d) => d.Length >= 6 && d[0] is 0x16 or 0x17 or 0x15 && d[1] == 0x03 && d[2] <= 0x04;

    static bool IsSmb(byte[] d) =>
        d.Length >= 8 && d[0] == 0x00 && (d[4] == 0xFF || d[4] == 0xFE) && d[5] == 'S' && d[6] == 'M' && d[7] == 'B';

    static string FirstLine(byte[] d)
    {
        int n = Math.Min(d.Length, 256);
        int end = Array.IndexOf(d, (byte)'\n', 0, n);
        return TextUtil.Latin1.GetString(d, 0, end < 0 ? n : end).Trim();
    }
}
