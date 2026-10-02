namespace PcapForensics.Core.Protocols;

/// <summary>TLS ClientHello 에서 SNI(접속 대상 도메인)와 버전을 추출한다.</summary>
public static class TlsParser
{
    public static (string? Sni, string Version) ParseClientHello(byte[] d)
    {
        // 여러 레코드에 걸친 핸드셰이크 조각을 이어 붙인다
        using var ms = new MemoryStream();
        int pos = 0;
        while (pos + 5 <= d.Length && d[pos] == 0x16 && d[pos + 1] == 0x03 && ms.Length < 65536)
        {
            int len = (d[pos + 3] << 8) | d[pos + 4];
            int take = Math.Min(len, d.Length - pos - 5);
            ms.Write(d, pos + 5, take);
            pos += 5 + len;
            if (ms.Length >= 4)
            {
                var buf = ms.GetBuffer();
                int hsLen = (buf[1] << 16) | (buf[2] << 8) | buf[3];
                if (ms.Length >= hsLen + 4) break;
            }
        }

        var h = ms.ToArray();
        if (h.Length < 42 || h[0] != 0x01) return (null, "");
        string version = VersionName((h[4] << 8) | h[5]);

        try
        {
            int p = 4 + 2 + 32;
            p += 1 + h[p];                          // session id
            p += 2 + ((h[p] << 8) | h[p + 1]);      // cipher suites
            p += 1 + h[p];                          // compression methods
            if (p + 2 > h.Length) return (null, version);
            int extEnd = Math.Min(h.Length, p + 2 + ((h[p] << 8) | h[p + 1]));
            p += 2;

            string? sni = null;
            while (p + 4 <= extEnd)
            {
                int type = (h[p] << 8) | h[p + 1];
                int len = (h[p + 2] << 8) | h[p + 3];
                p += 4;
                if (p + len > extEnd) break;
                if (type == 0 && len >= 5 && h[p + 2] == 0)
                {
                    int nameLen = (h[p + 3] << 8) | h[p + 4];
                    if (p + 5 + nameLen <= extEnd) sni = Encoding.ASCII.GetString(h, p + 5, nameLen);
                }
                else if (type == 43 && len >= 3)
                {
                    for (int i = p + 1; i + 1 < p + len; i += 2)
                        if (h[i] == 0x03 && h[i + 1] == 0x04) version = "TLS 1.3";
                }
                p += len;
            }
            return (sni, version);
        }
        catch (IndexOutOfRangeException)
        {
            return (null, version);
        }
    }

    static string VersionName(int v) => v switch
    {
        0x0300 => "SSL 3.0",
        0x0301 => "TLS 1.0",
        0x0302 => "TLS 1.1",
        0x0303 => "TLS 1.2",
        0x0304 => "TLS 1.3",
        _ => $"0x{v:X4}",
    };
}
