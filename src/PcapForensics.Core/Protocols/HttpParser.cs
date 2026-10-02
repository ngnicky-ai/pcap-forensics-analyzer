using System.Globalization;
using System.IO.Compression;

namespace PcapForensics.Core.Protocols;

/// <summary>재조립된 TCP 스트림에서 HTTP/1.x 요청·응답을 파싱한다(chunked, gzip/deflate/br 지원).</summary>
public static class HttpParser
{
    static readonly string[] Methods =
        { "GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS ", "CONNECT ", "PATCH ", "TRACE ", "PROPFIND " };

    const int MaxHeaderBytes = 128 * 1024;
    const int MaxDecodedBytes = 64 * 1024 * 1024;

    public static bool LooksLikeRequest(byte[] d, int pos)
    {
        foreach (var m in Methods)
            if (ByteUtil.StartsWithAscii(d, pos, m)) return true;
        return false;
    }

    sealed class Message
    {
        public int Offset;
        public DateTime? Time;
        public string StartLine = "";
        public List<KeyValuePair<string, string>> Headers = new();
        public int BodyStart;
        public byte[] Body = Array.Empty<byte>();

        public string? Header(string name)
        {
            foreach (var h in Headers)
                if (h.Key.Equals(name, StringComparison.OrdinalIgnoreCase)) return h.Value;
            return null;
        }
    }

    public static List<HttpTransaction> Parse(NetworkSession s)
    {
        var result = new List<HttpTransaction>();
        var requests = ParseRequests(s.ClientData);
        var d = s.ServerData.Data;
        int pos = 0, ri = 0, guard = 0;

        while (pos < d.Length && guard++ < 20000)
        {
            if (!ByteUtil.StartsWithAscii(d, pos, "HTTP/1."))
            {
                int next = FindNext(d, pos + 1, isResponse: true);
                if (next < 0) break;
                pos = next;
            }
            var resp = ParseHead(d, pos);
            if (resp is null) break;
            resp.Time = s.ServerData.TimeAt(pos);

            int status = ParseStatus(resp.StartLine);
            var req = ri < requests.Count ? requests[ri] : null;
            string method = req is null ? "" : FirstToken(req.StartLine);
            bool noBody = method == "HEAD" || status is >= 100 and < 200 or 204 or 304;
            resp.Body = ReadBody(d, resp, isResponse: true, noBody, out int end);
            pos = Math.Max(end, resp.BodyStart);

            if (status is >= 100 and < 200) continue; // 100 Continue 등 중간 응답

            result.Add(Build(s, req, resp, status));
            ri++;
            if (method == "CONNECT" && status == 200) break; // 이후는 터널 데이터
            if (end >= d.Length) break;
        }

        // 응답이 없는 나머지 요청
        for (; ri < requests.Count; ri++)
        {
            if (FirstToken(requests[ri].StartLine) == "CONNECT" && result.Any(r => r.Method == "CONNECT" && r.StatusCode == 200)) break;
            result.Add(Build(s, requests[ri], null, null));
        }
        return result;
    }

    static List<Message> ParseRequests(ReassembledStream st)
    {
        var list = new List<Message>();
        var d = st.Data;
        int pos = 0, guard = 0;
        while (pos < d.Length && guard++ < 20000)
        {
            if (!LooksLikeRequest(d, pos))
            {
                int next = FindNext(d, pos + 1, isResponse: false);
                if (next < 0) break;
                pos = next;
            }
            var msg = ParseHead(d, pos);
            if (msg is null) break;
            msg.Time = st.TimeAt(pos);
            msg.Body = ReadBody(d, msg, isResponse: false, noBody: false, out int end);
            list.Add(msg);
            pos = Math.Max(end, msg.BodyStart);
            if (FirstToken(msg.StartLine) == "CONNECT") break;
        }
        return list;
    }

    static int FindNext(byte[] d, int start, bool isResponse)
    {
        for (int i = Math.Max(start, 1); i < d.Length; i++)
        {
            if (d[i - 1] != (byte)'\n') continue;
            if (isResponse ? ByteUtil.StartsWithAscii(d, i, "HTTP/1.") : LooksLikeRequest(d, i)) return i;
        }
        return -1;
    }

    static Message? ParseHead(byte[] d, int pos)
    {
        int end = ByteUtil.IndexOf(d, "\r\n\r\n"u8, pos, MaxHeaderBytes);
        int sep = 4;
        if (end < 0)
        {
            end = ByteUtil.IndexOf(d, "\n\n"u8, pos, MaxHeaderBytes);
            sep = 2;
        }
        if (end < 0)
        {
            if (d.Length - pos > MaxHeaderBytes) return null;
            end = d.Length; // 헤더가 잘린 채 캡처 종료
            sep = 0;
        }

        var text = TextUtil.Latin1.GetString(d, pos, end - pos);
        var lines = text.Split('\n');
        var msg = new Message { Offset = pos, StartLine = lines[0].TrimEnd('\r'), BodyStart = Math.Min(d.Length, end + sep) };
        for (int i = 1; i < lines.Length; i++)
        {
            var line = lines[i].TrimEnd('\r');
            int colon = line.IndexOf(':');
            if (colon > 0) msg.Headers.Add(new(line[..colon].Trim(), line[(colon + 1)..].Trim()));
        }
        return msg;
    }

    static byte[] ReadBody(byte[] d, Message m, bool isResponse, bool noBody, out int end)
    {
        int start = m.BodyStart;
        end = start;
        if (noBody) return Array.Empty<byte>();

        byte[] raw;
        var te = m.Header("Transfer-Encoding");
        var cl = m.Header("Content-Length");
        if (te is not null && te.Contains("chunked", StringComparison.OrdinalIgnoreCase))
            raw = DecodeChunked(d, start, out end);
        else if (cl is not null && long.TryParse(cl.Trim(), out long n) && n >= 0)
        {
            int take = (int)Math.Min(n, d.Length - start);
            end = start + take;
            raw = d.AsSpan(start, take).ToArray();
        }
        else if (isResponse)
        {
            end = d.Length;
            raw = d.AsSpan(start).ToArray();
        }
        else return Array.Empty<byte>();

        return Decompress(raw, m.Header("Content-Encoding"));
    }

    static byte[] DecodeChunked(byte[] d, int pos, out int end)
    {
        using var ms = new MemoryStream();
        while (pos < d.Length)
        {
            int lineEnd = ByteUtil.IndexOf(d, "\r\n"u8, pos, 1024);
            if (lineEnd < 0) break;
            var sizeText = Encoding.ASCII.GetString(d, pos, lineEnd - pos);
            int semi = sizeText.IndexOf(';');
            if (semi >= 0) sizeText = sizeText[..semi];
            if (!int.TryParse(sizeText.Trim(), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out int size) || size < 0) break;
            pos = lineEnd + 2;

            if (size == 0)
            {
                // trailer 헤더를 빈 줄까지 건너뜀
                while (true)
                {
                    int t = ByteUtil.IndexOf(d, "\r\n"u8, pos, 8192);
                    if (t < 0) break;
                    bool blank = t == pos;
                    pos = t + 2;
                    if (blank) break;
                }
                end = Math.Min(pos, d.Length);
                return ms.ToArray();
            }

            int take = Math.Min(size, d.Length - pos);
            ms.Write(d, pos, take);
            pos += take;
            if (pos + 2 <= d.Length && d[pos] == '\r' && d[pos + 1] == '\n') pos += 2;
        }
        end = Math.Min(pos, d.Length);
        return ms.ToArray();
    }

    static byte[] Decompress(byte[] body, string? encoding)
    {
        if (body.Length == 0 || string.IsNullOrWhiteSpace(encoding)) return body;
        encoding = encoding.Trim().ToLowerInvariant();
        Stream? z;
        try
        {
            z = encoding switch
            {
                "gzip" or "x-gzip" => new GZipStream(new MemoryStream(body), CompressionMode.Decompress),
                "deflate" when body.Length > 1 && (body[0] & 0x0F) == 8 && ((body[0] << 8) | body[1]) % 31 == 0
                    => new ZLibStream(new MemoryStream(body), CompressionMode.Decompress),
                "deflate" => new DeflateStream(new MemoryStream(body), CompressionMode.Decompress),
                "br" => new BrotliStream(new MemoryStream(body), CompressionMode.Decompress),
                _ => null,
            };
        }
        catch (Exception) { return body; }
        if (z is null) return body;

        using (z)
        {
            using var output = new MemoryStream();
            var buf = new byte[81920];
            try
            {
                int n;
                while ((n = z.Read(buf, 0, buf.Length)) > 0)
                {
                    output.Write(buf, 0, n);
                    if (output.Length > MaxDecodedBytes) break;
                }
            }
            catch (Exception) when (output.Length > 0)
            {
                // 캡처가 잘린 압축 스트림: 복원된 부분까지만 사용
            }
            catch (Exception)
            {
                return body;
            }
            return output.ToArray();
        }
    }

    static HttpTransaction Build(NetworkSession s, Message? req, Message? resp, int? status)
    {
        var t = new HttpTransaction
        {
            SessionId = s.Id,
            ClientIp = s.ClientIp,
            ClientPort = s.ClientPort,
            ServerIp = s.ServerIp,
            ServerPort = s.ServerPort,
        };
        if (req is not null)
        {
            var parts = req.StartLine.Split(' ', 3);
            t.Method = parts[0];
            t.Uri = parts.Length > 1 ? parts[1] : "";
            t.Version = parts.Length > 2 ? parts[2] : "";
            t.RequestLine = req.StartLine;
            t.RequestHeaders = req.Headers;
            t.RequestBody = req.Body;
            t.Time = req.Time ?? s.Start;
        }
        else
        {
            t.Method = "(응답만)";
            t.Time = resp?.Time ?? s.Start;
        }
        if (resp is not null)
        {
            t.StatusCode = status;
            t.StatusLine = resp.StartLine;
            t.ResponseHeaders = resp.Headers;
            t.ResponseBody = resp.Body;
            t.ResponseTime = resp.Time;
        }
        return t;
    }

    static int ParseStatus(string line)
    {
        var parts = line.Split(' ', 3);
        return parts.Length > 1 && int.TryParse(parts[1], out int code) ? code : 0;
    }

    static string FirstToken(string line)
    {
        int sp = line.IndexOf(' ');
        return sp < 0 ? line : line[..sp];
    }
}
