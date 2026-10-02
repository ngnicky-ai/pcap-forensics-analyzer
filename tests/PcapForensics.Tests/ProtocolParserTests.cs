using System.IO.Compression;
using PcapForensics.Core.Protocols;

namespace PcapForensics.Tests;

public class DnsParserTests
{
    [Fact]
    public void ParsesResponseWithCompressionPointer()
    {
        var msg = new List<byte> { 0x12, 0x34, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0 };
        msg.AddRange(new byte[] { 7 }.Concat(Bytes.Ascii("example")).Concat(new byte[] { 3 }).Concat(Bytes.Ascii("com")).Concat(new byte[] { 0 }));
        msg.AddRange(new byte[] { 0, 1, 0, 1 });
        msg.AddRange(new byte[] { 0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0x0E, 0x10, 0, 4, 93, 184, 216, 34 });

        var m = DnsParser.TryParse(msg.ToArray());

        Assert.NotNull(m);
        Assert.True(m!.IsResponse);
        Assert.Equal(0x1234, m.Id);
        Assert.Equal("example.com", m.QueryName);
        Assert.Equal("A", m.QueryType);
        var a = Assert.Single(m.Answers);
        Assert.Equal("example.com", a.Name);
        Assert.Equal("93.184.216.34", a.Data);
        Assert.Equal(3600u, a.Ttl);
    }

    [Fact]
    public void PointerLoop_ReturnsNull()
    {
        var msg = new byte[] { 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xC0, 0x0C, 0, 1, 0, 1 };
        Assert.Null(DnsParser.TryParse(msg));
    }
}

public class HttpParserTests
{
    static readonly DateTime T = new(2020, 1, 1, 0, 0, 0, DateTimeKind.Utc);

    static byte[] Gzip(string s)
    {
        using var ms = new MemoryStream();
        using (var gz = new GZipStream(ms, CompressionLevel.Optimal, leaveOpen: true)) gz.Write(Encoding.UTF8.GetBytes(s));
        return ms.ToArray();
    }

    [Fact]
    public void ParsesChunkedGzip_HeadWithoutBody_And100Continue()
    {
        var gz = Gzip("hello world");
        var server = new List<byte>();
        server.AddRange(Bytes.Ascii("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Encoding: gzip\r\nContent-Type: text/plain\r\n\r\n"));
        int half = gz.Length / 2;
        server.AddRange(Bytes.Ascii($"{half:x}\r\n")); server.AddRange(gz[..half]); server.AddRange(Bytes.Ascii("\r\n"));
        server.AddRange(Bytes.Ascii($"{gz.Length - half:x}\r\n")); server.AddRange(gz[half..]); server.AddRange(Bytes.Ascii("\r\n0\r\n\r\n"));
        server.AddRange(Bytes.Ascii("HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n"));        // HEAD: 본문 없음
        server.AddRange(Bytes.Ascii("HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 302 Found\r\nContent-Length: 0\r\n\r\n"));

        var session = new NetworkSession
        {
            Id = 7, Transport = TransportProtocol.Tcp, ClientIp = "10.0.0.1", ClientPort = 5000, ServerIp = "10.0.0.2", ServerPort = 80,
            ClientData = Streams.Of(
                (T, "GET /a HTTP/1.1\r\nHost: x.test\r\n\r\n"),
                (T.AddSeconds(1), "HEAD /b HTTP/1.1\r\nHost: x.test\r\n\r\n"),
                (T.AddSeconds(2), "POST /login HTTP/1.1\r\nHost: x.test\r\nContent-Length: 3\r\n\r\nabc")),
            ServerData = Streams.Of(server.ToArray()),
        };

        var txs = HttpParser.Parse(session);

        Assert.Equal(3, txs.Count);
        Assert.Equal("hello world", Encoding.UTF8.GetString(txs[0].ResponseBody));
        Assert.Equal("http://x.test/a", txs[0].Url);
        Assert.Equal("HEAD", txs[1].Method);
        Assert.Empty(txs[1].ResponseBody);
        Assert.Equal(302, txs[2].StatusCode);
        Assert.Equal("abc", Encoding.ASCII.GetString(txs[2].RequestBody));
        Assert.Equal(T.AddSeconds(2), txs[2].Time);
    }

    [Fact]
    public void BasicAuthAndFormLogin_AreExtracted()
    {
        var basic = new HttpTransaction
        {
            Method = "GET", Uri = "/manager", StatusCode = 401, ServerIp = "10.0.0.2", ServerPort = 8080,
            RequestHeaders = { new("Authorization", "Basic " + Convert.ToBase64String(Bytes.Ascii("tomcat:s3cret"))) },
        };
        var form = new HttpTransaction
        {
            Method = "POST", Uri = "/login.php", StatusCode = 302,
            RequestHeaders = { new("Content-Type", "application/x-www-form-urlencoded") },
            RequestBody = Bytes.Ascii("username=alice&password=P%40ss&submit=1"),
        };
        var creds = new List<CredentialRecord>();

        CleartextAuthParser.ParseHttp(basic, creds);
        CleartextAuthParser.ParseHttp(form, creds);

        Assert.Equal(2, creds.Count);
        Assert.Equal(("tomcat", "s3cret", AuthResult.Failure), (creds[0].Username, creds[0].Password, creds[0].Result));
        Assert.Equal(("alice", "P@ss"), (creds[1].Username, creds[1].Password));
    }
}

public class CleartextAuthTests
{
    static readonly DateTime T = new(2020, 1, 1, 0, 0, 0, DateTimeKind.Utc);

    static NetworkSession Session(string app, int port, ReassembledStream client, ReassembledStream server) => new()
    {
        Id = 1, Transport = TransportProtocol.Tcp, ClientIp = "10.0.0.1", ClientPort = 4000, ServerIp = "10.0.0.2", ServerPort = port,
        AppProtocol = app, ClientData = client, ServerData = server,
    };

    [Fact]
    public void Ftp_PairsRepliesAndInfersUserFrom331()
    {
        // 캡처가 USER 이후부터 시작된 세션 + 같은 세션에서 재시도 후 성공
        var s = Session("FTP", 21,
            Streams.Of((T.AddSeconds(2), "PASS wrong\r\n"), (T.AddSeconds(4), "PASS right\r\n"), (T.AddSeconds(6), "RETR secret.txt\r\n")),
            Streams.Of((T.AddSeconds(1), "331 Password required for admin.\r\n"), (T.AddSeconds(3), "530 Login incorrect.\r\n"),
                       (T.AddSeconds(5), "230 User logged in.\r\n"), (T.AddSeconds(7), "550 Not found.\r\n")));
        var creds = new List<CredentialRecord>();
        var cmds = new List<FtpCommandRecord>();

        CleartextAuthParser.Parse(s, creds, cmds);

        Assert.Equal(2, creds.Count);
        Assert.All(creds, c => Assert.Equal("admin", c.Username));
        Assert.Equal(AuthResult.Failure, creds[0].Result);
        Assert.Equal(AuthResult.Success, creds[1].Result);
        var retr = Assert.Single(cmds);
        Assert.Equal(("RETR", "secret.txt", 550), (retr.Command, retr.Argument, retr.ReplyCode));
    }

    [Fact]
    public void SmtpAuthLogin_DecodesBase64()
    {
        var s = Session("SMTP", 25,
            Streams.Of((T.AddSeconds(1), "AUTH LOGIN\r\n"), (T.AddSeconds(2), Convert.ToBase64String(Bytes.Ascii("bob")) + "\r\n"),
                       (T.AddSeconds(3), Convert.ToBase64String(Bytes.Ascii("hunter2")) + "\r\n")),
            Streams.Of((T, "220 mail ESMTP\r\n"), (T.AddSeconds(4), "235 Authentication successful\r\n")));
        var creds = new List<CredentialRecord>();

        CleartextAuthParser.Parse(s, creds, new List<FtpCommandRecord>());

        var c = Assert.Single(creds);
        Assert.Equal(("bob", "hunter2", AuthResult.Success), (c.Username, c.Password, c.Result));
    }
}
