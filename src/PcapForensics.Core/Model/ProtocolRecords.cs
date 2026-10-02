namespace PcapForensics.Core.Model;

public sealed class HttpTransaction
{
    public int Id { get; set; }
    public int SessionId { get; init; }
    public DateTime Time { get; set; }
    public DateTime? ResponseTime { get; set; }
    public string ClientIp { get; init; } = "";
    public int ClientPort { get; init; }
    public string ServerIp { get; init; } = "";
    public int ServerPort { get; init; }

    public string Method { get; set; } = "";
    public string Uri { get; set; } = "";
    public string Version { get; set; } = "";
    public string RequestLine { get; set; } = "";
    public List<KeyValuePair<string, string>> RequestHeaders { get; set; } = new();
    public byte[] RequestBody { get; set; } = Array.Empty<byte>();

    public int? StatusCode { get; set; }
    public string StatusLine { get; set; } = "";
    public List<KeyValuePair<string, string>> ResponseHeaders { get; set; } = new();
    /// <summary>전송 인코딩/압축을 해제한 응답 본문.</summary>
    public byte[] ResponseBody { get; set; } = Array.Empty<byte>();

    public string Host => RequestHeader("Host") ?? "";
    public string UserAgent => RequestHeader("User-Agent") ?? "";
    public string Referer => RequestHeader("Referer") ?? "";
    public string ContentType => ResponseHeader("Content-Type") ?? "";
    public string StatusText => StatusCode?.ToString() ?? "-";
    public int ResponseLength => ResponseBody.Length;
    public string ResponseLengthText => TimeFormat.Bytes(ResponseBody.Length);
    public string TimeText => TimeFormat.Format(Time);

    public string Url
    {
        get
        {
            string host = Host.Length > 0 ? Host : ServerIp;
            string port = ServerPort != 80 && !host.Contains(':') ? ":" + ServerPort : "";
            return Method == "CONNECT" ? Uri : $"http://{host}{port}{Uri}";
        }
    }

    public string? RequestHeader(string name) => Find(RequestHeaders, name);
    public string? ResponseHeader(string name) => Find(ResponseHeaders, name);

    static string? Find(List<KeyValuePair<string, string>> headers, string name)
    {
        foreach (var h in headers)
            if (h.Key.Equals(name, StringComparison.OrdinalIgnoreCase)) return h.Value;
        return null;
    }
}

public sealed record DnsAnswer(string Name, string Type, string Data, uint Ttl);

public sealed class DnsTransaction
{
    public int Id { get; set; }
    public DateTime Time { get; set; }
    public DateTime? ResponseTime { get; set; }
    public string ClientIp { get; set; } = "";
    public int ClientPort { get; set; }
    public string ServerIp { get; set; } = "";
    public int TransactionId { get; set; }
    public string QueryName { get; set; } = "";
    public string QueryType { get; set; } = "";
    public int? RCode { get; set; }
    public List<DnsAnswer> Answers { get; set; } = new();
    public string Transport { get; set; } = "UDP";

    public string TimeText => TimeFormat.Format(Time);
    public string RCodeText => RCode switch
    {
        null => "응답 없음",
        0 => "NOERROR",
        1 => "FORMERR",
        2 => "SERVFAIL",
        3 => "NXDOMAIN",
        4 => "NOTIMP",
        5 => "REFUSED",
        var c => $"RCODE {c}",
    };

    public string AnswersText => string.Join(", ", Answers.Select(a =>
        a.Type is "A" or "AAAA" ? a.Data : $"{a.Type} {a.Data}"));
}

public sealed class TlsHandshakeInfo
{
    public DateTime Time { get; init; }
    public int SessionId { get; init; }
    public string ClientIp { get; init; } = "";
    public int ClientPort { get; init; }
    public string ServerIp { get; init; } = "";
    public int ServerPort { get; init; }
    public string Sni { get; init; } = "";
    public string Version { get; init; } = "";
    public string TimeText => TimeFormat.Format(Time);
}

public sealed class CredentialRecord
{
    public DateTime Time { get; init; }
    public string Protocol { get; init; } = "";
    public string ClientIp { get; init; } = "";
    public string ServerIp { get; init; } = "";
    public int ServerPort { get; init; }
    public string Username { get; init; } = "";
    public string Password { get; init; } = "";
    public AuthResult Result { get; set; }
    public int SessionId { get; init; }
    public string Detail { get; init; } = "";

    public string ResultText => Result.ToKorean();
    public string TimeText => TimeFormat.Format(Time);
}

/// <summary>FTP 제어 채널 명령과, 연결된 데이터 채널 정보.</summary>
public sealed class FtpCommandRecord
{
    public DateTime Time { get; init; }
    public int SessionId { get; init; }
    public string ClientIp { get; init; } = "";
    public string ServerIp { get; init; } = "";
    public string Command { get; init; } = "";
    public string Argument { get; init; } = "";
    public int? ReplyCode { get; set; }
    public string DataIp { get; set; } = "";
    public int DataPort { get; set; }
    public bool Passive { get; set; }
    public int? DataSessionId { get; set; }
    public long DataBytes { get; set; }
    public string TimeText => TimeFormat.Format(Time);
}
