using System.Text.RegularExpressions;
using System.Web;

namespace PcapForensics.Core.Protocols;

/// <summary>
/// 평문 프로토콜(FTP/POP3/IMAP/SMTP/HTTP)에서 인증 정보와 성공/실패 여부, FTP 명령을 추출한다.
/// 클라이언트/서버 줄을 도착 시각순으로 병합해 요청-응답을 짝짓는다.
/// </summary>
public static class CleartextAuthParser
{
    readonly record struct Line(DateTime Time, bool FromClient, string Text);

    static readonly HashSet<string> FtpRecordedCommands = new(StringComparer.OrdinalIgnoreCase)
    {
        "RETR", "STOR", "STOU", "APPE", "LIST", "NLST", "MLSD", "DELE", "MKD", "RMD", "CWD", "RNFR", "RNTO", "SITE",
    };

    static readonly HashSet<string> FtpDataCommands = new(StringComparer.OrdinalIgnoreCase)
    {
        "RETR", "STOR", "STOU", "APPE", "LIST", "NLST", "MLSD",
    };

    public static void Parse(NetworkSession s, List<CredentialRecord> creds, List<FtpCommandRecord> ftp)
    {
        switch (s.AppProtocol)
        {
            case "FTP": ParseFtp(s, creds, ftp); break;
            case "POP3": ParsePop3(s, creds); break;
            case "IMAP": ParseImap(s, creds); break;
            case "SMTP": ParseSmtp(s, creds); break;
        }
    }

    static List<Line> MergeLines(NetworkSession s)
    {
        var lines = new List<Line>();
        Split(s.ClientData, true, s.Start, lines);
        Split(s.ServerData, false, s.Start, lines);
        return lines.OrderBy(l => l.Time).ToList(); // 안정 정렬: 같은 시각이면 원래 순서 유지
    }

    static void Split(ReassembledStream st, bool fromClient, DateTime fallback, List<Line> output)
    {
        var d = st.Data;
        int len = Math.Min(d.Length, 4 * 1024 * 1024);
        int start = 0;
        for (int i = 0; i <= len; i++)
        {
            if (i < len && d[i] != (byte)'\n') continue;
            int e = i;
            if (e > start && d[e - 1] == (byte)'\r') e--;
            if (e > start)
                output.Add(new Line(st.TimeAt(start) ?? fallback, fromClient, Encoding.UTF8.GetString(d, start, e - start)));
            start = i + 1;
        }
    }

    static (string Cmd, string Arg) SplitCommand(string line)
    {
        int sp = line.IndexOf(' ');
        return sp < 0 ? (line.Trim().ToUpperInvariant(), "") : (line[..sp].ToUpperInvariant(), line[(sp + 1)..].Trim());
    }

    static int ReplyCode(string line, out bool final)
    {
        final = line.Length == 3 || (line.Length > 3 && line[3] == ' ');
        return line.Length >= 3 && int.TryParse(line.AsSpan(0, 3), out int code) ? code : 0;
    }

    static void ParseFtp(NetworkSession s, List<CredentialRecord> creds, List<FtpCommandRecord> ftp)
    {
        string? user = null;
        CredentialRecord? pending = null;
        FtpCommandRecord? last = null;
        (string Ip, int Port, bool Passive)? dataEp = null;

        foreach (var l in MergeLines(s))
        {
            if (l.FromClient)
            {
                var (cmd, arg) = SplitCommand(l.Text);
                switch (cmd)
                {
                    case "USER":
                        user = arg;
                        break;
                    case "PASS":
                        pending = NewCred(s, "FTP", l.Time, user ?? "", arg);
                        creds.Add(pending);
                        break;
                    case "PORT":
                        var parts = arg.Split(',');
                        if (parts.Length == 6 && parts.All(x => int.TryParse(x, out _)))
                            dataEp = ($"{parts[0]}.{parts[1]}.{parts[2]}.{parts[3]}", int.Parse(parts[4]) * 256 + int.Parse(parts[5]), false);
                        break;
                    case "EPRT":
                        var ep = arg.Split(arg.Length > 0 ? arg[0] : '|', StringSplitOptions.RemoveEmptyEntries);
                        if (ep.Length >= 3 && int.TryParse(ep[2], out int eport)) dataEp = (ep[1], eport, false);
                        break;
                    default:
                        if (FtpRecordedCommands.Contains(cmd))
                        {
                            last = new FtpCommandRecord
                            {
                                Time = l.Time, SessionId = s.Id, ClientIp = s.ClientIp, ServerIp = s.ServerIp,
                                Command = cmd, Argument = arg,
                            };
                            if (FtpDataCommands.Contains(cmd) && dataEp is { } d)
                            {
                                last.DataIp = d.Ip;
                                last.DataPort = d.Port;
                                last.Passive = d.Passive;
                                dataEp = null;
                            }
                            ftp.Add(last);
                        }
                        break;
                }
            }
            else
            {
                int code = ReplyCode(l.Text, out bool final);
                if (code == 0 || !final) continue;

                if (pending is not null && code is 230 or 202) { pending.Result = AuthResult.Success; pending = null; }
                else if (pending is not null && code is 530 or 430) { pending.Result = AuthResult.Failure; pending = null; }

                if (code == 331 && user is null)
                {
                    // USER 명령이 캡처되지 않은 경우 "331 Password required for admin." 에서 계정 추론
                    var m = Regex.Match(l.Text, @"for\s+(\S+?)\.?\s*$", RegexOptions.IgnoreCase);
                    if (m.Success) user = m.Groups[1].Value;
                }
                else if (code == 227)
                {
                    var m = Regex.Match(l.Text, @"(\d+),(\d+),(\d+),(\d+),(\d+),(\d+)");
                    if (m.Success)
                        dataEp = ($"{m.Groups[1]}.{m.Groups[2]}.{m.Groups[3]}.{m.Groups[4]}",
                            int.Parse(m.Groups[5].Value) * 256 + int.Parse(m.Groups[6].Value), true);
                }
                else if (code == 229)
                {
                    var m = Regex.Match(l.Text, @"\(\|\|\|(\d+)\|\)");
                    if (m.Success) dataEp = (s.ServerIp, int.Parse(m.Groups[1].Value), true);
                }
                else if (code >= 200 && last is not null && last.ReplyCode is null)
                {
                    last.ReplyCode = code;
                }
            }
        }
    }

    static void ParsePop3(NetworkSession s, List<CredentialRecord> creds)
    {
        string? user = null;
        CredentialRecord? pending = null;
        foreach (var l in MergeLines(s))
        {
            if (l.FromClient)
            {
                var (cmd, arg) = SplitCommand(l.Text);
                if (cmd == "USER") user = arg;
                else if (cmd == "PASS")
                {
                    pending = NewCred(s, "POP3", l.Time, user ?? "", arg);
                    creds.Add(pending);
                }
            }
            else if (pending is not null)
            {
                if (l.Text.StartsWith("+OK")) { pending.Result = AuthResult.Success; pending = null; }
                else if (l.Text.StartsWith("-ERR")) { pending.Result = AuthResult.Failure; pending = null; }
            }
        }
    }

    static readonly Regex ImapLogin = new(@"^(\S+)\s+LOGIN\s+(""(?:[^""\\]|\\.)*""|\S+)\s+(""(?:[^""\\]|\\.)*""|\S+)", RegexOptions.IgnoreCase);

    static void ParseImap(NetworkSession s, List<CredentialRecord> creds)
    {
        string? tag = null;
        CredentialRecord? pending = null;
        foreach (var l in MergeLines(s))
        {
            if (l.FromClient)
            {
                var m = ImapLogin.Match(l.Text);
                if (!m.Success) continue;
                tag = m.Groups[1].Value;
                pending = NewCred(s, "IMAP", l.Time, Unquote(m.Groups[2].Value), Unquote(m.Groups[3].Value));
                creds.Add(pending);
            }
            else if (pending is not null && tag is not null && l.Text.StartsWith(tag + " ", StringComparison.Ordinal))
            {
                var status = l.Text[(tag.Length + 1)..];
                pending.Result = status.StartsWith("OK", StringComparison.OrdinalIgnoreCase) ? AuthResult.Success : AuthResult.Failure;
                pending = null;
            }
        }
    }

    static void ParseSmtp(NetworkSession s, List<CredentialRecord> creds)
    {
        string state = "";
        string? user = null;
        CredentialRecord? pending = null;
        foreach (var l in MergeLines(s))
        {
            if (l.FromClient)
            {
                var text = l.Text.Trim();
                switch (state)
                {
                    case "login-user":
                        user = TextUtil.Base64DecodeText(text);
                        state = "login-pass";
                        continue;
                    case "login-pass":
                        pending = NewCred(s, "SMTP AUTH LOGIN", l.Time, user ?? "", TextUtil.Base64DecodeText(text));
                        creds.Add(pending);
                        state = "";
                        continue;
                    case "plain":
                        pending = AddPlain(s, l.Time, text, creds);
                        state = "";
                        continue;
                }

                var upper = text.ToUpperInvariant();
                if (upper.StartsWith("AUTH PLAIN"))
                {
                    var rest = text.Length > 10 ? text[10..].Trim() : "";
                    if (rest.Length > 0) pending = AddPlain(s, l.Time, rest, creds);
                    else state = "plain";
                }
                else if (upper.StartsWith("AUTH LOGIN"))
                {
                    var rest = text.Length > 10 ? text[10..].Trim() : "";
                    if (rest.Length > 0) { user = TextUtil.Base64DecodeText(rest); state = "login-pass"; }
                    else state = "login-user";
                }
            }
            else if (pending is not null)
            {
                int code = ReplyCode(l.Text, out bool final);
                if (!final) continue;
                if (code == 235) { pending.Result = AuthResult.Success; pending = null; }
                else if (code is 535 or 534 or 454) { pending.Result = AuthResult.Failure; pending = null; }
            }
        }
    }

    static CredentialRecord AddPlain(NetworkSession s, DateTime time, string b64, List<CredentialRecord> creds)
    {
        var parts = TextUtil.Base64DecodeText(b64).Split('\0');
        var cred = NewCred(s, "SMTP AUTH PLAIN", time, parts.Length >= 2 ? parts[^2] : "", parts.Length >= 1 ? parts[^1] : "");
        creds.Add(cred);
        return cred;
    }

    // ----- HTTP -----

    static readonly string[] PasswordKeys = { "pass", "pwd", "passwd", "password", "pw", "pswd", "j_password" };
    static readonly string[] UserKeys = { "user", "username", "userid", "user_id", "uname", "login", "login_id", "email", "mail", "id", "log", "account", "usr", "j_username" };

    public static void ParseHttp(HttpTransaction t, List<CredentialRecord> creds)
    {
        var auth = t.RequestHeader("Authorization");
        if (auth is not null && auth.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase))
        {
            var decoded = TextUtil.Base64DecodeText(auth[6..]);
            int colon = decoded.IndexOf(':');
            creds.Add(new CredentialRecord
            {
                Time = t.Time, Protocol = "HTTP Basic", ClientIp = t.ClientIp, ServerIp = t.ServerIp, ServerPort = t.ServerPort,
                Username = colon >= 0 ? decoded[..colon] : decoded,
                Password = colon >= 0 ? decoded[(colon + 1)..] : "",
                Result = StatusResult(t.StatusCode),
                SessionId = t.SessionId,
                Detail = t.Url,
            });
        }

        // 폼 로그인(본문) 및 쿼리 문자열에 포함된 비밀번호
        var sources = new List<string>();
        var ct = t.RequestHeader("Content-Type") ?? "";
        if (t.RequestBody.Length > 0 && t.RequestBody.Length < 64 * 1024
            && (ct.Contains("x-www-form-urlencoded", StringComparison.OrdinalIgnoreCase) || (ct.Length == 0 && TextUtil.LooksLikeText(t.RequestBody))))
            sources.Add(Encoding.UTF8.GetString(t.RequestBody));
        int q = t.Uri.IndexOf('?');
        if (q >= 0) sources.Add(t.Uri[(q + 1)..]);

        foreach (var src in sources)
        {
            var fields = ParseForm(src);
            var pass = fields.FirstOrDefault(f => IsKey(f.Key, PasswordKeys, partial: true));
            if (pass.Key is null || pass.Value.Length == 0) continue;
            var user = fields.FirstOrDefault(f => IsKey(f.Key, UserKeys, partial: false));
            creds.Add(new CredentialRecord
            {
                Time = t.Time, Protocol = "HTTP Form", ClientIp = t.ClientIp, ServerIp = t.ServerIp, ServerPort = t.ServerPort,
                Username = user.Value ?? "", Password = pass.Value,
                Result = t.StatusCode is 401 or 403 ? AuthResult.Failure : AuthResult.Unknown,
                SessionId = t.SessionId,
                Detail = $"{t.Method} {t.Url}",
            });
            break;
        }
    }

    static bool IsKey(string key, string[] names, bool partial)
    {
        var k = key.ToLowerInvariant();
        int bracket = k.LastIndexOf('[');
        if (bracket >= 0) k = k[(bracket + 1)..].TrimEnd(']'); // login[password] 형태
        return names.Any(n => k == n || (partial && n.Length >= 4 && k.Contains(n)));
    }

    static List<KeyValuePair<string, string>> ParseForm(string s)
    {
        var list = new List<KeyValuePair<string, string>>();
        foreach (var pair in s.Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            int eq = pair.IndexOf('=');
            if (eq <= 0) continue;
            list.Add(new(HttpUtility.UrlDecode(pair[..eq]), HttpUtility.UrlDecode(pair[(eq + 1)..])));
        }
        return list;
    }

    static AuthResult StatusResult(int? status) => status switch
    {
        401 or 403 => AuthResult.Failure,
        >= 200 and < 400 => AuthResult.Success,
        _ => AuthResult.Unknown,
    };

    static CredentialRecord NewCred(NetworkSession s, string protocol, DateTime time, string user, string pass) => new()
    {
        Time = time, Protocol = protocol, ClientIp = s.ClientIp, ServerIp = s.ServerIp, ServerPort = s.ServerPort,
        Username = user, Password = pass, SessionId = s.Id,
    };

    static string Unquote(string s) =>
        s.Length >= 2 && s[0] == '"' && s[^1] == '"' ? s[1..^1].Replace("\\\"", "\"").Replace("\\\\", "\\") : s;
}
