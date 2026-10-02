using System.Net;
using System.Text.RegularExpressions;

namespace PcapForensics.Core.Detection;

/// <summary>
/// 서버로의 스크립트/웹 애플리케이션 업로드(PUT, multipart, Tomcat Manager 배포)를 찾고,
/// 이후 같은 클라이언트가 업로드된 경로에 접근했는지 연결해 웹셸 설치·사용을 탐지한다.
/// </summary>
public sealed class WebShellDetector : IDetector
{
    public string Name => "웹셸";

    static readonly string[] ScriptExtensions =
        { ".war", ".jsp", ".jspx", ".php", ".php5", ".phtml", ".asp", ".aspx", ".ashx", ".asmx", ".cer", ".cgi", ".pl", ".py", ".sh" };

    static readonly string[] DeployPaths = { "/manager/html/upload", "/manager/text/deploy", "/manager/deploy" };

    static readonly Regex MultipartFileName = new(@"filename=""([^""]+)""", RegexOptions.IgnoreCase);

    public IEnumerable<Finding> Detect(DetectionContext ctx)
    {
        var http = ctx.Result.Http;
        foreach (var up in http.Where(h => h.Method is "POST" or "PUT"))
        {
            var (files, how) = UploadedFiles(up);
            if (files.Count == 0) continue;

            // 업로드된 리소스에 접근하는 경로: WAR 는 /이름/ 컨텍스트, 그 외는 파일명
            var markers = files.Select(f => f.EndsWith(".war", StringComparison.OrdinalIgnoreCase)
                ? "/" + Path.GetFileNameWithoutExtension(f) + "/"
                : Path.GetFileName(f)).ToList();

            var usage = http.Where(h => h.Time > up.Time && h.ServerIp == up.ServerIp && h.ServerPort == up.ServerPort
                                        && markers.Any(m => PathOf(h.Uri).Contains(m, StringComparison.OrdinalIgnoreCase)))
                .OrderBy(h => h.Time).ToList();

            var f = new Finding
            {
                Severity = usage.Count > 0 ? Severity.Critical : Severity.High,
                Category = "웹셸",
                Title = usage.Count > 0
                    ? $"웹셸 업로드 후 사용: {up.ClientIp} → {up.ServerIp}:{up.ServerPort} ({string.Join(", ", files)})"
                    : $"서버 스크립트 업로드(웹셸 설치 의심): {up.ClientIp} → {up.ServerIp}:{up.ServerPort} ({string.Join(", ", files)})",
                Description = $"{up.ClientIp}이(가) {how}로 실행 가능한 서버 측 파일({string.Join(", ", files)})을 업로드했습니다 (응답 {up.StatusText})." +
                              (usage.Count > 0
                                  ? $" 이후 업로드된 경로에 {usage.Count}회 접근(POST {usage.Count(h => h.Method == "POST")}회)해 원격 명령을 실행한 것으로 보입니다. 서버가 장악되었을 가능성이 매우 높습니다."
                                  : " 업로드된 파일이 웹셸이라면 원격 명령 실행에 사용될 수 있습니다."),
                SourceIp = up.ClientIp,
                TargetIp = up.ServerIp,
                FirstSeen = up.Time,
                LastSeen = usage.Count > 0 ? usage[^1].Time : up.Time,
                Count = 1 + usage.Count,
                Mitre = "T1505.003 Server Software Component: Web Shell / T1190 Exploit Public-Facing Application",
                Recommendation = "서버를 네트워크에서 격리하고 업로드된 파일과 배포된 애플리케이션을 보존·삭제하십시오. 웹 서버 계정으로 실행된 프로세스, 추가 생성 파일, 관리 계정(기본 비밀번호 여부)을 점검하십시오.",
                SessionIds = usage.Select(h => h.SessionId).Prepend(up.SessionId).Distinct().ToList(),
            };
            f.Evidence.Add($"[{TimeFormat.Format(up.Time)}] 업로드: {up.Method} {TextUtil.Truncate(up.Url, 200)} → {up.StatusText} (본문 {TimeFormat.Bytes(up.RequestBody.Length)})");
            var auth = up.RequestHeader("Authorization");
            if (auth is not null && auth.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase))
                f.Evidence.Add($"업로드에 사용된 계정: {TextUtil.Base64DecodeText(auth[6..])}");
            foreach (var h in usage.Take(15))
            {
                string param = h.Method == "POST" && h.RequestBody.Length > 0
                    ? "  본문: " + TextUtil.Truncate(WebUtility.UrlDecode(Encoding.UTF8.GetString(h.RequestBody)).Replace('\n', ' ').Replace('\r', ' '), 160)
                    : "";
                f.Evidence.Add($"[{TimeFormat.Format(h.Time)}] {h.Method} {TextUtil.Truncate(h.Uri, 120)} → {h.StatusText}{param}");
            }
            yield return f;
        }
    }

    static (List<string> Files, string How) UploadedFiles(HttpTransaction h)
    {
        var path = PathOf(h.Uri);
        var files = new List<string>();

        if (h.Method == "PUT" && HasScriptExt(path))
            return (new() { Path.GetFileName(path) }, "HTTP PUT");

        if (h.RequestBody.Length > 0)
        {
            var ct = h.RequestHeader("Content-Type") ?? "";
            if (ct.Contains("multipart/form-data", StringComparison.OrdinalIgnoreCase))
            {
                var head = TextUtil.Latin1.GetString(h.RequestBody, 0, Math.Min(h.RequestBody.Length, 1 << 20));
                files.AddRange(MultipartFileName.Matches(head).Select(m => Path.GetFileName(m.Groups[1].Value.Replace('\\', '/'))).Where(HasScriptExt));
            }
        }

        bool deploy = DeployPaths.Any(p => path.StartsWith(p, StringComparison.OrdinalIgnoreCase));
        if (deploy && files.Count == 0)
        {
            var war = Regex.Match(h.Uri, @"[?&]war=([^&]+)", RegexOptions.IgnoreCase);
            var p = Regex.Match(h.Uri, @"[?&]path=([^&]+)", RegexOptions.IgnoreCase);
            files.Add(war.Success ? Path.GetFileName(WebUtility.UrlDecode(war.Groups[1].Value))
                : p.Success ? WebUtility.UrlDecode(p.Groups[1].Value).Trim('/') + ".war" : "(WAR)");
        }
        return (files.Distinct().ToList(), deploy ? "Tomcat Manager 애플리케이션 배포" : "파일 업로드(multipart)");
    }

    static bool HasScriptExt(string name) =>
        ScriptExtensions.Contains(Path.GetExtension(name).ToLowerInvariant());

    static string PathOf(string uri)
    {
        int q = uri.IndexOf('?');
        return q >= 0 ? uri[..q] : uri;
    }
}
