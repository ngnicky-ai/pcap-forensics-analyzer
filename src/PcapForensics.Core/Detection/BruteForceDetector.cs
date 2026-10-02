namespace PcapForensics.Core.Detection;

/// <summary>
/// 무차별 대입 공격 탐지.
/// ① 평문 프로토콜의 인증 실패 반복(성공 시 심각) ② 인증 서비스 포트로의 반복 연결 ③ 웹 로그인 반복 요청
/// </summary>
public sealed class BruteForceDetector : IDetector
{
    public string Name => "무차별 대입";

    static readonly string[] LoginPathHints = { "login", "signin", "logon", "auth", "wp-login", "admin", "session", "account", "j_security_check" };

    public IEnumerable<Finding> Detect(DetectionContext ctx)
    {
        var r = ctx.Result;
        var st = ctx.Settings;
        var handled = new HashSet<(string, string, int)>();

        // ① 인증 실패 반복
        foreach (var g in r.Credentials.GroupBy(c => (c.Protocol, c.ClientIp, c.ServerIp, c.ServerPort)))
        {
            var list = g.OrderBy(c => c.Time).ToList();
            var failures = list.Where(c => c.Result == AuthResult.Failure).ToList();
            if (failures.Count < st.BruteForceMinFailures) continue;
            handled.Add((g.Key.ClientIp, g.Key.ServerIp, g.Key.ServerPort));

            var firstFail = failures[0].Time;
            var successes = list.Where(c => c.Result == AuthResult.Success && c.Time >= firstFail).ToList();
            var users = list.GroupBy(c => c.Username).OrderByDescending(x => x.Count())
                .Select(x => $"{(x.Key.Length > 0 ? x.Key : "(계정 미확인)")}({x.Count()})");
            int distinctPw = list.Select(c => c.Password).Distinct().Count();

            var f = new Finding
            {
                Severity = successes.Count > 0 ? Severity.Critical : Severity.High,
                Category = "계정 공격",
                Title = successes.Count > 0
                    ? $"{g.Key.Protocol} 무차별 대입 공격 성공: {g.Key.ClientIp} → {g.Key.ServerIp}"
                    : $"{g.Key.Protocol} 무차별 대입 공격: {g.Key.ClientIp} → {g.Key.ServerIp}",
                Description = $"{g.Key.ClientIp}이(가) {g.Key.ServerIp}:{g.Key.ServerPort} ({g.Key.Protocol})에 {list.Count}회 로그인을 시도해 {failures.Count}회 실패했습니다." +
                              (successes.Count > 0 ? $" 이후 {successes.Count}건의 로그인이 성공했습니다. 계정이 탈취되었을 가능성이 높습니다." : ""),
                SourceIp = g.Key.ClientIp,
                TargetIp = g.Key.ServerIp,
                FirstSeen = list[0].Time,
                LastSeen = list[^1].Time,
                Count = list.Count,
                Mitre = "T1110 Brute Force",
                Evidence =
                {
                    $"시도한 계정(횟수): {DetectorUtil.JoinLimited(users, 15)}",
                    $"서로 다른 비밀번호 {distinctPw}개 사용",
                    $"시도 빈도: 평균 {(list.Count > 1 ? (list[^1].Time - list[0].Time).TotalSeconds / (list.Count - 1) : 0):F2}초마다 1회",
                },
                SessionIds = list.Select(c => c.SessionId).Distinct().Take(500).ToList(),
                Recommendation = successes.Count > 0
                    ? "성공한 계정의 비밀번호를 즉시 변경하고, 로그인 이후 수행된 명령/파일 전송을 확인하십시오. 출발지 IP 를 차단하십시오."
                    : "출발지 IP 를 차단하고 계정 잠금 정책을 적용하십시오. 평문 프로토콜은 암호화 프로토콜(SFTP/FTPS 등)로 전환하십시오.",
            };
            foreach (var s in successes.Take(10))
                f.Evidence.Add($"로그인 성공: 계정 '{s.Username}' / 비밀번호 '{s.Password}' ({TimeFormat.Format(s.Time)})");
            yield return f;
        }

        // ② 인증 서비스 반복 연결 (SSH/RDP/SMB 등 암호화되어 결과를 볼 수 없는 경우)
        var authPorts = st.AuthServicePorts.ToHashSet();
        var candidates = r.Sessions.Where(s => s.Transport == TransportProtocol.Tcp && authPorts.Contains(s.ServerPort) && s.Established);
        foreach (var g in candidates.GroupBy(s => (s.ClientIp, s.ServerIp, s.ServerPort)))
        {
            if (handled.Contains(g.Key)) continue;
            var list = g.OrderBy(s => s.Start).ToList();
            int max = DetectorUtil.MaxCountInWindow(list, s => s.Start, st.BruteForceWindowSeconds);
            if (max < st.BruteForceMinConnections) continue;

            var service = list[0].AppProtocol;
            var shortLived = list.Count(s => s.DurationSeconds < 10);
            yield return new Finding
            {
                Severity = max >= 100 ? Severity.High : Severity.Medium,
                Category = "계정 공격",
                Title = $"{service} 반복 접속(무차별 대입 의심): {g.Key.ClientIp} → {g.Key.ServerIp}:{g.Key.ServerPort}",
                Description = $"{g.Key.ClientIp}이(가) {g.Key.ServerIp}의 {service}(TCP/{g.Key.ServerPort}) 서비스에 {list.Count}회 연결했습니다 " +
                              $"({st.BruteForceWindowSeconds:F0}초 구간 최대 {max}회). 짧은 연결이 반복되는 것은 자동화된 인증 시도의 전형적인 패턴입니다.",
                SourceIp = g.Key.ClientIp,
                TargetIp = g.Key.ServerIp,
                FirstSeen = list[0].Start,
                LastSeen = list[^1].End,
                Count = list.Count,
                Mitre = "T1110 Brute Force",
                Evidence =
                {
                    $"10초 미만 짧은 연결: {shortLived}/{list.Count}",
                    $"평균 연결 시간: {list.Average(s => s.DurationSeconds):F2}초, 평균 전송량: {TimeFormat.Bytes((long)list.Average(s => s.TotalPayload))}",
                    $"가장 긴 연결: {list.Max(s => s.DurationSeconds):F1}초 (장시간 연결은 로그인 성공 가능성)",
                },
                SessionIds = list.Select(s => s.Id).Take(500).ToList(),
                Recommendation = "대상 서버의 인증 로그(Windows 4625/4624, /var/log/auth.log 등)에서 해당 출발지의 성공 여부를 확인하십시오.",
            };
        }

        // ③ 웹 로그인 반복
        var loginPosts = r.Http.Where(h => h.Method == "POST" && IsLoginLike(h));
        foreach (var g in loginPosts.GroupBy(h => (h.ClientIp, h.ServerIp, Host: h.Host, Path: PathOf(h.Uri))))
        {
            var list = g.OrderBy(h => h.Time).ToList();
            int max = DetectorUtil.MaxCountInWindow(list, h => h.Time, st.BruteForceWindowSeconds);
            if (max < st.HttpLoginMinRequests) continue;
            var statuses = list.GroupBy(h => h.StatusText).Select(x => $"{x.Key}: {x.Count()}건");
            var users = r.Credentials.Where(c => c.Protocol.StartsWith("HTTP") && c.ClientIp == g.Key.ClientIp && c.ServerIp == g.Key.ServerIp)
                .Select(c => c.Username).Distinct();
            yield return new Finding
            {
                Severity = max >= 50 ? Severity.High : Severity.Medium,
                Category = "계정 공격",
                Title = $"웹 로그인 무차별 대입 의심: {g.Key.ClientIp} → {g.Key.Host}{g.Key.Path}",
                Description = $"{g.Key.ClientIp}이(가) 로그인 페이지({g.Key.Host}{g.Key.Path})에 POST 요청을 {list.Count}회 보냈습니다.",
                SourceIp = g.Key.ClientIp,
                TargetIp = g.Key.ServerIp,
                FirstSeen = list[0].Time,
                LastSeen = list[^1].Time,
                Count = list.Count,
                Mitre = "T1110 Brute Force",
                Evidence = { $"응답 코드 분포: {string.Join(", ", statuses)}", $"시도 계정: {DetectorUtil.JoinLimited(users, 15)}" },
                SessionIds = list.Select(h => h.SessionId).Distinct().Take(500).ToList(),
                Recommendation = "응답 크기/리다이렉트가 다른 요청(로그인 성공 가능)을 확인하고, 로그인 시도 제한과 CAPTCHA 를 적용하십시오.",
            };
        }

        foreach (var g in r.Http.Where(h => h.StatusCode == 401).GroupBy(h => (h.ClientIp, h.ServerIp, h.Host)))
        {
            var list = g.OrderBy(h => h.Time).ToList();
            if (DetectorUtil.MaxCountInWindow(list, h => h.Time, st.BruteForceWindowSeconds) < st.HttpLoginMinRequests) continue;
            yield return new Finding
            {
                Severity = Severity.Medium,
                Category = "계정 공격",
                Title = $"HTTP 인증 실패(401) 반복: {g.Key.ClientIp} → {g.Key.Host}",
                Description = $"{g.Key.ClientIp}의 요청에 대해 {g.Key.Host}({g.Key.ServerIp})가 401 Unauthorized 를 {list.Count}회 응답했습니다.",
                SourceIp = g.Key.ClientIp,
                TargetIp = g.Key.ServerIp,
                FirstSeen = list[0].Time,
                LastSeen = list[^1].Time,
                Count = list.Count,
                Mitre = "T1110 Brute Force",
                Evidence = { $"요청 URL: {DetectorUtil.JoinLimited(list.Select(h => h.Url).Distinct(), 5)}" },
                SessionIds = list.Select(h => h.SessionId).Distinct().Take(500).ToList(),
                Recommendation = "같은 출발지에서 이후 200 응답(인증 성공)이 있었는지 확인하십시오.",
            };
        }
    }

    static bool IsLoginLike(HttpTransaction h)
    {
        var path = PathOf(h.Uri).ToLowerInvariant();
        if (LoginPathHints.Any(path.Contains)) return true;
        if (h.RequestBody.Length is > 0 and < 8192)
        {
            var body = Encoding.UTF8.GetString(h.RequestBody).ToLowerInvariant();
            return body.Contains("pass") || body.Contains("pwd");
        }
        return false;
    }

    static string PathOf(string uri)
    {
        int q = uri.IndexOf('?');
        return q >= 0 ? uri[..q] : uri;
    }
}
