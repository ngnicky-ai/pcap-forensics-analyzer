using System.Net;

namespace PcapForensics.Core.Detection;

/// <summary>HTTP 요청/응답에 시그니처 규칙을 적용해 웹 공격과 그 성공 징후를 탐지한다.</summary>
public sealed class WebAttackDetector : IDetector
{
    public string Name => "웹 공격";

    sealed class Hit
    {
        public required PatternRule Rule;
        public required bool IsResponse;
        public readonly List<(HttpTransaction Tx, string Match)> Items = new();
    }

    public IEnumerable<Finding> Detect(DetectionContext ctx)
    {
        var rules = ctx.WebRules;
        var hits = new Dictionary<(string Rule, bool Resp, string Client, string Server), Hit>();
        var scanners = new Dictionary<(string Client, string Server, string Tool), List<HttpTransaction>>();

        foreach (var h in ctx.Result.Http)
        {
            if (h.RequestLine.Length > 0)
            {
                string text = RequestText(h);
                foreach (var rule in rules.RequestRules)
                {
                    if (!rule.TryMatch(text, out var m)) continue;
                    Add(hits, rule, false, h, m);
                }

                var ua = h.UserAgent.ToLowerInvariant();
                var tool = rules.ScannerUserAgents.FirstOrDefault(t => ua.Contains(t, StringComparison.OrdinalIgnoreCase));
                if (tool is not null)
                {
                    var key = (h.ClientIp, h.ServerIp, tool);
                    if (!scanners.TryGetValue(key, out var list)) scanners[key] = list = new();
                    list.Add(h);
                }
            }

            if (h.ResponseBody.Length > 0 && TextUtil.LooksLikeText(h.ResponseBody))
            {
                string body = TextUtil.Latin1.GetString(h.ResponseBody, 0, Math.Min(h.ResponseBody.Length, 64 * 1024));
                foreach (var rule in rules.ResponseRules)
                {
                    if (rule.TryMatch(body, out var m)) Add(hits, rule, true, h, m);
                }
            }
        }

        foreach (var hit in hits.Values)
        {
            var items = hit.Items.OrderBy(i => i.Tx.Time).ToList();
            var first = items[0].Tx;
            var statuses = items.GroupBy(i => i.Tx.StatusText).Select(x => $"{x.Key}: {x.Count()}건");
            var f = new Finding
            {
                Severity = hit.Rule.Severity,
                Category = hit.Rule.Category,
                Title = hit.IsResponse
                    ? $"{hit.Rule.Name}: {Target(first)} → {first.ClientIp}"
                    : $"{hit.Rule.Name} 시도: {first.ClientIp} → {Target(first)}",
                Description = hit.IsResponse
                    ? $"{Target(first)}의 응답 본문에서 '{hit.Rule.Name}' 패턴이 {items.Count}건 확인되었습니다. 공격이 성공했거나 민감 정보가 노출되었을 수 있습니다."
                    : $"{first.ClientIp}이(가) {Target(first)}에 '{hit.Rule.Name}' 패턴을 포함한 요청을 {items.Count}건 보냈습니다.",
                SourceIp = hit.IsResponse ? first.ServerIp : first.ClientIp,
                TargetIp = hit.IsResponse ? first.ClientIp : first.ServerIp,
                FirstSeen = first.Time,
                LastSeen = items[^1].Tx.Time,
                Count = items.Count,
                Mitre = hit.Rule.Mitre,
                Recommendation = hit.Rule.Recommendation,
                SessionIds = items.Select(i => i.Tx.SessionId).Distinct().Take(500).ToList(),
            };
            f.Evidence.Add($"응답 코드 분포: {string.Join(", ", statuses)}");
            foreach (var (tx, match) in items.Take(10))
                f.Evidence.Add($"[{TimeFormat.Format(tx.Time)}] {tx.Method} {TextUtil.Truncate(tx.Url, 200)} → {tx.StatusText}  (일치: {TextUtil.Truncate(match, 80)})");
            yield return f;
        }

        foreach (var ((client, server, tool), list) in scanners)
        {
            var sorted = list.OrderBy(h => h.Time).ToList();
            yield return new Finding
            {
                Severity = Severity.Medium,
                Category = "정찰",
                Title = $"웹 취약점 스캐너 사용({tool}): {client} → {sorted[0].Host}",
                Description = $"User-Agent 에 '{tool}' 이(가) 포함된 요청 {sorted.Count}건이 {sorted[0].Host}({server})로 전송되었습니다. 자동화된 취약점 점검/공격 도구입니다.",
                SourceIp = client,
                TargetIp = server,
                FirstSeen = sorted[0].Time,
                LastSeen = sorted[^1].Time,
                Count = sorted.Count,
                Mitre = "T1595.002 Active Scanning: Vulnerability Scanning",
                Evidence =
                {
                    $"User-Agent: {sorted[0].UserAgent}",
                    $"요청 예시: {DetectorUtil.JoinLimited(sorted.Select(h => h.Method + " " + TextUtil.Truncate(h.Uri, 120)).Distinct(), 8, " | ")}",
                },
                SessionIds = sorted.Select(h => h.SessionId).Distinct().Take(500).ToList(),
                Recommendation = "허가된 점검인지 확인하십시오. 허가되지 않았다면 출발지를 차단하고, 같은 기간의 다른 공격 탐지 결과와 연관 분석하십시오.",
            };
        }
    }

    static void Add(Dictionary<(string, bool, string, string), Hit> hits, PatternRule rule, bool resp, HttpTransaction h, string match)
    {
        var key = (rule.Name, resp, h.ClientIp, h.ServerIp);
        if (!hits.TryGetValue(key, out var hit)) hits[key] = hit = new Hit { Rule = rule, IsResponse = resp };
        hit.Items.Add((h, match));
    }

    static string Target(HttpTransaction h) =>
        h.Host.Length == 0 || NetUtil.IsIpLiteral(h.Host) ? NetUtil.Endpoint(h.ServerIp, h.ServerPort) : $"{h.Host} ({h.ServerIp})";

    static string RequestText(HttpTransaction h)
    {
        var sb = new StringBuilder();
        string uri = h.Uri;
        for (int i = 0; i < 2; i++) uri = WebUtility.UrlDecode(uri); // 이중 인코딩 대응
        sb.Append(uri).Append('\n');
        foreach (var kv in h.RequestHeaders)
        {
            if (kv.Key.Equals("Host", StringComparison.OrdinalIgnoreCase)) continue;
            sb.Append(kv.Value).Append('\n');
        }
        if (h.RequestBody.Length > 0 && TextUtil.LooksLikeText(h.RequestBody))
        {
            var body = Encoding.UTF8.GetString(h.RequestBody, 0, Math.Min(h.RequestBody.Length, 16 * 1024));
            sb.Append(WebUtility.UrlDecode(body));
        }
        return sb.ToString();
    }
}
