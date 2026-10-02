namespace PcapForensics.Core.Detection;

/// <summary>DNS 터널링(길고 무작위한 하위 도메인 대량 질의)과 DGA(다수의 NXDOMAIN)를 탐지한다.</summary>
public sealed class DnsAnomalyDetector : IDetector
{
    public string Name => "DNS 이상";

    public IEnumerable<Finding> Detect(DetectionContext ctx)
    {
        var r = ctx.Result;
        var st = ctx.Settings;
        var allow = st.DnsAllowList.Select(DomainUtil.Normalize).ToList();

        foreach (var g in r.Dns.Where(d => d.QueryName.Length > 0).GroupBy(d => DomainUtil.BaseDomain(d.QueryName)))
        {
            if (g.Key.Length == 0 || allow.Any(a => DomainUtil.MatchesSuffix(g.Key, a))) continue;

            var subs = g.Select(d => DomainUtil.SubdomainPart(d.QueryName, g.Key)).Where(s => s.Length > 0).Distinct().ToList();
            if (subs.Count < st.DnsTunnelMinUniqueSubdomains) continue;

            double avgLen = subs.Average(s => s.Length);
            double avgEntropy = subs.Average(s => EntropyUtil.Shannon(s.Replace(".", "")));
            int maxLabel = subs.Max(s => s.Split('.').Max(l => l.Length));
            int txt = g.Count(d => d.QueryType is "TXT" or "NULL" or "CNAME" or "MX");

            bool suspicious = avgLen >= st.DnsTunnelMinAvgLength
                              || (avgEntropy >= st.DnsTunnelMinEntropy && avgLen >= 12)
                              || maxLabel >= 52;
            if (!suspicious) continue;

            var list = g.OrderBy(d => d.Time).ToList();
            var clients = list.Select(d => d.ClientIp).Distinct().ToList();
            yield return new Finding
            {
                Severity = Severity.High,
                Category = "C2 / 유출",
                Title = $"DNS 터널링 의심: *.{g.Key}",
                Description = $"{g.Key} 의 서로 다른 하위 도메인 {subs.Count}개가 질의되었습니다. 평균 길이 {avgLen:F1}자, " +
                              $"평균 엔트로피 {avgEntropy:F2}로 데이터가 인코딩된 형태입니다. DNS 를 통한 C2 통신이나 데이터 유출일 수 있습니다.",
                SourceIp = string.Join(", ", clients.Take(3)),
                TargetIp = g.Key,
                FirstSeen = list[0].Time,
                LastSeen = list[^1].Time,
                Count = list.Count,
                Mitre = "T1071.004 Application Layer Protocol: DNS / T1048 Exfiltration Over Alternative Protocol",
                Evidence =
                {
                    $"질의 예시: {DetectorUtil.JoinLimited(subs.Take(5).Select(s => s + "." + g.Key), 5, " | ")}",
                    $"최대 레이블 길이 {maxLabel}자, TXT/NULL/CNAME/MX 질의 {txt}건",
                    $"질의 호스트: {DetectorUtil.JoinLimited(clients, 10)}",
                },
                Recommendation = "해당 도메인을 DNS 방화벽에서 차단하고, 질의 호스트에서 실행 중인 프로세스를 조사하십시오. 하위 도메인을 디코딩하면 유출 데이터를 확인할 수 있습니다.",
            };
        }

        foreach (var g in r.Dns.Where(d => d.RCode == 3).GroupBy(d => d.ClientIp))
        {
            var names = g.Select(d => DomainUtil.Normalize(d.QueryName))
                .Where(n => !allow.Any(a => DomainUtil.MatchesSuffix(n, a)))
                .Distinct().ToList();
            if (names.Count < st.DnsNxDomainThreshold) continue;
            var bases = names.Select(DomainUtil.BaseDomain).Distinct().ToList();
            var list = g.OrderBy(d => d.Time).ToList();
            yield return new Finding
            {
                Severity = bases.Count >= st.DnsNxDomainThreshold ? Severity.High : Severity.Medium,
                Category = "C2 / 유출",
                Title = $"NXDOMAIN 응답 다수(DGA 의심): {g.Key}",
                Description = $"{g.Key}이(가) 존재하지 않는 도메인 {names.Count}개(등록 도메인 {bases.Count}개)를 질의했습니다. " +
                              "도메인 생성 알고리즘(DGA)을 사용하는 악성코드가 C2 서버를 찾는 행위일 수 있습니다.",
                SourceIp = g.Key,
                TargetIp = list[0].ServerIp,
                FirstSeen = list[0].Time,
                LastSeen = list[^1].Time,
                Count = names.Count,
                Mitre = "T1568.002 Dynamic Resolution: Domain Generation Algorithms",
                Evidence = { $"질의된 도메인: {DetectorUtil.JoinLimited(names, 15)}" },
                Recommendation = "해당 호스트를 격리하고 악성코드 검사를 수행하십시오. 응답이 성공한(NOERROR) 유사 패턴 도메인이 있는지 확인하십시오.",
            };
        }
    }
}
