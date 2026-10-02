namespace PcapForensics.Core.Detection;

/// <summary>Suricata 경보를 시그니처·출발지·목적지별로 묶어 탐지 결과로 만든다.</summary>
public sealed class IdsAlertDetector : IDetector
{
    public string Name => "IDS 경보";

    public IEnumerable<Finding> Detect(DetectionContext ctx)
    {
        var groups = ctx.Result.IdsAlerts
            .Where(a => !a.Ignored)
            .GroupBy(a => (a.Gid, a.Sid, a.SrcIp, a.DstIp));

        foreach (var g in groups)
        {
            var list = g.OrderBy(a => a.Time).ToList();
            var first = list[0];
            var f = new Finding
            {
                Severity = list.Max(a => a.Severity),
                Category = "IDS 경보",
                Title = $"[Suricata] {first.Signature}",
                Description = $"Suricata 룰 {first.RuleId} 이(가) {first.SrcIp} → {first.DstIp} 트래픽에서 {list.Count}회 경보를 발생시켰습니다." +
                              (first.Classification.Length > 0 ? $" 분류: {first.Classification} (우선순위 {first.Priority})." : ""),
                SourceIp = first.SrcIp,
                TargetIp = first.DstIp,
                FirstSeen = first.Time,
                LastSeen = list[^1].Time,
                Count = list.Count,
                Mitre = first.Mitre,
                Recommendation = $"룰 sid {first.Sid} 의 원문과 참고 자료(reference)를 확인해 위협의 성격을 판단하십시오. 오탐이면 rules\\settings.json 의 Suricata.IgnoreSids 에 추가하십시오.",
                SessionIds = list.Where(a => a.SessionId.HasValue).Select(a => a.SessionId!.Value).Distinct().Take(500).ToList(),
            };
            foreach (var a in list.Take(10))
                f.Evidence.Add($"[{a.TimeText}] {a.Proto} {a.Source} → {a.Destination}" +
                               (a.AppProto.Length > 0 ? $" ({a.AppProto})" : "") +
                               (a.Detail.Length > 0 ? $"  {TextUtil.Truncate(a.Detail, 200)}" : "") +
                               (a.SessionId is int sid ? $"  세션 #{sid}" : ""));
            yield return f;
        }
    }
}
