namespace PcapForensics.Core.Ids;

/// <summary>IDS 경보를 분석기 세션에 연결하고, 설정에 따라 심각도와 제외 여부를 정한다.</summary>
public static class IdsAlertProcessor
{
    /// <summary>5-tuple 과 시각으로 경보가 속한 세션을 찾는다(방향 무관).</summary>
    public static void LinkSessions(AnalysisResult r)
    {
        var index = new Dictionary<(string, int, string, int), List<NetworkSession>>();
        foreach (var s in r.Sessions)
        {
            var key = (s.ClientIp, s.ClientPort, s.ServerIp, s.ServerPort);
            if (!index.TryGetValue(key, out var list)) index[key] = list = new();
            list.Add(s);
        }

        foreach (var a in r.IdsAlerts)
        {
            var candidates = new List<NetworkSession>();
            if (index.TryGetValue((a.SrcIp, a.SrcPort, a.DstIp, a.DstPort), out var l1)) candidates.AddRange(l1);
            if (index.TryGetValue((a.DstIp, a.DstPort, a.SrcIp, a.SrcPort), out var l2)) candidates.AddRange(l2);
            var match = candidates
                .Where(s => s.TransportText.Equals(a.Proto, StringComparison.OrdinalIgnoreCase))
                .OrderBy(s => a.Time >= s.Start.AddSeconds(-2) && a.Time <= s.End.AddSeconds(2) ? 0 : 1)
                .ThenBy(s => Math.Abs((s.Start - a.Time).TotalSeconds))
                .FirstOrDefault();
            a.SessionId = match?.Id;
        }
    }

    public static void Classify(IEnumerable<IdsAlert> alerts, SuricataOptions o)
    {
        var ignoreSids = o.IgnoreSids.ToHashSet();
        foreach (var a in alerts)
        {
            a.Ignored = ignoreSids.Contains(a.Sid)
                        || o.IgnoreSignaturePrefixes.Any(p => a.Signature.StartsWith(p, StringComparison.OrdinalIgnoreCase));
            var sev = o.SeverityMap.TryGetValue(a.Priority, out var mapped) ? mapped : Severity.Low;
            if (o.EscalateKeywords.Any(k => a.Signature.Contains(k, StringComparison.OrdinalIgnoreCase)) && sev < Severity.Critical)
                sev++;
            a.Severity = sev;
        }
    }
}
