namespace PcapForensics.Core.Detection;

/// <summary>
/// 수직 스캔(한 호스트의 여러 포트)과 수평 스윕(여러 호스트의 같은 포트)을 탐지한다.
/// SYN 을 보낸 TCP 세션 단위로 계산하므로 Half-open(SYN 스캔)도 포함된다.
/// </summary>
public sealed class PortScanDetector : IDetector
{
    public string Name => "포트 스캔";

    public IEnumerable<Finding> Detect(DetectionContext ctx)
    {
        var st = ctx.Settings;
        var probes = ctx.Result.Sessions.Where(s => s.Transport == TransportProtocol.Tcp && s.SynSeen).ToList();

        foreach (var g in probes.GroupBy(s => (s.ClientIp, s.ServerIp)))
        {
            var list = g.OrderBy(s => s.Start).ToList();
            int maxPorts = DetectorUtil.MaxDistinctInWindow(list, s => s.Start, s => s.ServerPort, st.PortScanWindowSeconds);
            if (maxPorts < st.PortScanMinPorts) continue;

            var ports = list.Select(s => s.ServerPort).Distinct().ToList();
            var open = list.Where(s => s.SynAckSeen).Select(s => s.ServerPort).Distinct().OrderBy(p => p).ToList();
            int refused = list.Count(s => !s.SynAckSeen && s.RstSeen);
            int silent = list.Count(s => !s.SynAckSeen && !s.RstSeen);
            int halfOpen = list.Count(s => s.SynAckSeen && s.ClientBytes == 0 && s.ServerBytes == 0 && s.RstSeen);

            yield return new Finding
            {
                Severity = ports.Count >= 100 ? Severity.High : Severity.Medium,
                Category = "정찰",
                Title = $"포트 스캔: {g.Key.ClientIp} → {g.Key.ServerIp}",
                Description = $"{g.Key.ClientIp}이(가) {g.Key.ServerIp}의 서로 다른 TCP 포트 {ports.Count}개에 연결을 시도했습니다 " +
                              $"({st.PortScanWindowSeconds:F0}초 구간 최대 {maxPorts}개). 열린 포트 {open.Count}개가 확인되었습니다.",
                SourceIp = g.Key.ClientIp,
                TargetIp = g.Key.ServerIp,
                FirstSeen = list[0].Start,
                LastSeen = list[^1].End,
                Count = list.Count,
                Mitre = "T1046 Network Service Discovery",
                Evidence =
                {
                    $"스캔 대상 포트: {DetectorUtil.PortRanges(ports)}",
                    $"열린 포트(SYN/ACK 응답): {(open.Count > 0 ? DetectorUtil.PortRanges(open) : "없음")}",
                    $"거부(RST) {refused}건, 무응답 {silent}건, Half-open(데이터 없이 RST 종료) {halfOpen}건",
                    $"스캔 기간: {TimeFormat.Format(list[0].Start)} ~ {TimeFormat.Format(list[^1].End)}",
                },
                SessionIds = list.Select(s => s.Id).Take(500).ToList(),
                Recommendation = "출발지 IP 를 차단 목록에 등록하고, 열린 포트의 서비스에 이후 공격(무차별 대입, 취약점 공격) 시도가 있었는지 확인하십시오.",
            };
        }

        foreach (var g in probes.GroupBy(s => (s.ClientIp, s.ServerPort)))
        {
            var list = g.OrderBy(s => s.Start).ToList();
            int maxHosts = DetectorUtil.MaxDistinctInWindow(list, s => s.Start, s => s.ServerIp, st.PortScanWindowSeconds);
            if (maxHosts < st.PortScanMinHosts) continue;

            var hosts = list.Select(s => s.ServerIp).Distinct().ToList();
            var alive = list.Where(s => s.SynAckSeen).Select(s => s.ServerIp).Distinct().ToList();

            // 일반 웹 브라우징처럼 외부 호스트 대부분이 정상 응답하는 경우는 스윕이 아니다
            int external = hosts.Count(NetUtil.IsExternal);
            if (external > hosts.Count / 2 && alive.Count > hosts.Count / 2) continue;

            yield return new Finding
            {
                Severity = Severity.Medium,
                Category = "정찰",
                Title = $"호스트 스윕: {g.Key.ClientIp} → 다수 호스트의 TCP/{g.Key.ServerPort}",
                Description = $"{g.Key.ClientIp}이(가) {hosts.Count}개 호스트의 TCP {g.Key.ServerPort} 포트에 연결을 시도했습니다. " +
                              $"응답한 호스트는 {alive.Count}개입니다. 내부 확산(래터럴 무브먼트) 또는 웜 활동일 수 있습니다.",
                SourceIp = g.Key.ClientIp,
                TargetIp = $"{hosts.Count}개 호스트",
                FirstSeen = list[0].Start,
                LastSeen = list[^1].End,
                Count = list.Count,
                Mitre = "T1046 Network Service Discovery",
                Evidence =
                {
                    $"대상 호스트: {DetectorUtil.JoinLimited(hosts, 30)}",
                    $"응답한 호스트: {(alive.Count > 0 ? DetectorUtil.JoinLimited(alive, 30) : "없음")}",
                },
                SessionIds = list.Select(s => s.Id).Take(500).ToList(),
                Recommendation = "출발지 호스트의 감염 여부를 점검하고, 응답한 호스트에서 해당 출발지의 접속 로그를 확인하십시오.",
            };
        }
    }
}
