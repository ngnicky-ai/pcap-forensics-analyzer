namespace PcapForensics.Core.Detection;

/// <summary>
/// 일정한 간격으로 반복되는 연결(C2 비컨)을 탐지한다.
/// 1초 이내 연속 연결은 한 번의 이벤트로 묶고, 간격의 중앙값 대비 허용 오차 안에 드는 비율로 규칙성을 판단한다.
/// </summary>
public sealed class BeaconDetector : IDetector
{
    public string Name => "비컨";

    public IEnumerable<Finding> Detect(DetectionContext ctx)
    {
        var r = ctx.Result;
        var st = ctx.Settings;
        var ignore = st.BeaconIgnorePorts.ToHashSet();

        var groups = r.Sessions
            .Where(s => s.Transport == TransportProtocol.Tcp && !ignore.Contains(s.ServerPort) && (s.SynSeen || s.ClientBytes > 0))
            .GroupBy(s => (s.ClientIp, s.ServerIp, s.ServerPort));

        foreach (var g in groups)
        {
            var sessions = g.OrderBy(s => s.Start).ToList();
            if (sessions.Count < st.BeaconMinConnections) continue;

            var events = new List<DateTime>();
            foreach (var s in sessions)
                if (events.Count == 0 || (s.Start - events[^1]).TotalSeconds > 1) events.Add(s.Start);
            if (events.Count < st.BeaconMinConnections) continue;

            var intervals = events.Zip(events.Skip(1), (a, b) => (b - a).TotalSeconds).ToList();
            double median = DetectorUtil.Median(intervals);
            if (median < st.BeaconMinIntervalSeconds) continue;

            double regular = intervals.Count(i => Math.Abs(i - median) <= median * st.BeaconMaxJitterRatio) / (double)intervals.Count;
            if (regular < st.BeaconMinRegularFraction) continue;

            double mean = intervals.Average();
            double std = Math.Sqrt(intervals.Average(i => (i - mean) * (i - mean)));
            bool external = NetUtil.IsExternal(g.Key.ServerIp);
            string target = DetectorUtil.WithName(r, g.Key.ServerIp);

            yield return new Finding
            {
                Severity = !external ? Severity.Low : events.Count >= 20 ? Severity.High : Severity.Medium,
                Category = "C2 / 유출",
                Title = $"주기적 통신(비컨) 의심: {g.Key.ClientIp} → {target}:{g.Key.ServerPort}",
                Description = $"{g.Key.ClientIp}이(가) {target}:{g.Key.ServerPort} 에 약 {median:F1}초 간격으로 {events.Count}회 반복 연결했습니다 " +
                              $"(규칙성 {regular:P0}, 변동계수 {(mean > 0 ? std / mean : 0):F2}). 사람이 아닌 프로그램의 주기적 통신으로, 악성코드의 C2 비컨일 수 있습니다.",
                SourceIp = g.Key.ClientIp,
                TargetIp = g.Key.ServerIp,
                FirstSeen = events[0],
                LastSeen = sessions[^1].End,
                Count = events.Count,
                Mitre = "T1071 Application Layer Protocol / T1029 Scheduled Transfer",
                Evidence =
                {
                    $"연결 간격(초): {DetectorUtil.JoinLimited(intervals.Select(i => i.ToString("F1")), 20)}",
                    $"연결당 평균 전송량: 송신 {TimeFormat.Bytes((long)sessions.Average(s => s.ClientBytes))}, 수신 {TimeFormat.Bytes((long)sessions.Average(s => s.ServerBytes))}",
                    $"응용 프로토콜: {string.Join(", ", sessions.Select(s => s.AppProtocol).Distinct())}",
                },
                SessionIds = sessions.Select(s => s.Id).Take(500).ToList(),
                Recommendation = "목적지의 평판(위협 인텔리전스)을 조회하고, 출발지 호스트에서 해당 연결을 생성한 프로세스를 확인하십시오. 업데이트/모니터링 에이전트 등 정상 프로그램인지도 구분해야 합니다.",
            };
        }
    }
}
