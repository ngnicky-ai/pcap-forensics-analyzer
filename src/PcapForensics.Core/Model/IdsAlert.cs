namespace PcapForensics.Core.Model;

/// <summary>Suricata(eve.json) 경보 한 건.</summary>
public sealed class IdsAlert
{
    public DateTime Time { get; init; }
    public string SrcIp { get; init; } = "";
    public int SrcPort { get; init; }
    public string DstIp { get; init; } = "";
    public int DstPort { get; init; }
    public string Proto { get; init; } = "";
    public string AppProto { get; init; } = "";
    public long FlowId { get; init; }

    public long Gid { get; init; } = 1;
    public long Sid { get; init; }
    public int Rev { get; init; }
    public string Signature { get; init; } = "";
    public string Classification { get; init; } = "";
    /// <summary>Suricata 우선순위(1 = 가장 높음).</summary>
    public int Priority { get; init; } = 3;
    public string Action { get; init; } = "";
    public string Mitre { get; init; } = "";
    /// <summary>HTTP URL, DNS 질의, TLS SNI 등 경보 관련 응용 계층 정보.</summary>
    public string Detail { get; init; } = "";

    /// <summary>분석기 세션과 연결된 경우 세션 번호.</summary>
    public int? SessionId { get; set; }
    /// <summary>설정(우선순위 매핑/상향 키워드)으로 계산한 심각도.</summary>
    public Severity Severity { get; set; } = Severity.Low;
    /// <summary>설정의 제외 목록에 해당하는 경보.</summary>
    public bool Ignored { get; set; }

    public string TimeText => TimeFormat.Format(Time);
    public string SeverityText => Ignored ? "제외" : Severity.ToKorean();
    public string Source => SrcPort > 0 ? NetUtil.Endpoint(SrcIp, SrcPort) : SrcIp;
    public string Destination => DstPort > 0 ? NetUtil.Endpoint(DstIp, DstPort) : DstIp;
    public string RuleId => $"{Gid}:{Sid}:{Rev}";
}
