namespace PcapForensics.Core.Model;

/// <summary>디코딩된 패킷 한 개.</summary>
public sealed class PacketRecord
{
    public int Index { get; init; }
    public DateTime Timestamp { get; init; }
    public int Length { get; init; }
    public int CapturedLength { get; init; }

    public string? SrcMac { get; set; }
    public string? DstMac { get; set; }
    public string Network { get; set; } = "";
    public string? SrcIp { get; set; }
    public string? DstIp { get; set; }
    public int IpProtocol { get; set; } = -1;
    public byte Ttl { get; set; }
    public bool IsFragment { get; set; }

    public TransportProtocol Transport { get; set; }
    public int SrcPort { get; set; }
    public int DstPort { get; set; }
    public TcpFlags Flags { get; set; }
    public uint Seq { get; set; }
    public uint Ack { get; set; }
    public ushort Window { get; set; }
    public byte IcmpType { get; set; }
    public byte IcmpCode { get; set; }
    public ArpInfo? Arp { get; set; }
    public byte[] Payload { get; set; } = Array.Empty<byte>();

    public string ProtocolName { get; set; } = "";
    public string Info { get; set; } = "";
    public int SessionId { get; set; } = -1;
    /// <summary>시각과 내용이 완전히 같은 프레임이 앞서 기록된 경우(캡처 병합 등).</summary>
    public bool IsDuplicate { get; set; }

    public bool HasPorts => Transport is TransportProtocol.Tcp or TransportProtocol.Udp;
    public string Source => SrcIp is null ? SrcMac ?? "" : HasPorts ? NetUtil.Endpoint(SrcIp, SrcPort) : SrcIp;
    public string Destination => DstIp is null ? DstMac ?? "" : HasPorts ? NetUtil.Endpoint(DstIp, DstPort) : DstIp;
    public string TimeText => TimeFormat.Precise(Timestamp);
    public int PayloadLength => Payload.Length;
}

public sealed record ArpInfo(int Operation, string SenderMac, string SenderIp, string TargetMac, string TargetIp);
