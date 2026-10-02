namespace PcapForensics.Core.Model;

/// <summary>TCP 연결 또는 UDP 흐름. 클라이언트는 연결을 시작한 쪽이다.</summary>
public sealed class NetworkSession
{
    public int Id { get; init; }
    public TransportProtocol Transport { get; init; }
    public string ClientIp { get; init; } = "";
    public int ClientPort { get; init; }
    public string ServerIp { get; init; } = "";
    public int ServerPort { get; init; }

    public DateTime Start { get; set; }
    public DateTime End { get; set; }
    public int Packets { get; set; }
    public long FrameBytes { get; set; }
    public long ClientBytes { get; set; }
    public long ServerBytes { get; set; }

    public bool SynSeen { get; set; }
    public bool SynAckSeen { get; set; }
    public bool FinSeen { get; set; }
    public bool RstSeen { get; set; }

    public string AppProtocol { get; set; } = "";
    public string ServerName { get; set; } = "";
    public string Summary { get; set; } = "";

    public ReassembledStream ClientData { get; set; } = ReassembledStream.Empty;
    public ReassembledStream ServerData { get; set; } = ReassembledStream.Empty;

    public string TransportText => Transport switch
    {
        TransportProtocol.Tcp => "TCP",
        TransportProtocol.Udp => "UDP",
        _ => Transport.ToString(),
    };

    public bool Established => SynAckSeen || (ClientBytes > 0 && ServerBytes > 0);

    public string State
    {
        get
        {
            if (Transport != TransportProtocol.Tcp) return "-";
            if (SynSeen && !SynAckSeen) return RstSeen ? "거부됨(RST)" : "응답 없음";
            if (RstSeen) return "리셋";
            if (FinSeen) return "종료";
            if (SynAckSeen) return "연결 유지";
            return "부분 캡처";
        }
    }

    public double DurationSeconds => (End - Start).TotalSeconds;
    public string DurationText => DurationSeconds.ToString("F2") + "s";
    public string ClientEndpoint => NetUtil.Endpoint(ClientIp, ClientPort);
    public string ServerEndpoint => NetUtil.Endpoint(ServerIp, ServerPort);
    public string StartText => TimeFormat.Format(Start);
    public long TotalPayload => ClientBytes + ServerBytes;
    public string ClientBytesText => TimeFormat.Bytes(ClientBytes);
    public string ServerBytesText => TimeFormat.Bytes(ServerBytes);
}

public readonly record struct StreamMark(int Offset, DateTime Time);

/// <summary>한 방향으로 재조립된 TCP 바이트 스트림과 각 구간의 도착 시각.</summary>
public sealed class ReassembledStream
{
    public static readonly ReassembledStream Empty = new(Array.Empty<byte>(), Array.Empty<StreamMark>(), 0);

    public ReassembledStream(byte[] data, IReadOnlyList<StreamMark> marks, int gaps)
    {
        Data = data;
        Marks = marks;
        Gaps = gaps;
    }

    public byte[] Data { get; }
    public IReadOnlyList<StreamMark> Marks { get; }
    /// <summary>패킷 손실로 비어 있는 구간 수.</summary>
    public int Gaps { get; }

    /// <summary>지정한 오프셋의 바이트가 포함된 세그먼트의 도착 시각.</summary>
    public DateTime? TimeAt(int offset)
    {
        if (Marks.Count == 0) return null;
        int lo = 0, hi = Marks.Count - 1, found = 0;
        while (lo <= hi)
        {
            int mid = (lo + hi) / 2;
            if (Marks[mid].Offset <= offset) { found = mid; lo = mid + 1; }
            else hi = mid - 1;
        }
        return Marks[found].Time;
    }
}
