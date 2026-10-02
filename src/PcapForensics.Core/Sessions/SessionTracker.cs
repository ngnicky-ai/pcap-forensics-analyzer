namespace PcapForensics.Core.Sessions;

/// <summary>패킷을 TCP 연결/UDP 흐름으로 묶고, 종료 시 양방향 스트림을 재조립한다.</summary>
public sealed class SessionTracker
{
    const double TcpIdleTimeout = 600;
    const double UdpIdleTimeout = 120;

    readonly Dictionary<FlowKey, NetworkSession> _active = new();
    readonly Dictionary<int, (StreamBuilder Client, StreamBuilder Server)> _builders = new();
    readonly List<NetworkSession> _sessions = new();

    public void Add(PacketRecord p)
    {
        if (p.SrcIp is null || p.DstIp is null || !p.HasPorts) return;

        var key = FlowKey.Create(p.Transport, p.SrcIp, p.SrcPort, p.DstIp, p.DstPort);
        bool tcp = p.Transport == TransportProtocol.Tcp;
        bool isSyn = tcp && p.Flags.HasFlag(TcpFlags.Syn) && !p.Flags.HasFlag(TcpFlags.Ack);

        if (_active.TryGetValue(key, out var s))
        {
            bool expired = (p.Timestamp - s.End).TotalSeconds > (tcp ? TcpIdleTimeout : UdpIdleTimeout);
            bool reopened = false;
            if (isSyn && s.SynSeen)
            {
                // 같은 4-tuple 재사용: 종료된 연결이거나 ISN 이 다르면 새 연결
                var isn = _builders[s.Id].Client.Isn;
                reopened = s.FinSeen || s.RstSeen || (isn.HasValue && isn.Value != p.Seq);
            }
            else if (isSyn && (s.FinSeen || s.RstSeen)) reopened = true;

            if (expired || reopened) s = null;
        }

        if (s is null)
        {
            s = Create(p);
            _active[key] = s;
            _sessions.Add(s);
            _builders[s.Id] = (new StreamBuilder(), new StreamBuilder());
        }
        Update(s, p);
    }

    NetworkSession Create(PacketRecord p)
    {
        bool srcIsClient;
        if (p.Transport == TransportProtocol.Tcp && p.Flags.HasFlag(TcpFlags.Syn))
            srcIsClient = !p.Flags.HasFlag(TcpFlags.Ack);
        else
        {
            bool srcSvc = IsServicePort(p.SrcPort), dstSvc = IsServicePort(p.DstPort);
            if (srcSvc != dstSvc) srcIsClient = dstSvc;
            else if (p.Transport == TransportProtocol.Udp) srcIsClient = true;
            else srcIsClient = p.DstPort <= p.SrcPort;
        }

        return new NetworkSession
        {
            Id = _sessions.Count + 1,
            Transport = p.Transport,
            ClientIp = srcIsClient ? p.SrcIp! : p.DstIp!,
            ClientPort = srcIsClient ? p.SrcPort : p.DstPort,
            ServerIp = srcIsClient ? p.DstIp! : p.SrcIp!,
            ServerPort = srcIsClient ? p.DstPort : p.SrcPort,
            Start = p.Timestamp,
            End = p.Timestamp,
        };
    }

    void Update(NetworkSession s, PacketRecord p)
    {
        bool fromClient = p.SrcIp == s.ClientIp && p.SrcPort == s.ClientPort;
        var (cb, sb) = _builders[s.Id];
        var builder = fromClient ? cb : sb;

        s.Packets++;
        s.FrameBytes += p.Length;
        if (p.Timestamp > s.End) s.End = p.Timestamp;
        if (p.Timestamp < s.Start) s.Start = p.Timestamp;
        p.SessionId = s.Id;

        if (p.Transport == TransportProtocol.Tcp)
        {
            bool syn = p.Flags.HasFlag(TcpFlags.Syn), ack = p.Flags.HasFlag(TcpFlags.Ack);
            if (syn && !ack) { s.SynSeen = true; builder.SetIsn(p.Seq); }
            if (syn && ack) { s.SynAckSeen = true; builder.SetIsn(p.Seq); }
            if (p.Flags.HasFlag(TcpFlags.Fin)) s.FinSeen = true;
            if (p.Flags.HasFlag(TcpFlags.Rst)) s.RstSeen = true;
            if (p.Payload.Length > 0 && !syn) builder.AddSegment(p.Seq, p.Payload, p.Timestamp);
        }
        else if (p.Payload.Length > 0)
        {
            builder.AddDatagram(p.Payload, p.Timestamp);
        }

        if (fromClient) s.ClientBytes += p.Payload.Length;
        else s.ServerBytes += p.Payload.Length;
    }

    /// <summary>모든 세션의 스트림을 재조립하고 목록을 반환한다.</summary>
    public List<NetworkSession> Complete()
    {
        foreach (var s in _sessions)
        {
            var (cb, sb) = _builders[s.Id];
            bool tcp = s.Transport == TransportProtocol.Tcp;
            s.ClientData = tcp ? cb.BuildTcp() : cb.BuildSequential();
            s.ServerData = tcp ? sb.BuildTcp() : sb.BuildSequential();
        }
        _builders.Clear();
        _active.Clear();
        return _sessions;
    }

    static readonly HashSet<int> KnownServicePorts = new()
    {
        1080, 1194, 1433, 1521, 1723, 1883, 1900, 2049, 2375, 3128, 3306, 3389, 4444, 5060, 5353, 5355,
        5432, 5672, 5900, 5985, 5986, 6379, 6667, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9200, 11211, 27017,
    };

    public static bool IsServicePort(int port) => port < 1024 || KnownServicePorts.Contains(port);

    readonly record struct FlowKey(TransportProtocol Transport, string A, int APort, string B, int BPort)
    {
        public static FlowKey Create(TransportProtocol t, string srcIp, int srcPort, string dstIp, int dstPort)
        {
            int c = string.CompareOrdinal(srcIp, dstIp);
            bool srcFirst = c < 0 || (c == 0 && srcPort <= dstPort);
            return srcFirst
                ? new FlowKey(t, srcIp, srcPort, dstIp, dstPort)
                : new FlowKey(t, dstIp, dstPort, srcIp, srcPort);
        }
    }
}

/// <summary>한 방향의 세그먼트를 모아 순서 정렬/중복 제거 후 연속된 바이트로 만든다.</summary>
internal sealed class StreamBuilder
{
    const long MaxStreamBytes = 64L * 1024 * 1024;

    readonly List<(uint Seq, byte[] Data, DateTime Time)> _segments = new();
    long _total;

    public uint? Isn { get; private set; }

    public void SetIsn(uint isn) => Isn ??= isn;

    public void AddSegment(uint seq, byte[] data, DateTime time)
    {
        if (_total > MaxStreamBytes) return;
        _segments.Add((seq, data, time));
        _total += data.Length;
    }

    public void AddDatagram(byte[] data, DateTime time) => AddSegment((uint)_total, data, time);

    public ReassembledStream BuildSequential()
    {
        if (_segments.Count == 0) return ReassembledStream.Empty;
        using var ms = new MemoryStream((int)Math.Min(_total, int.MaxValue));
        var marks = new List<StreamMark>(_segments.Count);
        foreach (var (_, data, time) in _segments)
        {
            marks.Add(new StreamMark((int)ms.Length, time));
            ms.Write(data);
        }
        return new ReassembledStream(ms.ToArray(), marks, 0);
    }

    public ReassembledStream BuildTcp()
    {
        if (_segments.Count == 0) return ReassembledStream.Empty;

        uint baseSeq;
        if (Isn.HasValue) baseSeq = unchecked(Isn.Value + 1);
        else
        {
            // 연결 중간부터 캡처된 경우: 가장 앞선 시퀀스를 기준으로 사용(랩어라운드 고려)
            baseSeq = _segments[0].Seq;
            foreach (var seg in _segments)
                if (unchecked((int)(seg.Seq - baseSeq)) < 0) baseSeq = seg.Seq;
        }

        var ordered = _segments
            .Select((seg, i) => (Rel: (long)unchecked((int)(seg.Seq - baseSeq)), seg.Data, seg.Time, Order: i))
            .Where(x => x.Rel >= 0)
            .OrderBy(x => x.Rel).ThenBy(x => x.Order)
            .ToList();

        using var ms = new MemoryStream();
        var marks = new List<StreamMark>(ordered.Count);
        long expected = 0;
        int gaps = 0;
        foreach (var (rel, data, time, _) in ordered)
        {
            long end = rel + data.Length;
            if (end <= expected) continue; // 재전송
            int skip = 0;
            if (rel < expected) skip = (int)(expected - rel); // 겹침
            else if (rel > expected) gaps++;                    // 손실 구간
            marks.Add(new StreamMark((int)ms.Length, time));
            ms.Write(data, skip, data.Length - skip);
            expected = end;
            if (ms.Length > MaxStreamBytes) break;
        }
        return new ReassembledStream(ms.ToArray(), marks, gaps);
    }
}
