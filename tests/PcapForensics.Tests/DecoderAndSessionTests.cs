using PcapForensics.Core.Decoding;
using PcapForensics.Core.Pcap;
using PcapForensics.Core.Sessions;

namespace PcapForensics.Tests;

public class DecoderTests
{
    static PacketRecord Decode(byte[] frame, int link = 1) =>
        PacketDecoder.Decode(new RawFrame(1, DateTime.UnixEpoch, link, frame.Length, frame));

    [Fact]
    public void Ipv4Tcp_StripsEthernetPadding()
    {
        var ip = Bytes.IPv4("10.0.0.1", "10.0.0.2", 6, Bytes.Tcp(40000, 80, 100, 0, TcpFlags.Syn | TcpFlags.Ack, Bytes.Ascii("hi")));
        var frame = Bytes.Ethernet(0x0800, ip.Concat(new byte[6]).ToArray()); // 이더넷 최소 길이 패딩

        var p = Decode(frame);

        Assert.Equal("10.0.0.1", p.SrcIp);
        Assert.Equal(80, p.DstPort);
        Assert.Equal(TcpFlags.Syn | TcpFlags.Ack, p.Flags);
        Assert.Equal(Bytes.Ascii("hi"), p.Payload);
    }

    [Fact]
    public void VlanTaggedUdp()
    {
        var frame = Bytes.Ethernet(0x0800, Bytes.IPv4("192.168.1.5", "8.8.8.8", 17, Bytes.Udp(5000, 53, new byte[12])), vlan: 100);

        var p = Decode(frame);

        Assert.Equal(TransportProtocol.Udp, p.Transport);
        Assert.Equal(53, p.DstPort);
        Assert.Equal(12, p.Payload.Length);
    }

    [Fact]
    public void Ipv6Udp()
    {
        var frame = Bytes.Ethernet(0x86DD, Bytes.IPv6("2001:db8::1", "2001:db8::2", 17, Bytes.Udp(1234, 443, new byte[4])));

        var p = Decode(frame);

        Assert.Equal("IPv6", p.Network);
        Assert.Equal("2001:db8::1", p.SrcIp);
        Assert.Equal(443, p.DstPort);
    }

    [Fact]
    public void ArpReply()
    {
        var arp = new byte[] { 0, 1, 8, 0, 6, 4, 0, 2, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 192, 168, 0, 1, 1, 2, 3, 4, 5, 6, 192, 168, 0, 2 };

        var p = Decode(Bytes.Ethernet(0x0806, arp));

        Assert.NotNull(p.Arp);
        Assert.Equal("192.168.0.1", p.Arp!.SenderIp);
        Assert.Equal("aa:bb:cc:dd:ee:ff", p.Arp.SenderMac);
        Assert.Contains("is at", p.Info);
    }

    [Fact]
    public void MalformedFrame_DoesNotThrow()
    {
        var p = Decode(new byte[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00, 0x45 });
        Assert.Equal("IPv4", p.Network);
    }
}

public class SessionTrackerTests
{
    static readonly DateTime T0 = new(2020, 1, 1, 0, 0, 0, DateTimeKind.Utc);

    static PacketRecord Tcp(int i, string src, int sport, string dst, int dport, uint seq, TcpFlags flags, string payload = "") => new()
    {
        Index = i, Timestamp = T0.AddMilliseconds(i), SrcIp = src, DstIp = dst, SrcPort = sport, DstPort = dport,
        Transport = TransportProtocol.Tcp, Seq = seq, Flags = flags, Payload = Bytes.Ascii(payload),
    };

    [Fact]
    public void ReassemblesOutOfOrderRetransmittedAndOverlappingSegments()
    {
        var t = new SessionTracker();
        t.Add(Tcp(1, "10.0.0.1", 5000, "10.0.0.2", 80, 1000, TcpFlags.Syn));
        t.Add(Tcp(2, "10.0.0.2", 80, "10.0.0.1", 5000, 9000, TcpFlags.Syn | TcpFlags.Ack));
        t.Add(Tcp(3, "10.0.0.1", 5000, "10.0.0.2", 80, 1007, TcpFlags.Ack, "World"));   // 순서 뒤바뀜
        t.Add(Tcp(4, "10.0.0.1", 5000, "10.0.0.2", 80, 1001, TcpFlags.Ack, "Hello "));
        t.Add(Tcp(5, "10.0.0.1", 5000, "10.0.0.2", 80, 1001, TcpFlags.Ack, "Hello "));  // 재전송
        t.Add(Tcp(6, "10.0.0.1", 5000, "10.0.0.2", 80, 1004, TcpFlags.Ack, "lo Wo"));   // 겹침
        t.Add(Tcp(7, "10.0.0.2", 80, "10.0.0.1", 5000, 9001, TcpFlags.Ack, "OK"));

        var s = Assert.Single(t.Complete());

        Assert.Equal("10.0.0.1", s.ClientIp);
        Assert.Equal(80, s.ServerPort);
        Assert.Equal("Hello World", Encoding.ASCII.GetString(s.ClientData.Data));
        Assert.Equal("OK", Encoding.ASCII.GetString(s.ServerData.Data));
        Assert.Equal(0, s.ClientData.Gaps);
    }

    [Fact]
    public void PortReuseAfterFin_StartsNewSession()
    {
        var t = new SessionTracker();
        t.Add(Tcp(1, "10.0.0.1", 5000, "10.0.0.2", 21, 100, TcpFlags.Syn));
        t.Add(Tcp(2, "10.0.0.1", 5000, "10.0.0.2", 21, 101, TcpFlags.Fin | TcpFlags.Ack));
        t.Add(Tcp(3, "10.0.0.1", 5000, "10.0.0.2", 21, 777, TcpFlags.Syn));

        Assert.Equal(2, t.Complete().Count);
    }

    [Fact]
    public void ServerToClientFirstPacket_UsesServicePortToPickClient()
    {
        var t = new SessionTracker();
        t.Add(Tcp(1, "10.0.0.2", 443, "10.0.0.1", 51000, 1, TcpFlags.Ack, "x"));

        var s = Assert.Single(t.Complete());
        Assert.Equal("10.0.0.1", s.ClientIp);
        Assert.Equal(443, s.ServerPort);
    }
}
