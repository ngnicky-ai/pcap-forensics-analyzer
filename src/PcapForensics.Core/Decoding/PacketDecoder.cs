using System.Buffers.Binary;
using System.Net;
using PcapForensics.Core.Pcap;

namespace PcapForensics.Core.Decoding;

/// <summary>
/// 링크 계층(Ethernet/VLAN, Linux SLL/SLL2, Raw IP, Null) → IPv4/IPv6/ARP → TCP/UDP/ICMP 까지 디코딩한다.
/// 손상된 패킷도 가능한 데까지 해석하며 예외를 밖으로 던지지 않는다.
/// </summary>
public static class PacketDecoder
{
    public static PacketRecord Decode(RawFrame frame)
    {
        var p = new PacketRecord
        {
            Index = frame.Index,
            Timestamp = frame.Timestamp,
            Length = frame.OriginalLength,
            CapturedLength = frame.Data.Length,
        };
        try
        {
            DecodeLink(p, frame.LinkType, frame.Data);
        }
        catch (Exception ex) when (ex is ArgumentOutOfRangeException or IndexOutOfRangeException or ArgumentException)
        {
            p.Info = "[디코딩 오류] " + p.Info;
        }
        if (p.ProtocolName.Length == 0) p.ProtocolName = p.Network.Length > 0 ? p.Network : "Unknown";
        return p;
    }

    static void DecodeLink(PacketRecord p, int linkType, ReadOnlySpan<byte> d)
    {
        switch (linkType)
        {
            case 1:
                DecodeEthernet(p, d);
                break;
            case 0: // BSD loopback: 호스트 바이트 순서의 주소 패밀리
            case 108:
            {
                if (d.Length < 4) return;
                uint fam = linkType == 108 ? BinaryPrimitives.ReadUInt32BigEndian(d) : BinaryPrimitives.ReadUInt32LittleEndian(d);
                if (fam > 0xFFFF) fam = BinaryPrimitives.ReverseEndianness(fam);
                if (fam == 2) DecodeIPv4(p, d[4..]);
                else if (fam is 24 or 28 or 30) DecodeIPv6(p, d[4..]);
                else p.Network = $"AF {fam}";
                break;
            }
            case 101: case 12: case 14: case 228: case 229:
                if (d.Length > 0 && d[0] >> 4 == 6) DecodeIPv6(p, d); else DecodeIPv4(p, d);
                break;
            case 113: // Linux cooked capture v1
                if (d.Length >= 16) DecodeEtherType(p, BinaryPrimitives.ReadUInt16BigEndian(d[14..]), d[16..]);
                break;
            case 276: // Linux cooked capture v2
                if (d.Length >= 20) DecodeEtherType(p, BinaryPrimitives.ReadUInt16BigEndian(d), d[20..]);
                break;
            default:
                p.Network = $"LinkType {linkType}";
                break;
        }
    }

    static void DecodeEthernet(PacketRecord p, ReadOnlySpan<byte> d)
    {
        if (d.Length < 14) return;
        p.DstMac = Mac(d[..6]);
        p.SrcMac = Mac(d.Slice(6, 6));
        int off = 12;
        ushort type = BinaryPrimitives.ReadUInt16BigEndian(d[off..]);
        off += 2;
        while (type is 0x8100 or 0x88A8 or 0x9100 && d.Length >= off + 4)
        {
            type = BinaryPrimitives.ReadUInt16BigEndian(d[(off + 2)..]);
            off += 4;
        }
        if (type <= 1500)
        {
            p.Network = "LLC";
            p.ProtocolName = d.Length > off + 2 && d[off] == 0x42 && d[off + 1] == 0x42 ? "STP" : "LLC";
            return;
        }
        DecodeEtherType(p, type, d[off..]);
    }

    static void DecodeEtherType(PacketRecord p, ushort type, ReadOnlySpan<byte> d)
    {
        switch (type)
        {
            case 0x0800: DecodeIPv4(p, d); break;
            case 0x86DD: DecodeIPv6(p, d); break;
            case 0x0806: DecodeArp(p, d); break;
            default:
                p.Network = $"0x{type:X4}";
                p.ProtocolName = type switch
                {
                    0x88CC => "LLDP",
                    0x888E => "EAPOL",
                    0x8035 => "RARP",
                    0x8863 or 0x8864 => "PPPoE",
                    _ => $"EtherType 0x{type:X4}",
                };
                break;
        }
    }

    static void DecodeIPv4(PacketRecord p, ReadOnlySpan<byte> d)
    {
        p.Network = "IPv4";
        if (d.Length < 20 || d[0] >> 4 != 4) return;
        int ihl = (d[0] & 0x0F) * 4;
        if (ihl < 20 || d.Length < ihl) return;
        int total = BinaryPrimitives.ReadUInt16BigEndian(d[2..]);
        if (total >= ihl && total < d.Length) d = d[..total]; // 이더넷 패딩 제거

        p.Ttl = d[8];
        int proto = d[9];
        p.IpProtocol = proto;
        p.SrcIp = Ip4(d.Slice(12, 4));
        p.DstIp = Ip4(d.Slice(16, 4));

        ushort frag = BinaryPrimitives.ReadUInt16BigEndian(d[6..]);
        int fragOffset = frag & 0x1FFF;
        if (fragOffset != 0)
        {
            p.IsFragment = true;
            p.ProtocolName = "IPv4";
            p.Info = $"IP 조각 (offset={fragOffset * 8}, proto={proto})";
            return;
        }
        if ((frag & 0x2000) != 0) p.IsFragment = true;
        DecodeTransport(p, proto, d[ihl..]);
    }

    static void DecodeIPv6(PacketRecord p, ReadOnlySpan<byte> d)
    {
        p.Network = "IPv6";
        if (d.Length < 40) return;
        int payloadLen = BinaryPrimitives.ReadUInt16BigEndian(d[4..]);
        int next = d[6];
        p.Ttl = d[7];
        p.SrcIp = new IPAddress(d.Slice(8, 16)).ToString();
        p.DstIp = new IPAddress(d.Slice(24, 16)).ToString();

        var rest = d[40..];
        if (payloadLen > 0 && payloadLen < rest.Length) rest = rest[..payloadLen];

        for (int i = 0; i < 8; i++)
        {
            if (next is 0 or 43 or 60)
            {
                if (rest.Length < 8) return;
                int len = (rest[1] + 1) * 8;
                next = rest[0];
                if (rest.Length < len) return;
                rest = rest[len..];
            }
            else if (next == 44)
            {
                if (rest.Length < 8) return;
                int fo = BinaryPrimitives.ReadUInt16BigEndian(rest[2..]) >> 3;
                next = rest[0];
                rest = rest[8..];
                if (fo != 0)
                {
                    p.IsFragment = true;
                    p.IpProtocol = next;
                    p.Info = $"IPv6 조각 (offset={fo * 8})";
                    return;
                }
            }
            else break;
        }
        p.IpProtocol = next;
        DecodeTransport(p, next, rest);
    }

    static void DecodeTransport(PacketRecord p, int proto, ReadOnlySpan<byte> d)
    {
        switch (proto)
        {
            case 6: DecodeTcp(p, d); break;
            case 17: DecodeUdp(p, d); break;
            case 1:
            case 58:
                p.Transport = proto == 1 ? TransportProtocol.Icmp : TransportProtocol.IcmpV6;
                p.ProtocolName = proto == 1 ? "ICMP" : "ICMPv6";
                if (d.Length >= 2)
                {
                    p.IcmpType = d[0];
                    p.IcmpCode = d[1];
                    p.Info = proto == 1 ? IcmpText(d[0], d[1]) : $"ICMPv6 type={d[0]} code={d[1]}";
                }
                if (d.Length > 8) p.Payload = d[8..].ToArray();
                break;
            default:
                p.Transport = TransportProtocol.Other;
                p.ProtocolName = proto switch
                {
                    2 => "IGMP",
                    47 => "GRE",
                    50 => "ESP",
                    51 => "AH",
                    89 => "OSPF",
                    132 => "SCTP",
                    _ => $"IP proto {proto}",
                };
                break;
        }
    }

    static void DecodeTcp(PacketRecord p, ReadOnlySpan<byte> d)
    {
        p.Transport = TransportProtocol.Tcp;
        p.ProtocolName = "TCP";
        if (d.Length < 20) return;
        p.SrcPort = BinaryPrimitives.ReadUInt16BigEndian(d);
        p.DstPort = BinaryPrimitives.ReadUInt16BigEndian(d[2..]);
        p.Seq = BinaryPrimitives.ReadUInt32BigEndian(d[4..]);
        p.Ack = BinaryPrimitives.ReadUInt32BigEndian(d[8..]);
        int off = (d[12] >> 4) * 4;
        p.Flags = (TcpFlags)(d[13] | ((d[12] & 1) << 8));
        p.Window = BinaryPrimitives.ReadUInt16BigEndian(d[14..]);
        if (off >= 20 && off <= d.Length) p.Payload = d[off..].ToArray();
        p.Info = $"{p.SrcPort} → {p.DstPort} [{p.Flags.ToText()}] Seq={p.Seq} Win={p.Window} Len={p.Payload.Length}";
    }

    static void DecodeUdp(PacketRecord p, ReadOnlySpan<byte> d)
    {
        p.Transport = TransportProtocol.Udp;
        p.ProtocolName = "UDP";
        if (d.Length < 8) return;
        p.SrcPort = BinaryPrimitives.ReadUInt16BigEndian(d);
        p.DstPort = BinaryPrimitives.ReadUInt16BigEndian(d[2..]);
        int len = BinaryPrimitives.ReadUInt16BigEndian(d[4..]);
        int end = len >= 8 ? Math.Min(len, d.Length) : d.Length;
        p.Payload = d[8..end].ToArray();
        p.Info = $"{p.SrcPort} → {p.DstPort} Len={p.Payload.Length}";
    }

    static void DecodeArp(PacketRecord p, ReadOnlySpan<byte> d)
    {
        p.Network = "ARP";
        p.ProtocolName = "ARP";
        p.Transport = TransportProtocol.Arp;
        if (d.Length < 28 || d[4] != 6 || d[5] != 4) return;
        int op = BinaryPrimitives.ReadUInt16BigEndian(d[6..]);
        var arp = new ArpInfo(op, Mac(d.Slice(8, 6)), Ip4(d.Slice(14, 4)), Mac(d.Slice(18, 6)), Ip4(d.Slice(24, 4)));
        p.Arp = arp;
        p.Info = op switch
        {
            1 when arp.SenderIp == arp.TargetIp => $"Gratuitous ARP {arp.SenderIp} ({arp.SenderMac})",
            1 => $"Who has {arp.TargetIp}? Tell {arp.SenderIp}",
            2 => $"{arp.SenderIp} is at {arp.SenderMac}",
            _ => $"ARP op={op}",
        };
    }

    static string IcmpText(byte type, byte code) => type switch
    {
        0 => "Echo reply",
        8 => "Echo request",
        3 => code switch
        {
            0 => "목적지 도달 불가 (네트워크)",
            1 => "목적지 도달 불가 (호스트)",
            3 => "목적지 도달 불가 (포트)",
            13 => "목적지 도달 불가 (관리상 차단)",
            _ => $"목적지 도달 불가 (code {code})",
        },
        5 => "Redirect",
        11 => "TTL 초과",
        _ => $"ICMP type={type} code={code}",
    };

    static string Mac(ReadOnlySpan<byte> b) =>
        $"{b[0]:x2}:{b[1]:x2}:{b[2]:x2}:{b[3]:x2}:{b[4]:x2}:{b[5]:x2}";

    static string Ip4(ReadOnlySpan<byte> b) => $"{b[0]}.{b[1]}.{b[2]}.{b[3]}";
}
