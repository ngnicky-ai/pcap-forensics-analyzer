using PcapForensics.Core.Analysis;
using PcapForensics.Core.Capture;
using PcapForensics.Core.Pcap;

namespace PcapForensics.Tests;

public class PcapNgWriterTests
{
    static readonly DateTime T0 = new(2026, 10, 8, 11, 5, 50, DateTimeKind.Utc);

    static string TempFile() => Path.Combine(Path.GetTempPath(), $"pf_test_{Guid.NewGuid():N}.pcapng");

    static byte[] Loopback(byte[] ip) => new byte[] { 2, 0, 0, 0 }.Concat(ip).ToArray(); // BSD Null: AF_INET(2)

    [Fact]
    public void WrittenFile_RoundTripsInterfacesLinkTypesAndTimestamps()
    {
        var path = TempFile();
        try
        {
            var eth = Bytes.Ethernet(0x0800, Bytes.IPv4("10.0.0.1", "10.0.0.2", 17, Bytes.Udp(1000, 53, new byte[3])));
            var lo = Loopback(Bytes.IPv4("127.0.0.1", "127.0.0.1", 6, Bytes.Tcp(5000, 9, 1, 0, TcpFlags.Syn)));
            using (var w = new PcapNgWriter(path))
            {
                Assert.Equal(0, w.AddInterface(1, 65535, @"\Device\NPF_{A}", "Wi-Fi"));
                Assert.Equal(1, w.AddInterface(0, 65535, @"\Device\NPF_Loopback", "루프백"));
                w.WritePacket(0, T0.AddTicks(1_234_560), eth, eth.Length);
                w.WritePacket(1, T0.AddSeconds(1), lo, 1500); // 잘린 패킷: 원래 길이 보존
                Assert.Throws<InvalidOperationException>(() => w.AddInterface(1, 100, "late", ""));
                Assert.True(w.BytesWritten > eth.Length + lo.Length);
            }

            List<RawFrame> frames;
            using (var fs = File.OpenRead(path)) frames = PcapFileReader.Read(fs).ToList();

            Assert.Equal(2, frames.Count);
            Assert.Equal((1, 0, T0.AddTicks(1_234_560)), (frames[0].LinkType, frames[0].InterfaceId, frames[0].Timestamp));
            Assert.Equal(eth, frames[0].Data);
            Assert.Equal((0, 1, 1500), (frames[1].LinkType, frames[1].InterfaceId, frames[1].OriginalLength));
            Assert.Equal(lo, frames[1].Data);
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public void Analyzer_DropsSamePacketSeenOnTwoInterfaces_ButKeepsRealRetransmission()
    {
        var path = TempFile();
        try
        {
            var ip = Bytes.IPv4("192.168.0.6", "93.184.216.34", 6, Bytes.Tcp(50000, 80, 100, 0, TcpFlags.Syn));
            using (var w = new PcapNgWriter(path))
            {
                w.AddInterface(1, 65535, "physical", "Wi-Fi");
                w.AddInterface(0, 65535, "virtual", "가상");
                var eth = Bytes.Ethernet(0x0800, ip);
                w.WritePacket(0, T0, eth, eth.Length);
                w.WritePacket(1, T0.AddMilliseconds(1), Loopback(ip), ip.Length + 4); // 다른 링크 계층, 같은 IP 패킷
                w.WritePacket(0, T0.AddSeconds(1), eth, eth.Length);                  // 같은 인터페이스 1초 뒤: SYN 재전송
            }

            var r = new PcapAnalyzer().Analyze(path);

            Assert.Equal(3, r.Packets.Count);
            Assert.Equal(new[] { false, true, false }, r.Packets.Select(p => p.IsDuplicate));
            Assert.Contains(r.Warnings, w => w.Contains("여러 인터페이스에서 같은 패킷이 중복 캡처된 1개"));
            Assert.Single(r.Sessions);
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public void CaptureSettings_DefaultPathIsTimestampedPcapngInLocalAppData()
    {
        var s = new CaptureSettings();
        var path = s.NewCapturePath();
        Assert.EndsWith(".pcapng", path);
        Assert.Contains(Path.Combine("PcapForensics", "captures"), path);
        Assert.Equal(200, s.MaxSizeMB);
    }
}
