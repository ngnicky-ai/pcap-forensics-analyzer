using System.Buffers.Binary;
using PcapForensics.Core.Pcap;

namespace PcapForensics.Tests;

public class PcapReaderTests
{
    [Fact]
    public void ClassicPcap_LittleEndianMicroseconds()
    {
        var file = Bytes.ClassicPcap(1, (1_500_000_000, 123_456, new byte[] { 1, 2, 3 }), (1_500_000_001, 0, new byte[] { 4 }));

        var frames = PcapFileReader.Read(new MemoryStream(file)).ToList();

        Assert.Equal(2, frames.Count);
        Assert.Equal(1, frames[0].LinkType);
        Assert.Equal(new byte[] { 1, 2, 3 }, frames[0].Data);
        Assert.Equal(DateTime.UnixEpoch.AddSeconds(1_500_000_000).AddTicks(1_234_560), frames[0].Timestamp);
        Assert.Equal(2, frames[1].Index);
    }

    [Fact]
    public void ClassicPcap_BigEndianNanoseconds()
    {
        using var ms = new MemoryStream();
        void U32(uint v) { var b = new byte[4]; BinaryPrimitives.WriteUInt32BigEndian(b, v); ms.Write(b); }
        void U16(ushort v) { var b = new byte[2]; BinaryPrimitives.WriteUInt16BigEndian(b, v); ms.Write(b); }
        U32(0xA1B23C4D); U16(2); U16(4); U32(0); U32(0); U32(65535); U32(101);
        U32(10); U32(123_456_789); U32(2); U32(2); ms.Write(new byte[] { 0x45, 0x00 });

        var frame = Assert.Single(PcapFileReader.Read(new MemoryStream(ms.ToArray())));

        Assert.Equal(101, frame.LinkType);
        Assert.Equal(DateTime.UnixEpoch.AddSeconds(10).AddTicks(1_234_567), frame.Timestamp);
    }

    [Fact]
    public void TruncatedLastFrame_ReturnsCompleteFramesAndWarns()
    {
        var file = Bytes.ClassicPcap(1, (1, 0, new byte[10]), (2, 0, new byte[10]));
        var cut = file[..^4];
        var warnings = new List<string>();

        var frames = PcapFileReader.Read(new MemoryStream(cut), warnings).ToList();

        Assert.Single(frames);
        Assert.Single(warnings);
    }

    [Fact]
    public void PcapNg_UsesInterfaceTimestampResolution()
    {
        using var ms = new MemoryStream();
        var w = new BinaryWriter(ms);
        // Section Header Block
        w.Write(0x0A0D0D0Au); w.Write(28u); w.Write(0x1A2B3C4Du); w.Write((ushort)1); w.Write((ushort)0); w.Write(-1L); w.Write(28u);
        // Interface Description Block: linktype 1, if_tsresol = 9 (나노초)
        w.Write(1u); w.Write(32u); w.Write((ushort)1); w.Write((ushort)0); w.Write(65535u);
        w.Write((ushort)9); w.Write((ushort)1); w.Write(new byte[] { 9, 0, 0, 0 }); w.Write(0u); w.Write(32u);
        // Enhanced Packet Block: 1초 + 500ns, 데이터 3바이트(4바이트 패딩)
        ulong ts = 1_000_000_500;
        w.Write(6u); w.Write(36u); w.Write(0u); w.Write((uint)(ts >> 32)); w.Write((uint)ts); w.Write(3u); w.Write(3u);
        w.Write(new byte[] { 0xAA, 0xBB, 0xCC, 0x00 }); w.Write(36u);

        var frame = Assert.Single(PcapFileReader.Read(new MemoryStream(ms.ToArray())));

        Assert.Equal(1, frame.LinkType);
        Assert.Equal(new byte[] { 0xAA, 0xBB, 0xCC }, frame.Data);
        Assert.Equal(DateTime.UnixEpoch.AddSeconds(1).AddTicks(5), frame.Timestamp);
    }

    [Fact]
    public void UnknownFormat_Throws()
    {
        Assert.Throws<InvalidDataException>(() => PcapFileReader.Read(new MemoryStream(Bytes.Ascii("not a pcap file"))).ToList());
    }
}
