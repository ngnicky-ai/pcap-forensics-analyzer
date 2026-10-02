using PcapForensics.Core.Detection;

namespace PcapForensics.Tests;

public class IocSetTests
{
    [Fact]
    public void ParsesDefangedValuesCidrUrlsAndHashes()
    {
        var set = IocSet.Parse(new[]
        {
            "# 주석",
            "evil[.]example # C2",
            "hxxp://bad.example.net/payload.exe",
            "198.51.100.0/24, 악성 대역",
            "203.0.113.5:8080",
            "44D88612FEA8A8F36DE82E1278ABB02F",
        });

        Assert.True(set.TryMatchDomain("a.b.EVIL.example.", out var matched, out var comment));
        Assert.Equal(("evil.example", "C2"), (matched, comment));
        Assert.True(set.TryMatchDomain("bad.example.net", out _, out _));
        Assert.False(set.TryMatchDomain("notevil.example", out _, out _));
        Assert.True(set.TryMatchIp("198.51.100.77", out var net, out _));
        Assert.Equal("198.51.100.0/24", net);
        Assert.False(set.TryMatchIp("198.51.101.1", out _, out _));
        Assert.True(set.TryMatchIp("203.0.113.5", out _, out _));
        Assert.True(set.TryMatchHash("44d88612fea8a8f36de82e1278abb02f", out _));
    }
}

public class FileTypeDetectorTests
{
    static byte[] Pe(bool dll)
    {
        var d = new byte[0x200];
        d[0] = (byte)'M'; d[1] = (byte)'Z';
        d[0x3C] = 0x80;
        "PE\0\0"u8.CopyTo(d.AsSpan(0x80));
        if (dll) d[0x80 + 23] = 0x20; // Characteristics 0x2000
        return d;
    }

    [Theory]
    [InlineData("exe", "PE 실행 파일(EXE)", FileCategory.Executable)]
    [InlineData("dll", "PE DLL", FileCategory.Executable)]
    [InlineData("swf", "Flash(SWF)", FileCategory.ActiveContent)]
    [InlineData("eot", "EOT 글꼴", FileCategory.Font)]
    [InlineData("jar", "Java JAR", FileCategory.ActiveContent)]
    [InlineData("html", "HTML", FileCategory.Web)]
    public void DetectsByMagicBytes(string sample, string kind, FileCategory category)
    {
        byte[] data = sample switch
        {
            "exe" => Pe(false),
            "dll" => Pe(true),
            "swf" => Bytes.Ascii("CWS\u000a....compressed"),
            "eot" => Enumerable.Range(0, 64).Select(i => i == 34 ? (byte)0x4C : i == 35 ? (byte)0x50 : (byte)7).ToArray(),
            "jar" => Bytes.Ascii("PK\u0003\u0004....META-INF/MANIFEST.MF"),
            _ => Bytes.Ascii("  <!DOCTYPE html><html><body>hi</body></html>"),
        };

        var (k, c) = FileTypeDetector.Detect(data);

        Assert.Equal(kind, k);
        Assert.Equal(category, c);
    }

    [Fact]
    public void RandomBytes_AreUnknownWithHighEntropy()
    {
        var data = new byte[32 * 1024];
        new Random(1).NextBytes(data);
        data[0] = 0x13; // 우연한 매직 바이트 방지

        Assert.Equal(FileCategory.Unknown, FileTypeDetector.Detect(data).Category);
        Assert.True(EntropyUtil.Shannon(data) > 7.9);
    }
}

public class DomainUtilTests
{
    [Theory]
    [InlineData("a.b.example.com", "example.com")]
    [InlineData("www.naver.co.kr.", "naver.co.kr")]
    [InlineData("localhost", "localhost")]
    public void BaseDomain(string name, string expected) => Assert.Equal(expected, DomainUtil.BaseDomain(name));
}
