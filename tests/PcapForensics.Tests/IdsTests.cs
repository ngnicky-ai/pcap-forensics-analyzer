using PcapForensics.Core.Ids;

namespace PcapForensics.Tests;

public class EveJsonReaderTests
{
    static string Fixture => Path.Combine(AppContext.BaseDirectory, "TestData", "02_eve.json");

    [Fact]
    public void ReadsAlertsOnly_AndReportsBadLines()
    {
        var warnings = new List<string>();

        var alerts = EveJsonReader.Read(Fixture, warnings);

        Assert.Equal(4, alerts.Count);
        Assert.Single(warnings);
        var a = alerts[0];
        Assert.Equal(9000001, a.Sid);
        Assert.Equal(1, a.Priority);
        Assert.Equal("192.168.206.152", a.SrcIp);
        Assert.Equal(44992, a.SrcPort);
        Assert.Equal("T1505 Server Software Component", a.Mitre);
        Assert.Equal("POST 192.168.206.133/attack/shell.jsp → 200", a.Detail);
        Assert.Equal(new DateTime(2017, 11, 23, 12, 29, 7, DateTimeKind.Utc).AddTicks(5_651_230), a.Time);
        Assert.Equal("DNS evil.example", alerts[3].Detail);
    }

    [Theory]
    [InlineData("2015-08-31T17:58:21.970123+0000", "2015-08-31T17:58:21.9701230Z")]
    [InlineData("2015-08-31T19:58:21.000000+0200", "2015-08-31T17:58:21.0000000Z")]
    [InlineData("2015-08-31T17:58:21.5+00:00", "2015-08-31T17:58:21.5000000Z")]
    public void ParsesTimestampOffsets(string input, string expectedUtc) =>
        Assert.Equal(DateTime.Parse(expectedUtc).ToUniversalTime(), EveJsonReader.ParseTime(input));
}

public class IdsAlertProcessorTests
{
    static IdsAlert Alert(string sig, int priority, long sid = 1) => new() { Signature = sig, Priority = priority, Sid = sid };

    [Fact]
    public void MapsPriority_EscalatesKeywords_AndAppliesIgnoreLists()
    {
        var o = new SuricataOptions { IgnoreSids = new long[] { 42 } };
        var alerts = new[]
        {
            Alert("ET POLICY curl User-Agent", 2),
            Alert("ET EXPLOIT_KIT Angler Landing", 1),
            Alert("ET MALWARE Something CnC Beacon", 2),
            Alert("SURICATA STREAM ESTABLISHED invalid ack", 3),
            Alert("ET INFO noisy rule", 3, sid: 42),
        };

        IdsAlertProcessor.Classify(alerts, o);

        Assert.Equal(Severity.Medium, alerts[0].Severity);
        Assert.Equal(Severity.Critical, alerts[1].Severity);
        Assert.Equal(Severity.High, alerts[2].Severity);
        Assert.True(alerts[3].Ignored);
        Assert.True(alerts[4].Ignored);
        Assert.False(alerts[0].Ignored);
    }
}

public class SuricataRunnerTests
{
    [Fact]
    public void BuildArguments_ContainsOfflineOptionsHomeNetAndRules()
    {
        var o = new SuricataOptions { HomeNet = "[10.0.0.0/8]", ExtraArguments = "--set \"logging.outputs.0.console.enabled=no\" -v" };

        var args = SuricataRunner.BuildArguments(@"C:\cap\a.pcap", @"C:\out", @"C:\nowhere\suricata.exe", o, @"C:\out\combined.rules");

        Assert.Equal(new[] { "-r", @"C:\cap\a.pcap", "-l", @"C:\out", "-k", "none" }, args.Take(6));
        Assert.Contains("vars.address-groups.HOME_NET=[10.0.0.0/8]", args);
        Assert.Equal(@"C:\out\combined.rules", args[args.IndexOf("-S") + 1]);
        Assert.Contains("logging.outputs.0.console.enabled=no", args);
        Assert.Equal("-v", args[^1]);
        Assert.DoesNotContain("-c", args); // 존재하지 않는 suricata.yaml 은 전달하지 않음
    }

    [Fact]
    public void FindExecutable_ConfiguredPathMissing_ReturnsNull() =>
        Assert.Null(SuricataRunner.FindExecutable(@"C:\definitely\missing\suricata.exe"));

    [Fact]
    public void ParsesVersionAndRuleCountFromLog()
    {
        const string log = "1/10/2026 -- 10:00:00 - <Notice> - This is Suricata version 7.0.6 RELEASE running in USER mode\n" +
                           "1/10/2026 -- 10:00:05 - <Info> - 1 rule files processed. 48211 rules successfully loaded, 3 rules failed";

        Assert.Equal("7.0.6", SuricataRunner.ParseVersion(log));
        Assert.Equal("룰 48,211개 로드 (실패 3개)", SuricataRunner.ParseRules(log));
    }
}
