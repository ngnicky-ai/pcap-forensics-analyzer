using System.Reflection;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace PcapForensics.Core.Detection;

/// <summary>탐지 임계값. rules\settings.json 으로 조정할 수 있다.</summary>
public sealed class DetectionSettings
{
    public int PortScanMinPorts { get; set; } = 15;
    public int PortScanMinHosts { get; set; } = 15;
    public double PortScanWindowSeconds { get; set; } = 300;

    public int BruteForceMinFailures { get; set; } = 5;
    public int BruteForceMinConnections { get; set; } = 15;
    public double BruteForceWindowSeconds { get; set; } = 300;
    public int[] AuthServicePorts { get; set; } = { 21, 22, 23, 25, 110, 143, 445, 1433, 3306, 3389, 5432, 5900 };
    public int HttpLoginMinRequests { get; set; } = 10;

    public int DnsTunnelMinUniqueSubdomains { get; set; } = 20;
    public double DnsTunnelMinAvgLength { get; set; } = 25;
    public double DnsTunnelMinEntropy { get; set; } = 3.8;
    public int DnsNxDomainThreshold { get; set; } = 10;
    public string[] DnsAllowList { get; set; } = Array.Empty<string>();

    public int BeaconMinConnections { get; set; } = 6;
    public double BeaconMinIntervalSeconds { get; set; } = 5;
    public double BeaconMaxJitterRatio { get; set; } = 0.2;
    public double BeaconMinRegularFraction { get; set; } = 0.8;
    public int[] BeaconIgnorePorts { get; set; } = { 53, 123, 137, 138, 1900, 5353, 5355 };

    public double HighEntropyThreshold { get; set; } = 7.5;
    public int HighEntropyMinBytes { get; set; } = 10240;
    public double ExploitChainWindowSeconds { get; set; } = 120;

    public Ids.SuricataOptions Suricata { get; set; } = new();
}

public sealed class PatternRule
{
    public string Name { get; set; } = "";
    public string Category { get; set; } = "웹 공격";
    public Severity Severity { get; set; } = Severity.Medium;
    public string Mitre { get; set; } = "";
    public string Recommendation { get; set; } = "";
    public string[] Patterns { get; set; } = Array.Empty<string>();

    [JsonIgnore] public Regex[] Compiled { get; private set; } = Array.Empty<Regex>();

    public void Compile() =>
        Compiled = Patterns
            .Select(p => new Regex(p, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled, TimeSpan.FromMilliseconds(250)))
            .ToArray();

    public bool TryMatch(string text, out string matched)
    {
        foreach (var r in Compiled)
        {
            try
            {
                var m = r.Match(text);
                if (m.Success) { matched = m.Value; return true; }
            }
            catch (RegexMatchTimeoutException) { }
        }
        matched = "";
        return false;
    }
}

/// <summary>웹 공격 시그니처. rules\web_attack_rules.json 으로 추가/수정할 수 있다.</summary>
public sealed class WebAttackRules
{
    public List<PatternRule> RequestRules { get; set; } = new();
    public List<PatternRule> ResponseRules { get; set; } = new();
    public string[] ScannerUserAgents { get; set; } = Array.Empty<string>();

    public void Compile()
    {
        foreach (var r in RequestRules) r.Compile();
        foreach (var r in ResponseRules) r.Compile();
    }
}

public static class RuleLoader
{
    static readonly JsonSerializerOptions Options = new()
    {
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true,
        Converters = { new JsonStringEnumConverter() },
    };

    public static DetectionSettings LoadSettings(string? path = null) =>
        Load<DetectionSettings>("settings.json", path) ?? new DetectionSettings();

    public static WebAttackRules LoadWebRules(string? path = null)
    {
        var rules = Load<WebAttackRules>("web_attack_rules.json", path) ?? new WebAttackRules();
        rules.Compile();
        return rules;
    }

    /// <summary>지정 경로 → 실행 폴더의 rules\ → 내장 기본값 순서로 찾는다.</summary>
    static T? Load<T>(string fileName, string? explicitPath) where T : class
    {
        var candidates = new[] { explicitPath, Path.Combine(AppContext.BaseDirectory, "rules", fileName) };
        foreach (var c in candidates)
        {
            if (c is not null && File.Exists(c))
                return JsonSerializer.Deserialize<T>(File.ReadAllText(c), Options);
        }

        using var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream("PcapForensics.Core.Rules." + fileName);
        return stream is null ? null : JsonSerializer.Deserialize<T>(stream, Options);
    }
}
