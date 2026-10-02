using System.Diagnostics;
using System.Text.RegularExpressions;

namespace PcapForensics.Core.Ids;

/// <summary>rules\settings.json 의 "Suricata" 항목.</summary>
public sealed class SuricataOptions
{
    /// <summary>suricata.exe 경로. 비우면 PATH 와 기본 설치 경로에서 찾는다.</summary>
    public string ExecutablePath { get; set; } = "";
    /// <summary>suricata.yaml 경로. 비우면 실행 파일 옆의 suricata.yaml 을 사용한다.</summary>
    public string ConfigPath { get; set; } = "";
    /// <summary>룰 파일(.rules) 또는 룰 폴더. 비우면 내려받은 ET Open 룰, 그것도 없으면 suricata.yaml 설정을 따른다.</summary>
    public string RulesPath { get; set; } = "";
    public string HomeNet { get; set; } = "[10.0.0.0/8,172.16.0.0/12,192.168.0.0/16]";
    public string ExtraArguments { get; set; } = "";
    public int TimeoutSeconds { get; set; } = 900;
    /// <summary>[ET Open 룰 받기] 에서 사용할 주소.</summary>
    public string EtOpenUrl { get; set; } = EtOpenRules.DefaultUrl;
    /// <summary>PCAP 분석 직후 Suricata 를 자동으로 실행할지 여부.</summary>
    public bool AutoRun { get; set; }

    /// <summary>Suricata 우선순위(1~4) → 분석기 심각도.</summary>
    public Dictionary<int, Severity> SeverityMap { get; set; } = new()
    {
        [1] = Severity.High, [2] = Severity.Medium, [3] = Severity.Low, [4] = Severity.Info,
    };

    /// <summary>시그니처에 포함되면 심각도를 한 단계 올리는 키워드.</summary>
    public string[] EscalateKeywords { get; set; } = { "EXPLOIT_KIT", "MALWARE", "TROJAN", "CnC", "Ransomware", "WebShell", "Web Shell" };

    /// <summary>오탐 관리: 제외할 sid 목록.</summary>
    public long[] IgnoreSids { get; set; } = Array.Empty<long>();
    /// <summary>오탐 관리: 이 문자열로 시작하는 시그니처 제외(프로토콜 이상 이벤트 등).</summary>
    public string[] IgnoreSignaturePrefixes { get; set; } = { "SURICATA STREAM", "SURICATA TCPv4 invalid checksum", "SURICATA UDPv4 invalid checksum" };
}

public sealed record SuricataRunResult(string EvePath, string OutputDirectory, string Version, string RulesSummary, string Log, TimeSpan Elapsed);

/// <summary>설치된 Suricata 로 PCAP 을 오프라인 검사하고 eve.json 경로를 돌려준다.</summary>
public static class SuricataRunner
{
    static readonly string[] DefaultLocations =
    {
        @"C:\Program Files\Suricata\suricata.exe",
        @"C:\Program Files (x86)\Suricata\suricata.exe",
        "/usr/bin/suricata",
        "/usr/local/bin/suricata",
    };

    public static string? FindExecutable(string? configured)
    {
        if (!string.IsNullOrWhiteSpace(configured)) return File.Exists(configured) ? configured : null;

        var names = OperatingSystem.IsWindows() ? new[] { "suricata.exe" } : new[] { "suricata" };
        foreach (var dir in (Environment.GetEnvironmentVariable("PATH") ?? "").Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries))
        {
            foreach (var n in names)
            {
                var p = Path.Combine(dir.Trim('"'), n);
                if (File.Exists(p)) return p;
            }
        }
        return DefaultLocations.FirstOrDefault(File.Exists);
    }

    /// <summary>Suricata 명령줄 인수. 룰 폴더는 하나의 임시 파일로 합쳐 -S 로 전달한다.</summary>
    public static List<string> BuildArguments(string pcap, string outDir, string exePath, SuricataOptions o, string? combinedRules)
    {
        var args = new List<string> { "-r", pcap, "-l", outDir, "-k", "none", "--runmode", "single" };

        var config = !string.IsNullOrWhiteSpace(o.ConfigPath)
            ? o.ConfigPath
            : Path.Combine(Path.GetDirectoryName(exePath) ?? "", "suricata.yaml");
        if (File.Exists(config)) args.AddRange(new[] { "-c", config });

        if (combinedRules is not null) args.AddRange(new[] { "-S", combinedRules });
        if (!string.IsNullOrWhiteSpace(o.HomeNet)) args.AddRange(new[] { "--set", $"vars.address-groups.HOME_NET={o.HomeNet}" });
        args.AddRange(SplitArgs(o.ExtraArguments));
        return args;
    }

    public static async Task<SuricataRunResult> RunAsync(string pcap, SuricataOptions o, IProgress<string>? log = null, CancellationToken ct = default)
    {
        var exe = FindExecutable(o.ExecutablePath)
                  ?? throw new FileNotFoundException("Suricata 실행 파일을 찾을 수 없습니다. 설치하거나 rules\\settings.json 의 Suricata.ExecutablePath 를 지정하십시오.");

        var outDir = Path.Combine(Path.GetTempPath(), "PcapForensics", "suricata_" + DateTime.Now.ToString("yyyyMMdd_HHmmss_fff"));
        Directory.CreateDirectory(outDir);
        var rulesPath = !string.IsNullOrWhiteSpace(o.RulesPath) ? o.RulesPath : EtOpenRules.IsInstalled ? EtOpenRules.RulesDirectory : "";
        string? rules = PrepareRules(rulesPath, outDir);

        var psi = new ProcessStartInfo(exe)
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
            WorkingDirectory = Path.GetDirectoryName(exe) ?? outDir,
        };
        foreach (var a in BuildArguments(Path.GetFullPath(pcap), outDir, exe, o, rules)) psi.ArgumentList.Add(a);
        // Windows 판 Suricata 는 wpcap.dll 이 필요하다. Npcap 을 WinPcap 호환 모드 없이 설치한 경우를 위해 Npcap 폴더를 PATH 에 추가
        if (OperatingSystem.IsWindows())
        {
            var npcap = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "Npcap");
            if (Directory.Exists(npcap)) psi.Environment["PATH"] = npcap + Path.PathSeparator + (psi.Environment["PATH"] ?? "");
        }

        var sw = Stopwatch.StartNew();
        var output = new StringBuilder();
        using var proc = new Process { StartInfo = psi, EnableRaisingEvents = true };
        void OnLine(string? line)
        {
            if (line is null) return;
            lock (output) output.AppendLine(line);
            log?.Report(line);
        }
        proc.OutputDataReceived += (_, e) => OnLine(e.Data);
        proc.ErrorDataReceived += (_, e) => OnLine(e.Data);

        proc.Start();
        proc.BeginOutputReadLine();
        proc.BeginErrorReadLine();

        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(Math.Max(30, o.TimeoutSeconds)));
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct, timeout.Token);
        try
        {
            await proc.WaitForExitAsync(linked.Token);
        }
        catch (OperationCanceledException)
        {
            try { proc.Kill(entireProcessTree: true); } catch (InvalidOperationException) { }
            if (ct.IsCancellationRequested) throw;
            throw new TimeoutException($"Suricata 가 {o.TimeoutSeconds}초 안에 끝나지 않아 중단했습니다.");
        }

        string text;
        lock (output) text = output.ToString();
        var suricataLog = Path.Combine(outDir, "suricata.log");
        if (File.Exists(suricataLog)) text += File.ReadAllText(suricataLog);

        var eve = Path.Combine(outDir, "eve.json");
        if (proc.ExitCode is 53 or -1073741515 && text.Length == 0)
            throw new InvalidOperationException("Suricata 실행에 필요한 Npcap(wpcap.dll)을 찾을 수 없습니다. https://npcap.com 에서 Npcap 을 설치하십시오.");
        if (proc.ExitCode != 0 || !File.Exists(eve))
        {
            var tail = string.Join("\n", text.Split('\n').Where(l => l.Contains("Error", StringComparison.OrdinalIgnoreCase) || l.Contains("<E>")).TakeLast(8));
            throw new InvalidOperationException($"Suricata 실행 실패 (종료 코드 {proc.ExitCode}).\n{(tail.Length > 0 ? tail : TextUtil.Truncate(text, 1500))}");
        }

        return new SuricataRunResult(eve, outDir, ParseVersion(text), ParseRules(text), text, sw.Elapsed);
    }

    /// <summary>룰 폴더면 *.rules 를 하나로 합치고, 파일이면 그대로 사용한다.</summary>
    static string? PrepareRules(string rulesPath, string outDir)
    {
        if (string.IsNullOrWhiteSpace(rulesPath)) return null;
        if (File.Exists(rulesPath)) return Path.GetFullPath(rulesPath);
        if (!Directory.Exists(rulesPath)) throw new DirectoryNotFoundException($"룰 경로를 찾을 수 없습니다: {rulesPath}");

        var combined = Path.Combine(outDir, "combined.rules");
        using var w = new StreamWriter(combined, false, new UTF8Encoding(false));
        foreach (var f in Directory.EnumerateFiles(rulesPath, "*.rules", SearchOption.AllDirectories).OrderBy(f => f, StringComparer.OrdinalIgnoreCase))
        {
            w.WriteLine($"# ---- {Path.GetFileName(f)}");
            foreach (var line in File.ReadLines(f)) w.WriteLine(line);
        }
        return combined;
    }

    public static string ParseVersion(string text)
    {
        var m = Regex.Match(text, @"Suricata version (\S+)", RegexOptions.IgnoreCase);
        return m.Success ? m.Groups[1].Value : "";
    }

    public static string ParseRules(string text)
    {
        var m = Regex.Match(text, @"(\d+) rules successfully loaded, (\d+) rules failed", RegexOptions.IgnoreCase);
        return m.Success ? $"룰 {int.Parse(m.Groups[1].Value):N0}개 로드 (실패 {m.Groups[2].Value}개)" : "";
    }

    static IEnumerable<string> SplitArgs(string s)
    {
        foreach (Match m in Regex.Matches(s ?? "", @"""([^""]*)""|(\S+)"))
            yield return m.Groups[1].Success ? m.Groups[1].Value : m.Groups[2].Value;
    }
}
