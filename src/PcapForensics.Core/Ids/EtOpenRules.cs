using System.Formats.Tar;
using System.IO.Compression;

namespace PcapForensics.Core.Ids;

/// <summary>
/// Proofpoint ET Open 룰셋(무료)을 내려받아 %LocalAppData%\PcapForensics\et-open\rules 에 둔다.
/// Suricata.RulesPath 가 비어 있으면 Suricata 검사 시 이 룰을 사용한다.
/// (Windows 에는 suricata-update 가 기본 제공되지 않으므로 이를 대신한다.)
/// </summary>
public static class EtOpenRules
{
    public const string DefaultUrl = "https://rules.emergingthreats.net/open/suricata-7.0.3/emerging.rules.tar.gz";

    public static string BaseDirectory { get; set; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "PcapForensics", "et-open");

    public static string RulesDirectory => Path.Combine(BaseDirectory, "rules");
    static string StampFile => Path.Combine(BaseDirectory, "updated.txt");

    public static bool IsInstalled => Directory.Exists(RulesDirectory) && Directory.EnumerateFiles(RulesDirectory, "*.rules").Any();

    public static DateTime? UpdatedAt => File.Exists(StampFile) ? File.GetLastWriteTimeUtc(StampFile) : null;

    public static string Status => IsInstalled
        ? $"ET Open 룰 설치됨 ({TimeFormat.Format(UpdatedAt)} UTC 갱신)"
        : "ET Open 룰 미설치";

    /// <summary>룰셋을 내려받아 교체한다. 반환값: (룰 파일 수, 활성 룰 수).</summary>
    public static async Task<(int Files, int Rules)> DownloadAsync(string? url = null, IProgress<string>? log = null, CancellationToken ct = default)
    {
        url = string.IsNullOrWhiteSpace(url) ? DefaultUrl : url;
        Directory.CreateDirectory(BaseDirectory);
        var archive = Path.Combine(BaseDirectory, "download.tar.gz");
        var staging = Path.Combine(BaseDirectory, "rules.new");

        log?.Report($"ET Open 룰 다운로드 중: {url}");
        using (var http = new HttpClient { Timeout = TimeSpan.FromMinutes(5) })
        {
            http.DefaultRequestHeaders.UserAgent.ParseAdd("PcapForensics/1.0");
            using var resp = await http.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, ct);
            resp.EnsureSuccessStatusCode();
            await using var src = await resp.Content.ReadAsStreamAsync(ct);
            await using var dst = File.Create(archive);
            await src.CopyToAsync(dst, ct);
        }

        log?.Report("룰 압축 해제 중");
        if (Directory.Exists(staging)) Directory.Delete(staging, true);
        Directory.CreateDirectory(staging);
        int files = 0, rules = 0;
        await using (var fs = File.OpenRead(archive))
        await using (var gz = new GZipStream(fs, CompressionMode.Decompress))
        {
            var tar = new TarReader(gz);
            TarEntry? entry;
            while ((entry = await tar.GetNextEntryAsync(cancellationToken: ct)) is not null)
            {
                if (entry.EntryType is not (TarEntryType.RegularFile or TarEntryType.V7RegularFile) || entry.DataStream is null) continue;
                var name = Path.GetFileName(entry.Name);
                if (!name.EndsWith(".rules", StringComparison.OrdinalIgnoreCase)) continue;

                var target = Path.Combine(staging, name);
                using (var reader = new StreamReader(entry.DataStream, Encoding.UTF8, leaveOpen: true)) // TarReader 가 다음 항목으로 넘어갈 때 스트림을 사용
                {
                    var text = await reader.ReadToEndAsync(ct);
                    rules += text.Split('\n').Count(l => l.StartsWith("alert ", StringComparison.Ordinal) || l.StartsWith("drop ", StringComparison.Ordinal));
                    await File.WriteAllTextAsync(target, text, ct);
                }
                files++;
            }
        }
        if (files == 0) throw new InvalidDataException("내려받은 파일에 .rules 가 없습니다. URL 을 확인하십시오.");

        if (Directory.Exists(RulesDirectory)) Directory.Delete(RulesDirectory, true);
        Directory.Move(staging, RulesDirectory);
        File.Delete(archive);
        await File.WriteAllTextAsync(StampFile, $"{url}\n{DateTime.UtcNow:O}\n", ct);
        log?.Report($"ET Open 룰 {files}개 파일, 활성 룰 {rules:N0}개 설치 완료");
        return (files, rules);
    }
}
