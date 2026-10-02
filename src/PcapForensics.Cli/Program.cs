using System.Text;
using PcapForensics.Core.Analysis;
using PcapForensics.Core.Detection;
using PcapForensics.Core.Model;
using PcapForensics.Core.Reporting;
using PcapForensics.Core.Util;

Console.OutputEncoding = Encoding.UTF8;

string? pcap = null, ioc = null, html = null, csv = null, extract = null, eve = null;
bool verbose = false, suricata = false, updateRules = false;
int? sessionId = null;
for (int i = 0; i < args.Length; i++)
{
    string Next() => i + 1 < args.Length ? args[++i] : throw new ArgumentException($"{args[i]} 옵션에 값이 필요합니다.");
    switch (args[i])
    {
        case "--ioc": ioc = Next(); break;
        case "--html": html = Next(); break;
        case "--csv": csv = Next(); break;
        case "--extract": extract = Next(); break;
        case "--eve": eve = Next(); break;
        case "--suricata": suricata = true; break;
        case "--update-rules": updateRules = true; break;
        case "-v": case "--verbose": verbose = true; break;
        case "--session": sessionId = int.Parse(Next()); break;
        case "-h": case "--help": pcap = null; i = args.Length; break;
        default: pcap = args[i]; break;
    }
}

if (updateRules)
{
    try
    {
        var settings = PcapForensics.Core.Detection.RuleLoader.LoadSettings();
        var (files, rules) = await PcapForensics.Core.Ids.EtOpenRules.DownloadAsync(settings.Suricata.EtOpenUrl, new Progress<string>(Console.WriteLine));
        Console.WriteLine($"설치 위치: {PcapForensics.Core.Ids.EtOpenRules.RulesDirectory} (파일 {files}개, 활성 룰 {rules:N0}개)");
    }
    catch (Exception ex) when (ex is HttpRequestException or IOException or InvalidDataException or TaskCanceledException)
    {
        Console.Error.WriteLine($"룰 다운로드 실패: {ex.Message}");
        return 1;
    }
    if (pcap is null) return 0;
}

if (pcap is null)
{
    Console.WriteLine("""
        PCAP 침해사고 분석기 (CLI)

        사용법: pcapir <파일.pcap|pcapng> [옵션]
          --ioc <파일>        IOC 목록(IP/도메인/해시)과 대조
          --html <파일>       HTML 보고서 저장
          --csv <폴더>        CSV 내보내기
          --extract <폴더>    전송된 파일 추출
          -v, --verbose       세션/인증 정보/추출 파일 상세 출력
          --session <번호>    해당 세션의 재조립된 스트림 내용 출력
          --suricata          설치된 Suricata 로 검사해 경보를 합침 (rules\settings.json 의 Suricata 설정 사용)
          --eve <eve.json>    다른 장비에서 만든 Suricata eve.json 경보를 합침
          --update-rules      ET Open 룰셋을 내려받음 (PCAP 없이 단독 실행 가능)

        종료 코드: 0 = 심각/높음 탐지 없음, 2 = 심각/높음 탐지 있음, 1 = 오류
        """);
    return 1;
}

try
{
    var analyzer = new PcapAnalyzer();
    if (ioc is not null) analyzer.Iocs = IocSet.LoadFromFile(ioc);

    var r = analyzer.Analyze(pcap, new ConsoleProgress());
    Console.Write("\r" + new string(' ', 70) + "\r");
    if (suricata || analyzer.Settings.Suricata.AutoRun)
    {
        Console.Write("  Suricata 검사 중...");
        try
        {
            await analyzer.RunSuricataAsync(r);
            Console.WriteLine(" 완료");
        }
        catch (Exception ex) when (ex is FileNotFoundException or InvalidOperationException or TimeoutException or DirectoryNotFoundException)
        {
            Console.WriteLine();
            r.Warnings.Add("Suricata 검사 실패: " + ex.Message);
        }
    }
    if (eve is not null) analyzer.ImportEve(r, eve);
    var st = r.Statistics;

    Section("분석 대상");
    Console.WriteLine($"  파일      : {r.FileName} ({TimeFormat.Bytes(r.FileSize)})");
    Console.WriteLine($"  SHA-256   : {r.FileSha256}");
    Console.WriteLine($"  캡처 기간 : {TimeFormat.Format(st.Start)} ~ {TimeFormat.Format(st.End)} UTC ({TimeFormat.Duration(st.Duration)})");
    Console.WriteLine($"  패킷      : {st.PacketCount:N0}개 / {TimeFormat.Bytes(st.TotalBytes)}, 고유 IP {st.UniqueIpCount}개");
    Console.WriteLine($"  세션      : TCP {st.TcpSessionCount:N0}, UDP {st.UdpSessionCount:N0}");
    Console.WriteLine($"  추출      : HTTP {r.Http.Count:N0}, DNS {r.Dns.Count:N0}, TLS {r.Tls.Count:N0}, 인증 {r.Credentials.Count:N0}, FTP 명령 {r.FtpCommands.Count:N0}, 파일 {r.Files.Count:N0}");
    Console.WriteLine($"  프로토콜  : {string.Join(", ", st.Protocols.Select(p => $"{p.Name} {p.Value:N0}"))}");
    Console.WriteLine($"  분석 시간 : {r.AnalysisTime.TotalSeconds:F2}초");
    if (r.IdsSource.Length > 0) Console.WriteLine($"  IDS 검사  : {r.IdsSource}, 경보 {r.IdsAlerts.Count(a => !a.Ignored):N0}건 (제외 {r.IdsAlerts.Count(a => a.Ignored):N0}건)");
    foreach (var w in r.Warnings) Console.WriteLine($"  [경고] {w}");

    Section($"탐지 결과 ({r.Findings.Count}건: 심각 {r.CountBySeverity(Severity.Critical)}, 높음 {r.CountBySeverity(Severity.High)}, 보통 {r.CountBySeverity(Severity.Medium)}, 낮음 {r.CountBySeverity(Severity.Low)})");
    foreach (var f in r.Findings)
    {
        var color = f.Severity switch
        {
            Severity.Critical => ConsoleColor.Red,
            Severity.High => ConsoleColor.DarkYellow,
            Severity.Medium => ConsoleColor.Yellow,
            _ => ConsoleColor.Gray,
        };
        Console.ForegroundColor = color;
        Console.Write($"  [{f.SeverityText}] ");
        Console.ResetColor();
        Console.WriteLine($"#{f.Id} {f.Title}");
        Console.WriteLine($"      {f.Description}");
        Console.WriteLine($"      {f.FirstSeenText} ~ {f.LastSeenText} | {f.Mitre}");
        foreach (var e in f.Evidence.Take(verbose ? 20 : 4)) Console.WriteLine($"      - {TextUtil.Truncate(e, 220)}");
    }

    if (st.TopDomains.Count > 0)
    {
        Section("질의 상위 도메인");
        foreach (var d in st.TopDomains) Console.WriteLine($"  {d.Value,6:N0}  {d.Name}");
    }

    if (verbose)
    {
        Section("인증 정보");
        foreach (var c in r.Credentials.Take(50))
            Console.WriteLine($"  {c.TimeText} {c.Protocol,-12} {c.ClientIp} → {c.ServerIp}:{c.ServerPort}  {c.Username} / {c.Password}  [{c.ResultText}] 세션#{c.SessionId}");
        Section("추출 파일");
        foreach (var f in r.Files)
            Console.WriteLine($"  #{f.Id,-4} {f.TimeText} {f.Kind,-18} {f.SizeText,10} H={f.Entropy:F2} {TextUtil.Truncate(f.Location, 90)}");
        Section("FTP 명령");
        foreach (var c in r.FtpCommands.Take(50))
            Console.WriteLine($"  {c.TimeText} {c.ClientIp} → {c.ServerIp} {c.Command} {c.Argument} → {c.ReplyCode} data={c.DataSessionId} {c.DataBytes}B");
    }

    if (sessionId is int sid && r.Sessions.FirstOrDefault(s => s.Id == sid) is { } ses)
    {
        Section($"세션 #{ses.Id} {ses.TransportText} {ses.ClientEndpoint} → {ses.ServerEndpoint} [{ses.AppProtocol}] {ses.State}, 패킷 {ses.Packets}");
        Console.WriteLine($"  --- 클라이언트 → 서버 ({TimeFormat.Bytes(ses.ClientBytes)}, 손실 구간 {ses.ClientData.Gaps}) ---");
        Console.WriteLine(TextUtil.ToPrintable(ses.ClientData.Data, 8192));
        Console.WriteLine($"  --- 서버 → 클라이언트 ({TimeFormat.Bytes(ses.ServerBytes)}, 손실 구간 {ses.ServerData.Gaps}) ---");
        Console.WriteLine(TextUtil.ToPrintable(ses.ServerData.Data, 8192));
    }

    if (html is not null) { HtmlReportWriter.Write(r, html); Console.WriteLine($"\nHTML 보고서: {Path.GetFullPath(html)}"); }
    if (csv is not null) { var files = CsvExporter.ExportAll(r, csv); Console.WriteLine($"CSV {files.Count}개: {Path.GetFullPath(csv)}"); }
    if (extract is not null) { int n = ObjectExporter.ExportAll(r.Files, extract); Console.WriteLine($"파일 {n}개 추출: {Path.GetFullPath(extract)}"); }

    return r.Findings.Any(f => f.Severity >= Severity.High) ? 2 : 0;
}
catch (Exception ex) when (ex is IOException or InvalidDataException or UnauthorizedAccessException or ArgumentException)
{
    Console.Error.WriteLine($"오류: {ex.Message}");
    return 1;
}

static void Section(string title)
{
    Console.WriteLine();
    Console.ForegroundColor = ConsoleColor.Cyan;
    Console.WriteLine($"■ {title}");
    Console.ResetColor();
}

sealed class ConsoleProgress : IProgress<AnalysisProgress>
{
    public void Report(AnalysisProgress value) => Console.Write($"\r  [{value.Percent,5:F1}%] {value.Stage}".PadRight(70));
}
