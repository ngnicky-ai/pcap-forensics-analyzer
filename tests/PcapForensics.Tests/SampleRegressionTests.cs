using PcapForensics.Core.Analysis;

namespace PcapForensics.Tests;

/// <summary>
/// samples 폴더의 실제 캡처로 탐지 결과를 고정한다.
/// 탐지 규칙을 바꾼 뒤 이 테스트가 깨지면 의도한 변경인지 확인할 것.
/// </summary>
public class SampleRegressionTests : IClassFixture<SampleFixture>
{
    readonly SampleFixture _samples;

    public SampleRegressionTests(SampleFixture samples) => _samples = samples;

    [SkippableFact]
    public void FtpCrack_DetectsBruteForce_AndDropsDuplicateFrames()
    {
        var r = _samples.Analyze("ftp-crack.pcap");

        Assert.Contains(r.Warnings, w => w.Contains("중복 프레임 9,865개"));
        Assert.Equal(703, r.Credentials.Count);
        Assert.DoesNotContain(r.Credentials, c => c.Username.Length == 0);

        var brute = Assert.Single(r.Findings, f => f.Category == "계정 공격");
        Assert.Equal(Severity.High, brute.Severity);
        Assert.Equal(703, brute.Count);
        Assert.Contains("FTP 무차별 대입 공격", brute.Title);
        Assert.DoesNotContain(r.Findings, f => f.Severity == Severity.Critical);
    }

    [SkippableFact]
    public void ExploitKitExercise_DetectsInfectionChainWithoutKnownFalsePositives()
    {
        var r = _samples.Analyze("2015-08-31-traffic-analysis-exercise.pcap");

        var chain = Assert.Single(r.Findings);
        Assert.Equal(Severity.Critical, chain.Severity);
        Assert.Contains("익스플로잇 킷 감염 체인", chain.Title);
        Assert.Equal("46.108.156.181", chain.SourceIp);
        Assert.Contains(chain.Evidence, e => e.Contains("vitaminsthatrock.com"));
        Assert.Contains(chain.Evidence, e => e.Contains("확장자 위장"));

        // 과거 오탐: 일반 브라우징의 호스트 스윕, EOT 웹 글꼴의 고엔트로피 판정
        Assert.DoesNotContain(r.Findings, f => f.Title.Contains("호스트 스윕"));
        Assert.Contains(r.Files, f => f.Kind == "EOT 글꼴");
    }

    [SkippableFact]
    public void TomcatSample_DetectsWebShellChainAndDefaultCredential()
    {
        var r = _samples.Analyze("02.pcap");

        var shell = Assert.Single(r.Findings, f => f.Category == "웹셸");
        Assert.Equal(Severity.Critical, shell.Severity);
        Assert.Contains("attack.war", shell.Title);
        Assert.Contains(shell.Evidence, e => e.Contains("tomcat:tomcat"));
        Assert.Contains(r.Findings, f => f.Severity == Severity.High && f.Title.Contains("기본/취약 비밀번호") && f.Title.Contains("tomcat"));
        Assert.Contains(r.Credentials, c => c is { Protocol: "HTTP Basic", Username: "tomcat", Password: "tomcat", Result: AuthResult.Success });
    }

    [SkippableFact]
    public void TomcatSample_ImportsEveAlertsAndLinksSessions()
    {
        // 공유 캐시를 바꾸지 않도록 별도로 분석
        var analyzer = new PcapAnalyzer();
        var r = analyzer.Analyze(SampleFixture.Require("02.pcap"));
        int before = r.Findings.Count;

        analyzer.ImportEve(r, Path.Combine(AppContext.BaseDirectory, "TestData", "02_eve.json"), "테스트 eve.json");

        Assert.Equal(4, r.IdsAlerts.Count);
        var post = r.IdsAlerts.Single(a => a.Sid == 9000001);
        var response = r.IdsAlerts.Single(a => a.Sid == 9000002);
        var session = r.Sessions.Single(s => s.Id == post.SessionId);
        Assert.Equal(44992, session.ClientPort);
        Assert.Equal(post.SessionId, response.SessionId);         // 반대 방향 경보도 같은 세션
        Assert.Null(r.IdsAlerts.Single(a => a.Sid == 9000003).SessionId); // 이 캡처에 없는 흐름

        Assert.True(r.IdsAlerts.Single(a => a.Sid == 2210045).Ignored);
        Assert.Equal(Severity.Critical, post.Severity);               // 우선순위 1 + WebShell 키워드 상향

        var ids = r.Findings.Where(f => f.Category == "IDS 경보").ToList();
        Assert.Equal(3, ids.Count);                                    // 제외된 STREAM 경보는 탐지 결과에 없음
        Assert.Equal(before + 3, r.Findings.Count);
        Assert.Contains(ids, f => f.Title == "[Suricata] TEST WEB_SERVER WebShell command POST" && f.SessionIds.SequenceEqual(new[] { session.Id }));
        Assert.Contains(r.Timeline, e => e.Category == "탐지" && e.Summary.StartsWith("[Suricata]"));
    }

    /// <summary>
    /// 실제 Suricata + ET Open 룰로 검사(설치된 PC 에서만 실행, 없으면 건너뜀).
    /// 설치: winget install OISF.Suricata, 룰: pcapir --update-rules
    /// </summary>
    [SkippableFact]
    public async Task RealSuricata_IdentifiesRansomwareCncInExploitKitSample()
    {
        Skip.If(Core.Ids.SuricataRunner.FindExecutable(null) is null, "Suricata 미설치 (winget install OISF.Suricata)");
        Skip.IfNot(Core.Ids.EtOpenRules.IsInstalled, "ET Open 룰 미설치 (pcapir --update-rules)");

        var analyzer = new PcapAnalyzer();
        var r = analyzer.Analyze(SampleFixture.Require("2015-08-31-traffic-analysis-exercise.pcap"));
        var run = await analyzer.RunSuricataAsync(r);

        Assert.StartsWith("룰 ", run.RulesSummary);
        Assert.NotEmpty(r.IdsAlerts);
        Assert.All(r.IdsAlerts.Where(a => a.Proto is "TCP" or "UDP"), a => Assert.NotNull(a.SessionId));
        Assert.Contains(r.Findings, f => f.Severity == Severity.Critical && f.Title.Contains("[Suricata]") && f.Title.Contains("CnC"));
        Assert.Contains(r.Findings, f => f.Severity == Severity.Critical && f.Title.Contains("EXPLOIT_KIT"));
    }

    [SkippableFact]
    public void ImportingEveFromAnotherCapture_Warns()
    {
        var analyzer = new PcapAnalyzer();
        var r = analyzer.Analyze(SampleFixture.Require("2015-08-31-traffic-analysis-exercise.pcap"));

        analyzer.ImportEve(r, Path.Combine(AppContext.BaseDirectory, "TestData", "02_eve.json"));

        Assert.Contains(r.Warnings, w => w.Contains("세션과 하나도 일치하지 않습니다"));
    }
}
