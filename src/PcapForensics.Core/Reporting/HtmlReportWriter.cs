using System.Net;

namespace PcapForensics.Core.Reporting;

/// <summary>외부 리소스 없이 단독으로 열리는 HTML 침해사고 분석 보고서를 생성한다.</summary>
public static class HtmlReportWriter
{
    public static void Write(AnalysisResult r, string path)
    {
        File.WriteAllText(path, Render(r), new UTF8Encoding(false));
    }

    static string E(string? s) => WebUtility.HtmlEncode(s ?? "");

    public static string Render(AnalysisResult r)
    {
        var st = r.Statistics;
        var sb = new StringBuilder();
        int sec = 0;
        sb.Append("""
<!doctype html>
<html lang="ko"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>침해사고 분석 보고서</title>
<style>
:root{--bg:#f5f7fb;--panel:#fff;--text:#1e293b;--muted:#64748b;--line:#e2e8f0;--accent:#2563eb;
--crit:#b91c1c;--high:#ea580c;--med:#ca8a04;--low:#2563eb;--info:#64748b}
@media (prefers-color-scheme:dark){:root{--bg:#0f172a;--panel:#1e293b;--text:#e2e8f0;--muted:#94a3b8;--line:#334155}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:14px/1.6 "Malgun Gothic","Segoe UI",sans-serif}
main{max-width:1200px;margin:0 auto;padding:24px 16px}h1{font-size:24px;margin:0 0 4px}h2{font-size:18px;margin:32px 0 12px;border-bottom:2px solid var(--line);padding-bottom:6px}
.muted{color:var(--muted)}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:14px}.card b{display:block;font-size:22px}
table{width:100%;border-collapse:collapse;background:var(--panel);font-size:13px}th,td{border:1px solid var(--line);padding:6px 8px;text-align:left;vertical-align:top;word-break:break-all}
th{background:rgba(100,116,139,.12)}.sev{display:inline-block;color:#fff;border-radius:4px;padding:1px 8px;font-size:12px;white-space:nowrap}
.Critical{background:var(--crit)}.High{background:var(--high)}.Medium{background:var(--med)}.Low{background:var(--low)}.Info{background:var(--info)}
.finding{background:var(--panel);border:1px solid var(--line);border-left:5px solid var(--info);border-radius:6px;padding:12px 16px;margin-bottom:12px}
.finding.Critical{border-left-color:var(--crit);background:var(--panel)}.finding.High{border-left-color:var(--high);background:var(--panel)}
.finding.Medium{border-left-color:var(--med);background:var(--panel)}.finding.Low{border-left-color:var(--low);background:var(--panel)}
.finding h3{margin:0 0 6px;font-size:15px}.finding ul{margin:6px 0;padding-left:20px;font-family:Consolas,monospace;font-size:12px}
.kv td:first-child{width:160px;color:var(--muted)}code{font-family:Consolas,monospace}
.wrap{overflow-x:auto}
</style></head><body><main>
""");
        sb.Append($"<h1>PCAP 침해사고 분석 보고서</h1><p class=\"muted\">생성: {E(TimeFormat.Format(r.AnalyzedAt))} UTC · 모든 시각은 UTC 기준</p>");

        // 개요
        sb.Append($"<h2>{++sec}. 분석 대상</h2><table class=\"kv\">");
        Row(sb, "파일", r.FileName);
        Row(sb, "SHA-256", r.FileSha256);
        Row(sb, "파일 크기", TimeFormat.Bytes(r.FileSize));
        Row(sb, "캡처 기간", $"{TimeFormat.Format(st.Start)} ~ {TimeFormat.Format(st.End)} ({TimeFormat.Duration(st.Duration)})");
        Row(sb, "패킷 / 바이트", $"{st.PacketCount:N0}개 / {TimeFormat.Bytes(st.TotalBytes)}");
        Row(sb, "세션", $"TCP {st.TcpSessionCount:N0} · UDP {st.UdpSessionCount:N0} · 고유 IP {st.UniqueIpCount:N0}");
        if (r.IdsSource.Length > 0) Row(sb, "IDS 검사", $"{r.IdsSource} — 경보 {r.IdsAlerts.Count(a => !a.Ignored):N0}건 (제외 {r.IdsAlerts.Count(a => a.Ignored):N0}건)");
        if (r.Warnings.Count > 0) Row(sb, "경고", string.Join(" / ", r.Warnings));
        sb.Append("</table>");

        // 요약
        sb.Append($"<h2>{++sec}. 탐지 요약</h2><div class=\"grid\">");
        foreach (var s in new[] { Severity.Critical, Severity.High, Severity.Medium, Severity.Low })
            sb.Append($"<div class=\"card\"><span class=\"sev {s}\">{s.ToKorean()}</span><b>{r.CountBySeverity(s)}</b></div>");
        sb.Append($"<div class=\"card\">HTTP 요청<b>{r.Http.Count:N0}</b></div><div class=\"card\">DNS 질의<b>{r.Dns.Count:N0}</b></div>");
        sb.Append($"<div class=\"card\">인증 정보<b>{r.Credentials.Count:N0}</b></div><div class=\"card\">추출 파일<b>{r.Files.Count:N0}</b></div></div>");

        // 상세
        sb.Append($"<h2>{++sec}. 탐지 상세</h2>");
        if (r.Findings.Count == 0) sb.Append("<p class=\"muted\">탐지된 위협이 없습니다.</p>");
        foreach (var f in r.Findings)
        {
            sb.Append($"<div class=\"finding {f.Severity}\"><h3><span class=\"sev {f.Severity}\">{f.SeverityText}</span> #{f.Id} {E(f.Title)}</h3>");
            sb.Append($"<div class=\"muted\">{E(f.Category)} · {E(f.FirstSeenText)} ~ {E(f.LastSeenText)} · {f.Count:N0}건 · MITRE ATT&amp;CK: {E(f.Mitre)}</div>");
            sb.Append($"<p>{E(f.Description)}</p>");
            if (f.Evidence.Count > 0)
            {
                sb.Append("<ul>");
                foreach (var ev in f.Evidence) sb.Append($"<li>{E(ev)}</li>");
                sb.Append("</ul>");
            }
            if (f.Recommendation.Length > 0) sb.Append($"<p><b>대응 권고:</b> {E(f.Recommendation)}</p>");
            sb.Append("</div>");
        }

        // 관찰된 지표
        sb.Append($"<h2>{++sec}. 관찰된 외부 지표</h2><div class=\"wrap\"><table><tr><th>외부 IP</th><th>관련 도메인</th><th>전송량</th></tr>");
        foreach (var h in st.TopExternalHosts) sb.Append($"<tr><td>{E(h.Name)}</td><td>{E(h.Detail)}</td><td>{TimeFormat.Bytes(h.Value)}</td></tr>");
        sb.Append("</table></div>");

        var dangerous = r.Files.Where(f => f.IsDangerous || f.Category == FileCategory.Unknown).ToList();
        if (dangerous.Count > 0)
        {
            sb.Append($"<h2>{++sec}. 의심 파일</h2><div class=\"wrap\"><table><tr><th>#</th><th>시간</th><th>파일</th><th>형식</th><th>크기</th><th>SHA-256</th><th>위치</th></tr>");
            foreach (var f in dangerous)
                sb.Append($"<tr><td>{f.Id}</td><td>{E(f.TimeText)}</td><td>{E(f.FileName)}</td><td>{E(f.Kind)}</td><td>{E(f.SizeText)}</td><td><code>{E(f.Sha256)}</code></td><td>{E(TextUtil.Truncate(f.Location, 200))}</td></tr>");
            sb.Append("</table></div>");
        }

        if (r.Credentials.Count > 0)
        {
            sb.Append($"<h2>{++sec}. 노출된 인증 정보</h2><div class=\"wrap\"><table><tr><th>시간</th><th>프로토콜</th><th>클라이언트</th><th>서버</th><th>계정</th><th>비밀번호</th><th>결과</th></tr>");
            foreach (var c in r.Credentials.Take(500))
                sb.Append($"<tr><td>{E(c.TimeText)}</td><td>{E(c.Protocol)}</td><td>{E(c.ClientIp)}</td><td>{E(NetUtil.Endpoint(c.ServerIp, c.ServerPort))}</td><td>{E(c.Username)}</td><td><code>{E(c.Password)}</code></td><td>{E(c.ResultText)}</td></tr>");
            sb.Append("</table></div>");
            if (r.Credentials.Count > 500) sb.Append($"<p class=\"muted\">… 외 {r.Credentials.Count - 500:N0}건 (CSV 내보내기 참조)</p>");
        }

        sb.Append($"<h2>{++sec}. 주요 타임라인</h2><div class=\"wrap\"><table><tr><th>시간</th><th>분류</th><th>출발지</th><th>목적지</th><th>내용</th></tr>");
        var important = r.Timeline.Where(e => e.Category is "탐지" or "인증" or "파일" or "FTP" || (e.Category == "HTTP" && e.Summary.StartsWith("POST"))).Take(1000).ToList();
        foreach (var e in important)
        {
            string sev = e.Severity is Severity s ? $"<span class=\"sev {s}\">{e.SeverityText}</span> " : "";
            sb.Append($"<tr><td>{E(e.TimeText)}</td><td>{sev}{E(e.Category)}</td><td>{E(e.Source)}</td><td>{E(e.Destination)}</td><td>{E(e.Summary)}</td></tr>");
        }
        sb.Append("</table></div>");

        sb.Append($"<h2>{++sec}. 질의된 도메인 상위</h2><div class=\"wrap\"><table><tr><th>도메인</th><th>질의 수</th></tr>");
        foreach (var d in st.TopDomains) sb.Append($"<tr><td>{E(d.Name)}</td><td>{d.Value:N0}</td></tr>");
        sb.Append("</table></div>");

        sb.Append($"<p class=\"muted\" style=\"margin-top:32px\">PCAP 침해사고 분석기 · 분석 소요 {r.AnalysisTime.TotalSeconds:F1}초</p></main></body></html>");
        return sb.ToString();
    }

    static void Row(StringBuilder sb, string k, string v) => sb.Append($"<tr><td>{E(k)}</td><td>{E(v)}</td></tr>");
}
