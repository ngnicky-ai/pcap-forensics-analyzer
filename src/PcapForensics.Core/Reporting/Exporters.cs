namespace PcapForensics.Core.Reporting;

/// <summary>분석 결과를 Excel 에서 바로 열 수 있는 CSV(UTF-8 BOM)로 내보낸다.</summary>
public static class CsvExporter
{
    public static IReadOnlyList<string> ExportAll(AnalysisResult r, string folder)
    {
        Directory.CreateDirectory(folder);
        string prefix = Path.GetFileNameWithoutExtension(r.FileName);
        var written = new List<string>();

        void Write<T>(string name, string[] header, IEnumerable<T> rows, Func<T, object?[]> cells)
        {
            var path = Path.Combine(folder, $"{prefix}_{name}.csv");
            using var w = new StreamWriter(path, false, new UTF8Encoding(true));
            w.WriteLine(string.Join(",", header.Select(Escape)));
            foreach (var row in rows) w.WriteLine(string.Join(",", cells(row).Select(c => Escape(c?.ToString() ?? ""))));
            written.Add(path);
        }

        Write("findings", new[] { "번호", "심각도", "분류", "제목", "출발지", "대상", "최초(UTC)", "최종(UTC)", "건수", "MITRE ATT&CK", "설명", "근거", "권고" },
            r.Findings, f => new object?[] { f.Id, f.SeverityText, f.Category, f.Title, f.SourceIp, f.TargetIp, f.FirstSeenText, f.LastSeenText, f.Count, f.Mitre, f.Description, string.Join(" | ", f.Evidence), f.Recommendation });

        Write("timeline", new[] { "시간(UTC)", "분류", "심각도", "출발지", "목적지", "내용", "세션" },
            r.Timeline, e => new object?[] { e.TimeText, e.Category, e.SeverityText, e.Source, e.Destination, e.Summary, e.SessionId });

        Write("sessions", new[] { "세션", "프로토콜", "응용", "클라이언트", "서버", "서버 이름", "시작(UTC)", "지속(초)", "패킷", "송신 바이트", "수신 바이트", "상태", "요약" },
            r.Sessions, s => new object?[] { s.Id, s.TransportText, s.AppProtocol, s.ClientEndpoint, s.ServerEndpoint, s.ServerName, s.StartText, s.DurationSeconds.ToString("F3"), s.Packets, s.ClientBytes, s.ServerBytes, s.State, s.Summary });

        Write("http", new[] { "번호", "시간(UTC)", "클라이언트", "서버", "메서드", "URL", "상태", "Content-Type", "응답 크기", "User-Agent", "Referer" },
            r.Http, h => new object?[] { h.Id, h.TimeText, h.ClientIp, h.ServerIp, h.Method, h.Url, h.StatusText, h.ContentType, h.ResponseLength, h.UserAgent, h.Referer });

        Write("dns", new[] { "번호", "시간(UTC)", "클라이언트", "DNS 서버", "질의", "유형", "응답 코드", "응답" },
            r.Dns, d => new object?[] { d.Id, d.TimeText, d.ClientIp, d.ServerIp, d.QueryName, d.QueryType, d.RCodeText, d.AnswersText });

        Write("tls", new[] { "시간(UTC)", "클라이언트", "서버", "SNI", "버전" },
            r.Tls, t => new object?[] { t.TimeText, t.ClientIp, NetUtil.Endpoint(t.ServerIp, t.ServerPort), t.Sni, t.Version });

        Write("credentials", new[] { "시간(UTC)", "프로토콜", "클라이언트", "서버", "계정", "비밀번호", "결과", "비고" },
            r.Credentials, c => new object?[] { c.TimeText, c.Protocol, c.ClientIp, NetUtil.Endpoint(c.ServerIp, c.ServerPort), c.Username, c.Password, c.ResultText, c.Detail });

        Write("files", new[] { "번호", "시간(UTC)", "출처", "서버", "클라이언트", "파일명", "위치", "선언 형식", "실제 형식", "분류", "크기", "엔트로피", "MD5", "SHA1", "SHA256" },
            r.Files, f => new object?[] { f.Id, f.TimeText, f.Source, f.ServerIp, f.ClientIp, f.FileName, f.Location, f.DeclaredType, f.Kind, f.CategoryText, f.Size, f.Entropy.ToString("F3"), f.Md5, f.Sha1, f.Sha256 });

        if (r.IdsAlerts.Count > 0)
            Write("ids_alerts", new[] { "시간(UTC)", "심각도", "룰", "시그니처", "분류", "우선순위", "출발지", "목적지", "프로토콜", "응용", "상세", "세션", "MITRE" },
                r.IdsAlerts, a => new object?[] { a.TimeText, a.SeverityText, a.RuleId, a.Signature, a.Classification, a.Priority, a.Source, a.Destination, a.Proto, a.AppProto, a.Detail, a.SessionId, a.Mitre });

        return written;
    }

    static string Escape(string s)
    {
        // 수식 삽입(CSV Injection) 방지
        if (s.Length > 0 && s[0] is '=' or '+' or '-' or '@') s = "'" + s;
        return s.IndexOfAny(new[] { ',', '"', '\n', '\r' }) >= 0 ? "\"" + s.Replace("\"", "\"\"") + "\"" : s;
    }
}

/// <summary>추출된 파일을 디스크에 저장한다. 실행 가능한 형식은 실수로 실행되지 않도록 확장자를 바꾼다.</summary>
public static class ObjectExporter
{
    public const string DangerousSuffix = ".infected";

    public static string SafeName(ExtractedFile f)
    {
        var name = $"{f.Id:D4}_{TextUtil.SafeFileName(f.FileName)}";
        return f.IsDangerous || f.Category == FileCategory.Unknown ? name + DangerousSuffix : name;
    }

    public static int ExportAll(IEnumerable<ExtractedFile> files, string folder)
    {
        Directory.CreateDirectory(folder);
        var manifest = new StringBuilder("번호,파일명,저장 이름,실제 형식,크기,MD5,SHA256,위치\n");
        int n = 0;
        foreach (var f in files)
        {
            var name = SafeName(f);
            File.WriteAllBytes(Path.Combine(folder, name), f.Data);
            manifest.AppendLine($"{f.Id},\"{f.FileName.Replace("\"", "'")}\",\"{name}\",{f.Kind},{f.Size},{f.Md5},{f.Sha256},\"{f.Location.Replace("\"", "'")}\"");
            n++;
        }
        File.WriteAllText(Path.Combine(folder, "manifest.csv"), manifest.ToString(), new UTF8Encoding(true));
        return n;
    }
}
