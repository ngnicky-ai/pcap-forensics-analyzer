using System.Net;

namespace PcapForensics.Core.Analysis;

/// <summary>HTTP 응답/업로드 본문과 FTP 데이터 채널에서 파일을 추출하고 해시·형식·엔트로피를 계산한다.</summary>
public static class FileExtractor
{
    public static void Extract(AnalysisResult r)
    {
        foreach (var h in r.Http)
        {
            if (h.ResponseBody.Length > 0)
                Add(r, h.ResponseBody, h.ResponseTime ?? h.Time, "HTTP", h, FileNameFor(h), h.ContentType);

            if (h.RequestBody.Length >= 1024)
                Add(r, h.RequestBody, h.Time, "HTTP 업로드", h, $"upload_{h.Id}", h.RequestHeader("Content-Type") ?? "");
        }

        var sessions = r.Sessions.ToDictionary(s => s.Id);
        foreach (var cmd in r.FtpCommands)
        {
            if (cmd.DataSessionId is not int sid || cmd.Command is not ("RETR" or "STOR" or "STOU" or "APPE")) continue;
            var data = PcapAnalyzer.FtpPayload(sessions[sid], cmd);
            if (data.Length == 0) continue;
            var (kind, category) = FileTypeDetector.Detect(data);
            r.Files.Add(new ExtractedFile
            {
                Time = cmd.Time,
                Source = cmd.Command == "RETR" ? "FTP 다운로드" : "FTP 업로드",
                ClientIp = cmd.ClientIp,
                ServerIp = cmd.ServerIp,
                ServerPort = 21,
                Host = cmd.ServerIp,
                Location = $"ftp://{cmd.ServerIp}/{cmd.Argument}",
                FileName = Path.GetFileName(cmd.Argument.Replace('\\', '/')),
                Kind = kind,
                Category = category,
                Size = data.Length,
                Md5 = HashUtil.Md5(data),
                Sha1 = HashUtil.Sha1(data),
                Sha256 = HashUtil.Sha256(data),
                Entropy = EntropyUtil.Shannon(data.AsSpan(0, Math.Min(data.Length, 1 << 20))),
                SessionId = sid,
                Data = data,
            });
        }

        r.Files.Sort((a, b) => a.Time.CompareTo(b.Time));
        for (int i = 0; i < r.Files.Count; i++) r.Files[i].Id = i + 1;
    }

    static void Add(AnalysisResult r, byte[] data, DateTime time, string source, HttpTransaction h, string name, string declared)
    {
        var (kind, category) = FileTypeDetector.Detect(data, declared);
        r.Files.Add(new ExtractedFile
        {
            Time = time,
            Source = source,
            ClientIp = h.ClientIp,
            ServerIp = h.ServerIp,
            ServerPort = h.ServerPort,
            Host = h.Host.Length > 0 ? h.Host : h.ServerIp,
            Location = h.Url,
            FileName = name,
            DeclaredType = declared,
            Kind = kind,
            Category = category,
            Size = data.Length,
            Md5 = HashUtil.Md5(data),
            Sha1 = HashUtil.Sha1(data),
            Sha256 = HashUtil.Sha256(data),
            Entropy = EntropyUtil.Shannon(data.AsSpan(0, Math.Min(data.Length, 1 << 20))),
            Referer = h.Referer,
            SessionId = h.SessionId,
            Data = data,
        });
    }

    static string FileNameFor(HttpTransaction h)
    {
        var cd = h.ResponseHeader("Content-Disposition");
        if (cd is not null)
        {
            int i = cd.IndexOf("filename=", StringComparison.OrdinalIgnoreCase);
            if (i >= 0)
            {
                var name = cd[(i + 9)..].Split(';')[0].Trim().Trim('"');
                if (name.Length > 0) return name;
            }
        }
        var path = h.Uri;
        int q = path.IndexOfAny(new[] { '?', '#' });
        if (q >= 0) path = path[..q];
        var last = WebUtility.UrlDecode(path.TrimEnd('/').Split('/').LastOrDefault() ?? "");
        return last.Length > 0 ? last : "index";
    }
}

public static class StatisticsBuilder
{
    public static CaptureStatistics Build(AnalysisResult r)
    {
        var st = new CaptureStatistics { PacketCount = r.Packets.Count };
        if (r.Packets.Count == 0) return st;

        st.TotalBytes = r.Packets.Sum(p => (long)p.Length);
        st.Start = r.Packets.Min(p => p.Timestamp);
        st.End = r.Packets.Max(p => p.Timestamp);
        st.TcpSessionCount = r.Sessions.Count(s => s.Transport == TransportProtocol.Tcp);
        st.UdpSessionCount = r.Sessions.Count(s => s.Transport == TransportProtocol.Udp);

        var proto = r.Packets.GroupBy(p => p.ProtocolName).Select(g => new NamedCount(g.Key, g.Count())).OrderByDescending(x => x.Value).ToList();
        st.Protocols = proto.Take(10).ToList();
        if (proto.Count > 10) st.Protocols.Add(new NamedCount("기타", proto.Skip(10).Sum(x => x.Value)));

        var bytesByIp = new Dictionary<string, (long Bytes, int Packets)>();
        foreach (var p in r.Packets)
        {
            foreach (var ip in new[] { p.SrcIp, p.DstIp })
            {
                if (ip is null) continue;
                var v = bytesByIp.GetValueOrDefault(ip);
                bytesByIp[ip] = (v.Bytes + p.Length, v.Packets + 1);
            }
        }
        st.UniqueIpCount = bytesByIp.Count;
        st.TopTalkers = bytesByIp.OrderByDescending(kv => kv.Value.Bytes).Take(10)
            .Select(kv => new NamedCount(kv.Key, kv.Value.Bytes, r.NamesOf(kv.Key, 1)))
            .ToList();

        st.TopServerPorts = r.Sessions.GroupBy(s => (s.Transport, s.ServerPort, s.AppProtocol))
            .Select(g => new NamedCount($"{(g.Key.Transport == TransportProtocol.Tcp ? "TCP" : "UDP")}/{g.Key.ServerPort} {g.Key.AppProtocol}", g.Count()))
            .OrderByDescending(x => x.Value).Take(10).ToList();

        st.TopExternalHosts = r.Sessions.Where(s => NetUtil.IsExternal(s.ServerIp))
            .GroupBy(s => s.ServerIp)
            .Select(g => new NamedCount(g.Key, g.Sum(s => s.TotalPayload), r.NamesOf(g.Key, 2)))
            .OrderByDescending(x => x.Value).Take(10).ToList();

        st.TopDomains = r.Dns.Where(d => d.QueryName.Length > 0)
            .GroupBy(d => DomainUtil.Normalize(d.QueryName))
            .Select(g => new NamedCount(g.Key, g.Count()))
            .OrderByDescending(x => x.Value).Take(10).ToList();

        double seconds = Math.Max(1, st.Duration.TotalSeconds);
        st.BucketSeconds = Math.Max(1, Math.Ceiling(seconds / 120));
        int buckets = (int)Math.Ceiling(seconds / st.BucketSeconds) + 1;
        var series = new double[buckets];
        foreach (var p in r.Packets)
        {
            int i = (int)((p.Timestamp - st.Start.Value).TotalSeconds / st.BucketSeconds);
            if (i >= 0 && i < buckets) series[i] += p.Length;
        }
        st.TrafficSeries = series.ToList();
        return st;
    }
}

public static class TimelineBuilder
{
    public static List<TimelineEvent> Build(AnalysisResult r)
    {
        var list = new List<TimelineEvent>();

        foreach (var f in r.Findings)
            list.Add(new TimelineEvent { Time = f.FirstSeen, Category = "탐지", Severity = f.Severity, Source = f.SourceIp, Destination = f.TargetIp, Summary = f.Title, SessionId = f.SessionIds.FirstOrDefault() });

        foreach (var d in r.Dns)
            list.Add(new TimelineEvent
            {
                Time = d.Time, Category = "DNS", Source = d.ClientIp, Destination = d.ServerIp,
                Summary = $"{d.QueryType} {d.QueryName} → {(d.RCode == 0 ? TextUtil.Truncate(d.AnswersText, 150) : d.RCodeText)}",
            });

        foreach (var h in r.Http)
            list.Add(new TimelineEvent
            {
                Time = h.Time, Category = "HTTP", Source = h.ClientIp, Destination = h.ServerIp, SessionId = h.SessionId,
                Summary = $"{h.Method} {TextUtil.Truncate(h.Url, 200)} → {h.StatusText}" + (h.ResponseLength > 0 ? $" ({h.ContentType}, {h.ResponseLengthText})" : ""),
            });

        foreach (var t in r.Tls)
            list.Add(new TimelineEvent { Time = t.Time, Category = "TLS", Source = t.ClientIp, Destination = t.ServerIp, SessionId = t.SessionId, Summary = $"{t.Version} 연결 SNI={t.Sni}" });

        foreach (var c in r.Credentials)
            list.Add(new TimelineEvent
            {
                Time = c.Time, Category = "인증", Source = c.ClientIp, Destination = c.ServerIp, SessionId = c.SessionId,
                Summary = $"{c.Protocol} 로그인 {c.ResultText}: {c.Username}",
                Severity = c.Result == AuthResult.Success ? Severity.Info : null,
            });

        foreach (var c in r.FtpCommands)
            list.Add(new TimelineEvent
            {
                Time = c.Time, Category = "FTP", Source = c.ClientIp, Destination = c.ServerIp, SessionId = c.SessionId,
                Summary = $"{c.Command} {c.Argument}" + (c.ReplyCode is int code ? $" → {code}" : "") + (c.DataBytes > 0 ? $" ({TimeFormat.Bytes(c.DataBytes)})" : ""),
            });

        foreach (var f in r.Files.Where(f => f.Category is not (FileCategory.Image or FileCategory.Font or FileCategory.Web or FileCategory.Text)))
            list.Add(new TimelineEvent
            {
                Time = f.Time, Category = "파일", Source = f.ServerIp, Destination = f.ClientIp, SessionId = f.SessionId,
                Summary = $"{f.Source}: {f.FileName} ({f.Kind}, {f.SizeText}) SHA256={f.Sha256[..16]}…",
                Severity = f.IsDangerous ? Severity.Medium : null,
            });

        return list.OrderBy(e => e.Time).ThenByDescending(e => e.Severity ?? Severity.Info).ToList();
    }
}
