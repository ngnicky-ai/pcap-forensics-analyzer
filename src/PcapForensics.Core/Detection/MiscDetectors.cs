namespace PcapForensics.Core.Detection;

/// <summary>평문으로 전송된 인증 정보를 보고한다.</summary>
public sealed class CleartextCredentialDetector : IDetector
{
    public string Name => "평문 인증 정보";

    public IEnumerable<Finding> Detect(DetectionContext ctx)
    {
        foreach (var g in ctx.Result.Credentials.GroupBy(c => (c.Protocol, c.ServerIp, c.ServerPort)))
        {
            var list = g.OrderBy(c => c.Time).ToList();
            var accounts = list.GroupBy(c => c.Username).Select(x => x.Key).ToList();
            int success = list.Count(c => c.Result == AuthResult.Success);
            var f = new Finding
            {
                Severity = Severity.Medium,
                Category = "정보 노출",
                Title = $"평문 인증 정보 노출({g.Key.Protocol}): {g.Key.ServerIp}:{g.Key.ServerPort}",
                Description = $"{g.Key.Protocol} 로 계정 {accounts.Count}개의 인증 정보가 암호화 없이 {list.Count}회 전송되었습니다 (성공 {success}건). " +
                              "네트워크를 감청할 수 있는 공격자가 그대로 탈취할 수 있습니다.",
                SourceIp = string.Join(", ", list.Select(c => c.ClientIp).Distinct().Take(3)),
                TargetIp = g.Key.ServerIp,
                FirstSeen = list[0].Time,
                LastSeen = list[^1].Time,
                Count = list.Count,
                Mitre = "T1040 Network Sniffing / T1552 Unsecured Credentials",
                Recommendation = "노출된 계정의 비밀번호를 변경하고, 해당 서비스를 암호화 프로토콜(SFTP, FTPS, HTTPS, IMAPS 등)로 전환하십시오.",
                SessionIds = list.Select(c => c.SessionId).Distinct().Take(500).ToList(),
            };
            foreach (var c in list.Where(c => c.Result == AuthResult.Success).Concat(list).DistinctBy(c => (c.Username, c.Password)).Take(10))
                f.Evidence.Add($"[{TimeFormat.Format(c.Time)}] {(c.Username.Length > 0 ? c.Username : "(계정 미확인)")} / {c.Password} → {c.ResultText}");
            yield return f;
        }

        // 기본/취약 비밀번호로 로그인 성공
        var weak = ctx.Result.Credentials.Where(c => c.Result == AuthResult.Success && IsWeak(c.Username, c.Password));
        foreach (var g in weak.GroupBy(c => (c.Protocol, c.ServerIp, c.ServerPort, c.Username, c.Password)))
        {
            var list = g.OrderBy(c => c.Time).ToList();
            yield return new Finding
            {
                Severity = Severity.High,
                Category = "계정 공격",
                Title = $"기본/취약 비밀번호로 로그인 성공: {g.Key.Username} @ {g.Key.ServerIp}:{g.Key.ServerPort} ({g.Key.Protocol})",
                Description = $"계정 '{g.Key.Username}'이(가) 추측하기 쉬운 비밀번호('{g.Key.Password}')로 로그인에 성공했습니다. " +
                              "공격자가 기본 계정을 이용해 관리 기능에 접근했을 수 있습니다.",
                SourceIp = string.Join(", ", list.Select(c => c.ClientIp).Distinct().Take(3)),
                TargetIp = g.Key.ServerIp,
                FirstSeen = list[0].Time,
                LastSeen = list[^1].Time,
                Count = list.Count,
                Mitre = "T1078.001 Valid Accounts: Default Accounts",
                Evidence = list.Take(5).Select(c => $"[{TimeFormat.Format(c.Time)}] {c.ClientIp} → {c.Detail}".TrimEnd(' ', '→')).ToList(),
                SessionIds = list.Select(c => c.SessionId).Distinct().ToList(),
                Recommendation = "해당 계정의 비밀번호를 즉시 변경하고, 로그인 이후 수행된 관리 작업(배포, 설정 변경, 파일 업로드)을 확인하십시오.",
            };
        }
    }

    static readonly HashSet<string> WeakPasswords = new(StringComparer.OrdinalIgnoreCase)
    {
        "", "password", "passw0rd", "p@ssw0rd", "123456", "12345678", "1234", "12345", "123456789", "qwerty", "admin", "root",
        "toor", "tomcat", "manager", "s3cret", "secret", "guest", "test", "changeme", "default", "letmein", "welcome", "1q2w3e4r",
    };

    static bool IsWeak(string user, string pass) =>
        WeakPasswords.Contains(pass) || (user.Length > 0 && pass.Equals(user, StringComparison.OrdinalIgnoreCase));
}

/// <summary>하나의 IP 에 대해 여러 MAC 이 ARP 응답한 경우(ARP 스푸핑/중간자 공격)를 탐지한다.</summary>
public sealed class ArpSpoofDetector : IDetector
{
    public string Name => "ARP 스푸핑";

    public IEnumerable<Finding> Detect(DetectionContext ctx)
    {
        var claims = new Dictionary<string, Dictionary<string, (DateTime First, DateTime Last, int Count)>>();
        foreach (var p in ctx.Result.Packets)
        {
            var a = p.Arp;
            if (a is null || a.SenderIp == "0.0.0.0") continue;
            if (a.Operation != 2 && a.SenderIp != a.TargetIp) continue; // 응답 또는 Gratuitous ARP 만
            if (!claims.TryGetValue(a.SenderIp, out var macs)) claims[a.SenderIp] = macs = new();
            macs[a.SenderMac] = macs.TryGetValue(a.SenderMac, out var v)
                ? (v.First, p.Timestamp, v.Count + 1)
                : (p.Timestamp, p.Timestamp, 1);
        }

        foreach (var (ip, macs) in claims)
        {
            if (macs.Count < 2) continue;
            var ordered = macs.OrderBy(m => m.Value.First).ToList();
            // 같은 MAC 이 다른 IP 도 주장하는지 확인(공격자 식별 단서)
            var otherIps = ordered.ToDictionary(m => m.Key,
                m => claims.Where(c => c.Key != ip && c.Value.ContainsKey(m.Key)).Select(c => c.Key).ToList());

            var f = new Finding
            {
                Severity = Severity.High,
                Category = "중간자 공격",
                Title = $"ARP 스푸핑 의심: {ip} 에 대해 MAC {macs.Count}개",
                Description = $"IP {ip} 에 대해 서로 다른 MAC 주소 {macs.Count}개가 ARP 응답을 보냈습니다. 게이트웨이 IP 라면 트래픽을 가로채는 중간자 공격일 가능성이 높습니다.",
                SourceIp = string.Join(", ", ordered.Select(m => m.Key)),
                TargetIp = ip,
                FirstSeen = ordered.Min(m => m.Value.First),
                LastSeen = ordered.Max(m => m.Value.Last),
                Count = ordered.Sum(m => m.Value.Count),
                Mitre = "T1557.002 Adversary-in-the-Middle: ARP Cache Poisoning",
                Recommendation = "스위치의 MAC 주소 테이블로 의심 MAC 의 포트를 찾아 차단하고, Dynamic ARP Inspection 적용을 검토하십시오.",
            };
            foreach (var (mac, info) in ordered)
            {
                var others = otherIps[mac];
                f.Evidence.Add($"{mac}: ARP 응답 {info.Count}회 ({TimeFormat.Format(info.First)} ~ {TimeFormat.Format(info.Last)})" +
                               (others.Count > 0 ? $", 다른 IP 도 주장: {DetectorUtil.JoinLimited(others, 5)}" : ""));
            }
            yield return f;
        }
    }
}

/// <summary>사용자가 불러온 IOC(IP/도메인/해시)와 트래픽을 대조한다.</summary>
public sealed class IocMatchDetector : IDetector
{
    public string Name => "IOC 매칭";

    public IEnumerable<Finding> Detect(DetectionContext ctx)
    {
        var iocs = ctx.Iocs;
        if (iocs.Count == 0) yield break;
        var r = ctx.Result;

        // IP
        var ipHits = new Dictionary<string, (string Comment, List<PacketRecord> Packets, HashSet<string> Peers)>();
        foreach (var p in r.Packets)
        {
            foreach (var (ip, peer) in new[] { (p.SrcIp, p.DstIp), (p.DstIp, p.SrcIp) })
            {
                if (ip is null || !iocs.TryMatchIp(ip, out var matched, out var comment)) continue;
                if (!ipHits.TryGetValue(ip, out var hit)) ipHits[ip] = hit = ($"{matched} {comment}".Trim(), new(), new());
                hit.Packets.Add(p);
                if (peer is not null) hit.Peers.Add(peer);
            }
        }
        foreach (var (ip, hit) in ipHits)
        {
            yield return new Finding
            {
                Severity = Severity.High,
                Category = "IOC 일치",
                Title = $"악성 IP 와 통신: {DetectorUtil.WithName(r, ip)}",
                Description = $"IOC 목록의 IP({hit.Comment})와 패킷 {hit.Packets.Count}개를 주고받았습니다.",
                SourceIp = string.Join(", ", hit.Peers.Take(5)),
                TargetIp = ip,
                FirstSeen = hit.Packets.Min(p => p.Timestamp),
                LastSeen = hit.Packets.Max(p => p.Timestamp),
                Count = hit.Packets.Count,
                Mitre = "T1071 Application Layer Protocol",
                Evidence = { $"통신한 내부 호스트: {DetectorUtil.JoinLimited(hit.Peers, 10)}" },
                SessionIds = hit.Packets.Where(p => p.SessionId > 0).Select(p => p.SessionId).Distinct().Take(500).ToList(),
                Recommendation = "통신한 호스트를 격리하고, 해당 IP 를 방화벽에서 차단하십시오.",
            };
        }

        // 도메인 (DNS 질의, HTTP Host, TLS SNI)
        var observed = r.Dns.Select(d => (Name: d.QueryName, d.Time, Client: d.ClientIp, Via: "DNS 질의", Sid: 0))
            .Concat(r.Http.Where(h => h.Host.Length > 0).Select(h => (Name: h.Host.Split(':')[0], h.Time, Client: h.ClientIp, Via: "HTTP Host", Sid: h.SessionId)))
            .Concat(r.Tls.Where(t => t.Sni.Length > 0).Select(t => (Name: t.Sni, t.Time, Client: t.ClientIp, Via: "TLS SNI", Sid: t.SessionId)));
        var domainHits = new Dictionary<string, List<(string Name, DateTime Time, string Client, string Via, int Sid, string Comment)>>();
        foreach (var o in observed)
        {
            if (!iocs.TryMatchDomain(o.Name, out var matched, out var comment)) continue;
            if (!domainHits.TryGetValue(matched, out var list)) domainHits[matched] = list = new();
            list.Add((o.Name, o.Time, o.Client, o.Via, o.Sid, comment));
        }
        foreach (var (domain, list) in domainHits)
        {
            var sorted = list.OrderBy(x => x.Time).ToList();
            yield return new Finding
            {
                Severity = Severity.High,
                Category = "IOC 일치",
                Title = $"악성 도메인 접근: {domain}",
                Description = $"IOC 목록의 도메인 {domain}{(sorted[0].Comment.Length > 0 ? $"({sorted[0].Comment})" : "")} 이(가) {sorted.Count}회 관찰되었습니다.",
                SourceIp = string.Join(", ", sorted.Select(x => x.Client).Distinct().Take(5)),
                TargetIp = domain,
                FirstSeen = sorted[0].Time,
                LastSeen = sorted[^1].Time,
                Count = sorted.Count,
                Mitre = "T1071 Application Layer Protocol / T1189 Drive-by Compromise",
                Evidence = sorted.Select(x => $"[{TimeFormat.Format(x.Time)}] {x.Via}: {x.Name} (호스트 {x.Client})").Distinct().Take(15).ToList(),
                SessionIds = sorted.Where(x => x.Sid > 0).Select(x => x.Sid).Distinct().ToList(),
                Recommendation = "도메인을 DNS/프록시에서 차단하고, 접근한 호스트의 감염 여부를 조사하십시오.",
            };
        }

        // 파일 해시
        foreach (var f in r.Files)
        {
            string? comment = null;
            string matchedHash = "";
            foreach (var h in new[] { f.Md5, f.Sha1, f.Sha256 })
            {
                if (iocs.TryMatchHash(h, out var c)) { comment = c; matchedHash = h; break; }
            }
            if (comment is null) continue;
            yield return new Finding
            {
                Severity = Severity.Critical,
                Category = "IOC 일치",
                Title = $"악성 파일 전송: {f.FileName}",
                Description = $"전송된 파일의 해시가 IOC 목록과 일치합니다{(comment.Length > 0 ? $" ({comment})" : "")}.",
                SourceIp = f.ServerIp,
                TargetIp = f.ClientIp,
                FirstSeen = f.Time,
                LastSeen = f.Time,
                Mitre = "T1105 Ingress Tool Transfer",
                Evidence = { $"일치 해시: {matchedHash}", $"위치: {f.Location}", $"형식: {f.Kind}, 크기 {f.SizeText}" },
                SessionIds = { f.SessionId },
                Recommendation = "수신 호스트를 즉시 격리하고 해당 파일의 실행 여부를 확인하십시오.",
            };
        }
    }
}
