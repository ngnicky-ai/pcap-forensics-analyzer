using System.Globalization;
using System.Text.Json;

namespace PcapForensics.Core.Ids;

/// <summary>Suricata EVE JSON(한 줄에 이벤트 하나)에서 alert 이벤트를 읽는다.</summary>
public static class EveJsonReader
{
    public static List<IdsAlert> Read(string path, ICollection<string>? warnings = null)
    {
        using var reader = new StreamReader(path, Encoding.UTF8);
        return Read(reader, warnings);
    }

    public static List<IdsAlert> Read(TextReader reader, ICollection<string>? warnings = null)
    {
        var alerts = new List<IdsAlert>();
        int lineNo = 0, bad = 0;
        string? line;
        while ((line = reader.ReadLine()) is not null)
        {
            lineNo++;
            if (line.Length == 0 || !line.Contains("\"alert\"")) continue;
            try
            {
                using var doc = JsonDocument.Parse(line);
                var root = doc.RootElement;
                if (Str(root, "event_type") != "alert" || !root.TryGetProperty("alert", out var a)) continue;
                alerts.Add(new IdsAlert
                {
                    Time = ParseTime(Str(root, "timestamp")),
                    SrcIp = Str(root, "src_ip"),
                    SrcPort = Int(root, "src_port"),
                    DstIp = Str(root, "dest_ip"),
                    DstPort = Int(root, "dest_port"),
                    Proto = Str(root, "proto"),
                    AppProto = Str(root, "app_proto"),
                    FlowId = Long(root, "flow_id"),
                    Gid = Long(a, "gid", 1),
                    Sid = Long(a, "signature_id"),
                    Rev = Int(a, "rev"),
                    Signature = Str(a, "signature"),
                    Classification = Str(a, "category"),
                    Priority = Int(a, "severity", 3),
                    Action = Str(a, "action"),
                    Mitre = Mitre(a),
                    Detail = Detail(root),
                });
            }
            catch (JsonException)
            {
                bad++;
            }
        }
        if (bad > 0) warnings?.Add($"eve.json 에서 해석할 수 없는 줄 {bad}개를 건너뛰었습니다.");
        return alerts;
    }

    /// <summary>"2015-08-31T17:58:21.970123+0000" 형식(콜론 없는 오프셋 포함)을 UTC 로 변환.</summary>
    public static DateTime ParseTime(string s)
    {
        if (s.Length > 5 && (s[^5] == '+' || s[^5] == '-') && char.IsDigit(s[^1]))
            s = s[..^2] + ":" + s[^2..];
        return DateTimeOffset.TryParse(s, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var dto)
            ? dto.UtcDateTime
            : DateTime.UnixEpoch;
    }

    static string Mitre(JsonElement alert)
    {
        if (!alert.TryGetProperty("metadata", out var md) || md.ValueKind != JsonValueKind.Object) return "";
        var ids = Values(md, "mitre_technique_id");
        var names = Values(md, "mitre_technique_name");
        return string.Join(" / ", ids.Select((id, i) => i < names.Count ? $"{id} {names[i].Replace('_', ' ')}" : id));
    }

    static List<string> Values(JsonElement obj, string name) =>
        obj.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Array
            ? v.EnumerateArray().Select(x => x.ToString()).ToList()
            : new List<string>();

    static string Detail(JsonElement root)
    {
        if (root.TryGetProperty("http", out var http))
        {
            var host = Str(http, "hostname");
            var url = Str(http, "url");
            var method = Str(http, "http_method");
            int status = Int(http, "status");
            return $"{method} {host}{url}".Trim() + (status > 0 ? $" → {status}" : "");
        }
        if (root.TryGetProperty("tls", out var tls)) return "TLS SNI=" + Str(tls, "sni");
        if (root.TryGetProperty("dns", out var dns))
        {
            var q = Str(dns, "rrname");
            if (q.Length == 0 && dns.TryGetProperty("query", out var qa) && qa.ValueKind == JsonValueKind.Array && qa.GetArrayLength() > 0)
                q = Str(qa[0], "rrname");
            return "DNS " + q;
        }
        if (root.TryGetProperty("fileinfo", out var fi)) return "파일 " + Str(fi, "filename");
        return "";
    }

    static string Str(JsonElement e, string name) =>
        e.TryGetProperty(name, out var v) ? v.ValueKind == JsonValueKind.String ? v.GetString() ?? "" : v.ToString() : "";

    static int Int(JsonElement e, string name, int fallback = 0) =>
        e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Number && v.TryGetInt32(out int i) ? i : fallback;

    static long Long(JsonElement e, string name, long fallback = 0) =>
        e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Number && v.TryGetInt64(out long l) ? l : fallback;
}
