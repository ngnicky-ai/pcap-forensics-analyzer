namespace PcapForensics.Core.Model;

public sealed class AnalysisResult
{
    public string FilePath { get; init; } = "";
    public string FileName => Path.GetFileName(FilePath);
    public long FileSize { get; init; }
    public string FileSha256 { get; set; } = "";
    public DateTime AnalyzedAt { get; init; } = DateTime.UtcNow;
    public TimeSpan AnalysisTime { get; set; }

    public List<PacketRecord> Packets { get; } = new();
    public List<NetworkSession> Sessions { get; set; } = new();
    public List<HttpTransaction> Http { get; } = new();
    public List<DnsTransaction> Dns { get; } = new();
    public List<TlsHandshakeInfo> Tls { get; } = new();
    public List<CredentialRecord> Credentials { get; } = new();
    public List<FtpCommandRecord> FtpCommands { get; } = new();
    public List<ExtractedFile> Files { get; } = new();
    public List<IdsAlert> IdsAlerts { get; set; } = new();
    /// <summary>IDS 경보 출처 설명(예: Suricata 7.0.5, 룰 45,000개).</summary>
    public string IdsSource { get; set; } = "";
    public List<Finding> Findings { get; set; } = new();
    public List<TimelineEvent> Timeline { get; set; } = new();
    public CaptureStatistics Statistics { get; set; } = new();
    public List<string> Warnings { get; } = new();

    /// <summary>IP → 관찰된 호스트 이름(DNS 응답, HTTP Host, TLS SNI).</summary>
    public Dictionary<string, SortedSet<string>> HostNames { get; } = new();

    public string NamesOf(string ip, int max = 3) =>
        HostNames.TryGetValue(ip, out var set) ? string.Join(", ", set.Take(max)) + (set.Count > max ? " …" : "") : "";

    public int CountBySeverity(Severity s) => Findings.Count(f => f.Severity == s);
}

public sealed class CaptureStatistics
{
    public int PacketCount { get; set; }
    public long TotalBytes { get; set; }
    public DateTime? Start { get; set; }
    public DateTime? End { get; set; }
    public TimeSpan Duration => Start.HasValue && End.HasValue ? End.Value - Start.Value : TimeSpan.Zero;
    public int UniqueIpCount { get; set; }
    public int TcpSessionCount { get; set; }
    public int UdpSessionCount { get; set; }
    public List<NamedCount> Protocols { get; set; } = new();
    public List<NamedCount> TopTalkers { get; set; } = new();
    public List<NamedCount> TopServerPorts { get; set; } = new();
    public List<NamedCount> TopExternalHosts { get; set; } = new();
    public List<NamedCount> TopDomains { get; set; } = new();
    public List<double> TrafficSeries { get; set; } = new();
    public double BucketSeconds { get; set; }
}

public sealed record NamedCount(string Name, long Value, string Detail = "");

public readonly record struct AnalysisProgress(string Stage, double Percent);
