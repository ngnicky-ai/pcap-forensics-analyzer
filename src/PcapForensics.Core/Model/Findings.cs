namespace PcapForensics.Core.Model;

/// <summary>탐지 규칙이 생성한 침해 지표.</summary>
public sealed class Finding
{
    public int Id { get; set; }
    public Severity Severity { get; init; }
    public string Category { get; init; } = "";
    public string Title { get; init; } = "";
    public string Description { get; init; } = "";
    public string SourceIp { get; init; } = "";
    public string TargetIp { get; init; } = "";
    public DateTime FirstSeen { get; init; }
    public DateTime LastSeen { get; init; }
    public int Count { get; init; } = 1;
    public string Mitre { get; init; } = "";
    public string Recommendation { get; init; } = "";
    public List<string> Evidence { get; init; } = new();
    public List<int> SessionIds { get; init; } = new();

    public string SeverityText => Severity.ToKorean();
    public string FirstSeenText => TimeFormat.Format(FirstSeen);
    public string LastSeenText => TimeFormat.Format(LastSeen);
}

public sealed class TimelineEvent
{
    public DateTime Time { get; init; }
    public string Category { get; init; } = "";
    public Severity? Severity { get; init; }
    public string Source { get; init; } = "";
    public string Destination { get; init; } = "";
    public string Summary { get; init; } = "";
    public int? SessionId { get; init; }

    public string TimeText => TimeFormat.Format(Time);
    public string SeverityText => Severity?.ToKorean() ?? "";
}

public sealed class ExtractedFile
{
    public int Id { get; set; }
    public DateTime Time { get; init; }
    public string Source { get; init; } = "";
    public string ClientIp { get; init; } = "";
    public string ServerIp { get; init; } = "";
    public int ServerPort { get; init; }
    public string Host { get; init; } = "";
    public string Location { get; init; } = "";
    public string FileName { get; init; } = "";
    public string DeclaredType { get; init; } = "";
    public string Kind { get; init; } = "";
    public FileCategory Category { get; init; }
    public long Size { get; init; }
    public string Md5 { get; init; } = "";
    public string Sha1 { get; init; } = "";
    public string Sha256 { get; init; } = "";
    public double Entropy { get; init; }
    public string Referer { get; init; } = "";
    public int SessionId { get; init; }
    public byte[] Data { get; init; } = Array.Empty<byte>();

    public string CategoryText => Category.ToKorean();
    public string SizeText => TimeFormat.Bytes(Size);
    public string TimeText => TimeFormat.Format(Time);
    public bool IsDangerous => Category is FileCategory.Executable or FileCategory.ActiveContent or FileCategory.Script;
}
