namespace PcapForensics.Core.Detection;

public sealed class DetectionContext
{
    public DetectionContext(AnalysisResult result, DetectionSettings settings, WebAttackRules webRules, IocSet iocs)
    {
        Result = result;
        Settings = settings;
        WebRules = webRules;
        Iocs = iocs;
    }

    public AnalysisResult Result { get; }
    public DetectionSettings Settings { get; }
    public WebAttackRules WebRules { get; }
    public IocSet Iocs { get; }
}

/// <summary>탐지 규칙. 새 규칙은 이 인터페이스를 구현해 <see cref="Analysis.PcapAnalyzer"/>의 목록에 추가한다.</summary>
public interface IDetector
{
    string Name { get; }
    IEnumerable<Finding> Detect(DetectionContext ctx);
}

internal static class DetectorUtil
{
    /// <summary>시간순 정렬된 항목에서, 주어진 시간 창 안에 나타난 서로 다른 키 개수의 최댓값.</summary>
    public static int MaxDistinctInWindow<T, TKey>(IReadOnlyList<T> sorted, Func<T, DateTime> time, Func<T, TKey> key, double windowSeconds)
        where TKey : notnull
    {
        var counts = new Dictionary<TKey, int>();
        int left = 0, best = 0;
        for (int right = 0; right < sorted.Count; right++)
        {
            var k = key(sorted[right]);
            counts[k] = counts.GetValueOrDefault(k) + 1;
            while ((time(sorted[right]) - time(sorted[left])).TotalSeconds > windowSeconds)
            {
                var lk = key(sorted[left]);
                if (--counts[lk] == 0) counts.Remove(lk);
                left++;
            }
            best = Math.Max(best, counts.Count);
        }
        return best;
    }

    /// <summary>시간 창 안에 들어오는 항목 수의 최댓값.</summary>
    public static int MaxCountInWindow<T>(IReadOnlyList<T> sorted, Func<T, DateTime> time, double windowSeconds)
    {
        int left = 0, best = 0;
        for (int right = 0; right < sorted.Count; right++)
        {
            while ((time(sorted[right]) - time(sorted[left])).TotalSeconds > windowSeconds) left++;
            best = Math.Max(best, right - left + 1);
        }
        return best;
    }

    public static string JoinLimited<T>(IEnumerable<T> items, int max, string sep = ", ")
    {
        var list = items.ToList();
        var shown = string.Join(sep, list.Take(max));
        return list.Count > max ? $"{shown} … (총 {list.Count}개)" : shown;
    }

    /// <summary>"80-85, 443" 처럼 연속 구간을 압축해 표시.</summary>
    public static string PortRanges(IEnumerable<int> ports, int maxParts = 40)
    {
        var sorted = ports.Distinct().OrderBy(p => p).ToList();
        var parts = new List<string>();
        for (int i = 0; i < sorted.Count; i++)
        {
            int start = sorted[i];
            while (i + 1 < sorted.Count && sorted[i + 1] == sorted[i] + 1) i++;
            parts.Add(start == sorted[i] ? start.ToString() : $"{start}-{sorted[i]}");
        }
        return JoinLimited(parts, maxParts);
    }

    public static string WithName(AnalysisResult r, string ip)
    {
        var names = r.NamesOf(ip, 2);
        return names.Length > 0 ? $"{ip} ({names})" : ip;
    }

    public static double Median(List<double> values)
    {
        if (values.Count == 0) return 0;
        var s = values.OrderBy(v => v).ToList();
        int mid = s.Count / 2;
        return s.Count % 2 == 1 ? s[mid] : (s[mid - 1] + s[mid]) / 2;
    }
}
