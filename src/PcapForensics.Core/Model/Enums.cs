namespace PcapForensics.Core.Model;

public enum Severity { Info = 0, Low = 1, Medium = 2, High = 3, Critical = 4 }

public enum TransportProtocol { None, Tcp, Udp, Icmp, IcmpV6, Arp, Other }

[Flags]
public enum TcpFlags : ushort
{
    None = 0, Fin = 0x01, Syn = 0x02, Rst = 0x04, Psh = 0x08,
    Ack = 0x10, Urg = 0x20, Ece = 0x40, Cwr = 0x80, Ns = 0x100,
}

public enum AuthResult { Unknown, Success, Failure }

public enum FileCategory { Unknown, Executable, ActiveContent, Script, Archive, Document, Image, Media, Font, Web, Text }

public static class EnumText
{
    public static string ToKorean(this Severity s) => s switch
    {
        Severity.Critical => "심각",
        Severity.High => "높음",
        Severity.Medium => "보통",
        Severity.Low => "낮음",
        _ => "정보",
    };

    public static string ToKorean(this AuthResult r) => r switch
    {
        AuthResult.Success => "성공",
        AuthResult.Failure => "실패",
        _ => "알 수 없음",
    };

    public static string ToKorean(this FileCategory c) => c switch
    {
        FileCategory.Executable => "실행 파일",
        FileCategory.ActiveContent => "액티브 콘텐츠",
        FileCategory.Script => "스크립트",
        FileCategory.Archive => "압축 파일",
        FileCategory.Document => "문서",
        FileCategory.Image => "이미지",
        FileCategory.Media => "미디어",
        FileCategory.Font => "글꼴",
        FileCategory.Web => "웹 문서",
        FileCategory.Text => "텍스트",
        _ => "알 수 없음",
    };

    public static string ToText(this TcpFlags f)
    {
        var parts = new List<string>(6);
        if (f.HasFlag(TcpFlags.Syn)) parts.Add("SYN");
        if (f.HasFlag(TcpFlags.Ack)) parts.Add("ACK");
        if (f.HasFlag(TcpFlags.Psh)) parts.Add("PSH");
        if (f.HasFlag(TcpFlags.Fin)) parts.Add("FIN");
        if (f.HasFlag(TcpFlags.Rst)) parts.Add("RST");
        if (f.HasFlag(TcpFlags.Urg)) parts.Add("URG");
        return string.Join(", ", parts);
    }
}
