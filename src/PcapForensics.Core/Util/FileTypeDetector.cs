using System.Buffers.Binary;

namespace PcapForensics.Core.Util;

/// <summary>매직 바이트로 실제 파일 형식을 판별한다(Content-Type/확장자 위장 대응).</summary>
public static class FileTypeDetector
{
    public static (string Kind, FileCategory Category) Detect(byte[] d, string? contentType = null)
    {
        contentType = (contentType ?? "").ToLowerInvariant();
        if (d.Length == 0) return ("비어 있음", FileCategory.Unknown);

        if (Starts(d, "MZ")) return DetectPe(d);
        if (d.Length >= 4 && d[0] == 0x7F && Starts(d, 1, "ELF")) return ("ELF 실행 파일", FileCategory.Executable);
        if (d.Length >= 4 && d[0] == 0xCA && d[1] == 0xFE && d[2] == 0xBA && d[3] == 0xBE) return ("Java Class", FileCategory.ActiveContent);
        if (Starts(d, "FWS") || Starts(d, "CWS") || Starts(d, "ZWS")) return ("Flash(SWF)", FileCategory.ActiveContent);
        if (Starts(d, "%PDF")) return ("PDF", FileCategory.Document);
        if (d.Length >= 4 && d[0] == 0xD0 && d[1] == 0xCF && d[2] == 0x11 && d[3] == 0xE0) return ("OLE 복합 문서(Office 97/MSI)", FileCategory.Document);
        if (Starts(d, "PK\u0003\u0004")) return DetectZip(d);
        if (Starts(d, "Rar!")) return ("RAR", FileCategory.Archive);
        if (d.Length >= 6 && d[0] == '7' && d[1] == 'z' && d[2] == 0xBC && d[3] == 0xAF) return ("7-Zip", FileCategory.Archive);
        if (d.Length >= 2 && d[0] == 0x1F && d[1] == 0x8B) return ("GZIP", FileCategory.Archive);
        if (Starts(d, "MSCF")) return ("CAB", FileCategory.Archive);
        if (d.Length >= 3 && d[0] == 0xFF && d[1] == 0xD8 && d[2] == 0xFF) return ("JPEG", FileCategory.Image);
        if (d.Length >= 8 && d[0] == 0x89 && Starts(d, 1, "PNG")) return ("PNG", FileCategory.Image);
        if (Starts(d, "GIF8")) return ("GIF", FileCategory.Image);
        if (Starts(d, "BM") && d.Length > 14 && contentType.Contains("image")) return ("BMP", FileCategory.Image);
        if (d.Length >= 4 && d[0] == 0 && d[1] == 0 && d[2] == 1 && d[3] == 0) return ("ICO", FileCategory.Image);
        if (Starts(d, "RIFF") && d.Length >= 12)
            return Starts(d, 8, "WEBP") ? ("WEBP", FileCategory.Image) : ("RIFF 미디어", FileCategory.Media);
        if (Starts(d, "wOFF") || Starts(d, "wOF2") || Starts(d, "OTTO")) return ("웹 글꼴", FileCategory.Font);
        if (d.Length > 36 && d[34] == 0x4C && d[35] == 0x50) return ("EOT 글꼴", FileCategory.Font);
        if (d.Length >= 12 && d[0] == 0 && d[1] == 1 && d[2] == 0 && d[3] == 0) return ("TrueType 글꼴", FileCategory.Font);
        if (d.Length >= 8 && Starts(d, 4, "ftyp")) return ("MP4/MOV", FileCategory.Media);
        if (Starts(d, "ID3") || (d.Length > 1 && d[0] == 0xFF && (d[1] & 0xE0) == 0xE0 && contentType.Contains("audio"))) return ("MP3", FileCategory.Media);

        if (TextUtil.LooksLikeText(d))
        {
            var head = TextUtil.Latin1.GetString(d, 0, Math.Min(d.Length, 512)).TrimStart('﻿', 'ï', '»', '¿', ' ', '\r', '\n', '\t').ToLowerInvariant();
            if (head.StartsWith("<!doctype html") || head.StartsWith("<html") || head.StartsWith("<head") || head.StartsWith("<script")
                || contentType.Contains("html"))
                return ("HTML", FileCategory.Web);
            if (head.StartsWith("<?xml") || contentType.Contains("xml")) return ("XML", FileCategory.Web);
            if (contentType.Contains("javascript") || contentType.Contains("ecmascript")) return ("JavaScript", FileCategory.Web);
            if (contentType.Contains("css")) return ("CSS", FileCategory.Web);
            if (contentType.Contains("json") || head.StartsWith("{") || head.StartsWith("[")) return ("JSON", FileCategory.Text);
            if (head.StartsWith("#!") || contentType.Contains("x-sh")) return ("셸 스크립트", FileCategory.Script);
            if (contentType.Contains("hta")) return ("HTA", FileCategory.Script);
            if (head.Contains("powershell") || head.Contains("wscript.shell") || head.Contains("createobject(")) return ("스크립트", FileCategory.Script);
            return ("텍스트", FileCategory.Text);
        }

        return ("바이너리(알 수 없음)", FileCategory.Unknown);
    }

    static (string, FileCategory) DetectPe(byte[] d)
    {
        if (d.Length >= 0x40)
        {
            int peOff = BinaryPrimitives.ReadInt32LittleEndian(d.AsSpan(0x3C));
            if (peOff > 0 && peOff + 24 <= d.Length && Starts(d, peOff, "PE\0\0"))
            {
                ushort characteristics = BinaryPrimitives.ReadUInt16LittleEndian(d.AsSpan(peOff + 22));
                return (characteristics & 0x2000) != 0 ? ("PE DLL", FileCategory.Executable) : ("PE 실행 파일(EXE)", FileCategory.Executable);
            }
        }
        return ("MZ 실행 파일(손상 가능)", FileCategory.Executable);
    }

    static (string, FileCategory) DetectZip(byte[] d)
    {
        var head = TextUtil.Latin1.GetString(d, 0, Math.Min(d.Length, 8192));
        if (head.Contains("AndroidManifest.xml") || head.Contains("classes.dex")) return ("Android APK", FileCategory.Executable);
        if (head.Contains("META-INF/") || head.Contains(".class")) return ("Java JAR", FileCategory.ActiveContent);
        if (head.Contains("AppManifest.xaml")) return ("Silverlight XAP", FileCategory.ActiveContent);
        if (head.Contains("[Content_Types].xml") || head.Contains("word/") || head.Contains("xl/") || head.Contains("ppt/"))
            return ("Office 문서(OOXML)", FileCategory.Document);
        return ("ZIP", FileCategory.Archive);
    }

    static bool Starts(byte[] d, string token) => ByteUtil.StartsWithAscii(d, 0, token);
    static bool Starts(byte[] d, int pos, string token) => ByteUtil.StartsWithAscii(d, pos, token);
}
