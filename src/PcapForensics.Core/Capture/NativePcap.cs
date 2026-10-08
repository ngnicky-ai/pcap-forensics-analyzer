using System.Reflection;
using System.Runtime.InteropServices;

namespace PcapForensics.Core.Capture;

/// <summary>
/// Npcap(Windows) / libpcap(Linux) 의 C API 를 직접 호출한다.
/// Npcap 은 기본적으로 System32\Npcap 에 설치되므로(WinPcap 호환 모드가 아니면 PATH 에 없음) 그 위치에서 직접 불러온다.
/// </summary>
internal static class NativePcap
{
    const string Lib = "wpcap";
    public const int ErrBufSize = 256;

    static readonly object Gate = new();
    static IntPtr _handle;
    static string? _loadError;

    /// <summary>캡처 라이브러리를 불러온다. 실패하면 사용자에게 보여 줄 이유를 돌려준다.</summary>
    public static bool TryLoad(out string error)
    {
        lock (Gate)
        {
            if (_handle != IntPtr.Zero) { error = ""; return true; }
            if (_loadError is not null) { error = _loadError; return false; }

            var candidates = new List<string>();
            if (OperatingSystem.IsWindows())
            {
                var npcapDir = Path.Combine(Environment.SystemDirectory, "Npcap");
                if (Directory.Exists(npcapDir))
                {
                    SetDllDirectory(npcapDir); // wpcap.dll 이 같은 폴더의 Packet.dll 을 찾도록
                    candidates.Add(Path.Combine(npcapDir, "wpcap.dll"));
                }
                candidates.Add("wpcap.dll");
            }
            else
            {
                candidates.AddRange(new[] { "libpcap.so.1", "libpcap.so", "libpcap.dylib" });
            }

            foreach (var c in candidates)
            {
                if (NativeLibrary.TryLoad(c, out _handle)) break;
            }

            if (_handle == IntPtr.Zero)
            {
                _loadError = OperatingSystem.IsWindows()
                    ? "Npcap 이 설치되어 있지 않습니다. https://npcap.com 에서 Npcap 을 설치한 뒤 다시 시도하십시오."
                    : "libpcap 을 찾을 수 없습니다. 패키지 관리자로 libpcap 을 설치하십시오.";
                error = _loadError;
                return false;
            }

            NativeLibrary.SetDllImportResolver(typeof(NativePcap).Assembly, Resolve);
            error = "";
            return true;
        }
    }

    static IntPtr Resolve(string name, Assembly asm, DllImportSearchPath? path) => name == Lib ? _handle : IntPtr.Zero;

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool SetDllDirectory(string path);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    public static extern int pcap_findalldevs(out IntPtr alldevs, byte[] errbuf);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    public static extern void pcap_freealldevs(IntPtr alldevs);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr pcap_create([MarshalAs(UnmanagedType.LPStr)] string source, byte[] errbuf);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    public static extern int pcap_set_snaplen(IntPtr p, int snaplen);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    public static extern int pcap_set_promisc(IntPtr p, int promisc);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    public static extern int pcap_set_timeout(IntPtr p, int ms);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    public static extern int pcap_set_buffer_size(IntPtr p, int bytes);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    public static extern int pcap_activate(IntPtr p);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr pcap_geterr(IntPtr p);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    public static extern int pcap_datalink(IntPtr p);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    public static extern int pcap_next_ex(IntPtr p, out IntPtr header, out IntPtr data);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    public static extern void pcap_breakloop(IntPtr p);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    public static extern void pcap_close(IntPtr p);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    public static extern int pcap_stats(IntPtr p, ref PcapStat stats);

    [DllImport(Lib, CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr pcap_lib_version();

    [StructLayout(LayoutKind.Sequential)]
    public struct PcapStat
    {
        public uint Received;
        public uint Dropped;
        public uint InterfaceDropped;
    }

    public static string ErrorText(byte[] errbuf)
    {
        int n = Array.IndexOf(errbuf, (byte)0);
        return Encoding.Default.GetString(errbuf, 0, n < 0 ? errbuf.Length : n).Trim();
    }

    /// <summary>
    /// pcap_pkthdr 해석. Windows(LLP64)는 timeval 이 32비트 두 개(16바이트 헤더),
    /// 64비트 Linux/macOS 는 64비트 두 개(24바이트 헤더)다.
    /// </summary>
    public static (DateTime Time, int CapLen, int Len) ReadHeader(IntPtr hdr)
    {
        long sec, usec;
        int off;
        if (OperatingSystem.IsWindows() || IntPtr.Size == 4)
        {
            sec = (uint)Marshal.ReadInt32(hdr, 0);
            usec = (uint)Marshal.ReadInt32(hdr, 4);
            off = 8;
        }
        else
        {
            sec = Marshal.ReadInt64(hdr, 0);
            usec = Marshal.ReadInt64(hdr, 8);
            off = 16;
        }
        int caplen = Marshal.ReadInt32(hdr, off);
        int len = Marshal.ReadInt32(hdr, off + 4);
        var time = DateTime.UnixEpoch.AddTicks(sec * TimeSpan.TicksPerSecond + usec * 10);
        return (time, caplen, len);
    }
}
