using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;

namespace PcapForensics.Core.Capture;

/// <summary>캡처할 수 있는 네트워크 인터페이스(실제·가상·루프백 포함).</summary>
public sealed class CaptureDevice
{
    public string Name { get; init; } = "";
    public string Description { get; init; } = "";
    public string FriendlyName { get; init; } = "";
    public string Kind { get; init; } = "";
    public string Status { get; init; } = "";
    public bool IsConnected { get; init; }
    public bool IsLoopback { get; init; }
    public List<string> Addresses { get; init; } = new();

    public string DisplayName => FriendlyName.Length > 0 ? FriendlyName : Description.Length > 0 ? Description : Name;
    public string AddressText => string.Join(", ", Addresses);
}

public static class CaptureDevices
{
    const uint IfLoopback = 0x1, IfUp = 0x2, IfRunning = 0x4, IfWireless = 0x8, IfStatusMask = 0x30, IfConnected = 0x10, IfDisconnected = 0x20;

    /// <summary>캡처 라이브러리 버전 문자열(예: "Npcap version 1.10.4, based on libpcap version 1.10.4").</summary>
    public static string LibraryVersion()
    {
        if (!NativePcap.TryLoad(out var error)) return error;
        return Marshal.PtrToStringAnsi(NativePcap.pcap_lib_version()) ?? "";
    }

    public static bool IsAvailable(out string error) => NativePcap.TryLoad(out error);

    public static List<CaptureDevice> List()
    {
        if (!NativePcap.TryLoad(out var loadError)) throw new InvalidOperationException(loadError);

        var errbuf = new byte[NativePcap.ErrBufSize];
        if (NativePcap.pcap_findalldevs(out var all, errbuf) != 0)
            throw new InvalidOperationException("네트워크 인터페이스 목록을 가져오지 못했습니다: " + NativePcap.ErrorText(errbuf));

        // Windows 어댑터 이름(이더넷, Wi-Fi, vEthernet (WSL) 등)과 상태를 GUID 로 연결
        var nics = new Dictionary<string, NetworkInterface>(StringComparer.OrdinalIgnoreCase);
        try
        {
            foreach (var n in NetworkInterface.GetAllNetworkInterfaces()) nics[n.Id] = n;
        }
        catch (NetworkInformationException) { }

        var list = new List<CaptureDevice>();
        try
        {
            int ps = IntPtr.Size;
            for (var dev = all; dev != IntPtr.Zero; dev = Marshal.ReadIntPtr(dev, 0))
            {
                string name = Marshal.PtrToStringAnsi(Marshal.ReadIntPtr(dev, ps)) ?? "";
                string desc = Marshal.PtrToStringAnsi(Marshal.ReadIntPtr(dev, ps * 2)) ?? "";
                var addrList = Marshal.ReadIntPtr(dev, ps * 3);
                uint flags = (uint)Marshal.ReadInt32(dev, ps * 4);

                int brace = name.IndexOf('{');
                nics.TryGetValue(brace >= 0 ? name[brace..] : "", out var nic);
                bool loopback = (flags & IfLoopback) != 0 || name.Contains("Loopback", StringComparison.OrdinalIgnoreCase);

                bool connected = nic is not null
                    ? nic.OperationalStatus == OperationalStatus.Up
                    : (flags & IfStatusMask) == IfConnected || ((flags & IfStatusMask) != IfDisconnected && (flags & (IfUp | IfRunning)) == (IfUp | IfRunning));
                if (loopback) connected = true;

                list.Add(new CaptureDevice
                {
                    Name = name,
                    Description = desc,
                    FriendlyName = loopback && nic is null ? "루프백 (이 PC 내부 통신)" : nic?.Name ?? "",
                    Kind = KindOf(desc, nic, flags, loopback),
                    Status = connected ? "연결됨" : (flags & IfStatusMask) == IfDisconnected || nic?.OperationalStatus == OperationalStatus.Down ? "연결 끊김" : "알 수 없음",
                    IsConnected = connected,
                    IsLoopback = loopback,
                    Addresses = ReadAddresses(addrList),
                });
            }
        }
        finally
        {
            NativePcap.pcap_freealldevs(all);
        }

        // 연결된 장치, 실제 장치를 먼저 보여 준다
        return list.OrderByDescending(d => d.IsConnected)
            .ThenBy(d => d.Kind switch { "유선" => 0, "무선" => 1, "가상" => 2, "루프백" => 3, _ => 4 })
            .ThenBy(d => d.DisplayName, StringComparer.CurrentCulture)
            .ToList();
    }

    static string KindOf(string desc, NetworkInterface? nic, uint flags, bool loopback)
    {
        if (loopback) return "루프백";
        string text = desc + " " + (nic?.Description ?? "") + " " + (nic?.Name ?? "");
        string[] virtualHints = { "Virtual", "VMware", "VirtualBox", "Hyper-V", "vEthernet", "TAP-", "Wintun", "WireGuard", "Docker", "WSL", "Wi-Fi Direct", "Npcap Loopback" };
        if (text.Contains("WAN Miniport", StringComparison.OrdinalIgnoreCase)) return "WAN 미니포트";
        if (text.Contains("Bluetooth", StringComparison.OrdinalIgnoreCase)) return "블루투스";
        if (virtualHints.Any(h => text.Contains(h, StringComparison.OrdinalIgnoreCase))) return "가상";
        if ((flags & IfWireless) != 0 || nic?.NetworkInterfaceType == NetworkInterfaceType.Wireless80211) return "무선";
        return "유선";
    }

    static List<string> ReadAddresses(IntPtr addr)
    {
        var result = new List<string>();
        int ps = IntPtr.Size;
        for (; addr != IntPtr.Zero; addr = Marshal.ReadIntPtr(addr, 0))
        {
            var sa = Marshal.ReadIntPtr(addr, ps);
            if (sa == IntPtr.Zero) continue;
            int family = Marshal.ReadInt16(sa, 0);
            if (family == 2)
            {
                var b = new byte[4];
                Marshal.Copy(sa + 4, b, 0, 4);
                result.Add(new IPAddress(b).ToString());
            }
            else if (family is 23 or 10 or 30) // AF_INET6: Windows 23, Linux 10, macOS 30
            {
                var b = new byte[16];
                Marshal.Copy(sa + 8, b, 0, 16);
                result.Add(new IPAddress(b).ToString());
            }
        }
        return result;
    }
}
