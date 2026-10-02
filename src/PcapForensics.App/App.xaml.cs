using System.Windows;
using System.Windows.Threading;

namespace PcapForensics.App;

public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        DispatcherUnhandledException += OnUnhandledException;
        base.OnStartup(e);
    }

    static void OnUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        MessageBox.Show($"예기치 않은 오류가 발생했습니다.\n\n{e.Exception.Message}", "PCAP 침해사고 분석기",
            MessageBoxButton.OK, MessageBoxImage.Error);
        e.Handled = true;
    }
}
