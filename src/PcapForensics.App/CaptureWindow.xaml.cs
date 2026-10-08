using System.ComponentModel;
using System.Windows;
using System.Windows.Input;
using PcapForensics.App.ViewModels;
using PcapForensics.Core.Capture;

namespace PcapForensics.App;

public partial class CaptureWindow : Window
{
    readonly CaptureViewModel _vm;
    bool _completed;

    public CaptureWindow(CaptureSettings settings, double zoom)
    {
        InitializeComponent();
        _vm = new CaptureViewModel(settings);
        DataContext = _vm;
        ZoomTransform.ScaleX = ZoomTransform.ScaleY = zoom;
        _vm.CaptureCompleted += path =>
        {
            CapturedFile = path;
            _completed = true;
            Close();
        };
    }

    /// <summary>분석할 캡처 파일(자동 분석 또는 [저장한 캡처 분석하기]).</summary>
    public string? CapturedFile { get; private set; }
    public string CaptureNote => _vm.CaptureNote;

    protected override void OnClosing(CancelEventArgs e)
    {
        if (!_completed && _vm.IsCapturing)
        {
            var answer = MessageBox.Show("모니터링 중입니다. 캡처를 멈추고 지금까지의 내용을 분석할까요?\n\n[예] 멈추고 분석  [아니요] 멈추고 닫기  [취소] 계속 모니터링",
                "실시간 모니터링", MessageBoxButton.YesNoCancel, MessageBoxImage.Question);
            if (answer == MessageBoxResult.Cancel)
            {
                e.Cancel = true;
                return;
            }
            if (answer == MessageBoxResult.Yes)
            {
                e.Cancel = true;
                _vm.AutoAnalyze = true;
                _ = _vm.FinishAsync();
                return;
            }
        }
        _vm.StopIfRunning();
        base.OnClosing(e);
    }

    // 본창과 같은 확대/축소 (Ctrl+휠, Ctrl +/-/0)
    void Window_PreviewMouseWheel(object sender, MouseWheelEventArgs e)
    {
        if (Keyboard.Modifiers != ModifierKeys.Control) return;
        SetZoom(ZoomTransform.ScaleX + (e.Delta > 0 ? 0.1 : -0.1));
        e.Handled = true;
    }

    void Window_PreviewKeyDown(object sender, KeyEventArgs e)
    {
        if (Keyboard.Modifiers != ModifierKeys.Control) return;
        double? z = e.Key switch
        {
            Key.OemPlus or Key.Add => ZoomTransform.ScaleX + 0.1,
            Key.OemMinus or Key.Subtract => ZoomTransform.ScaleX - 0.1,
            Key.D0 or Key.NumPad0 => 1.0,
            _ => null,
        };
        if (z is null) return;
        SetZoom(z.Value);
        e.Handled = true;
    }

    void SetZoom(double z) => ZoomTransform.ScaleX = ZoomTransform.ScaleY = Math.Round(Math.Clamp(z, 0.6, 2.5), 2);
}
