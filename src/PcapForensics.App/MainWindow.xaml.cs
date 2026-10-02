using System.Globalization;
using System.IO;
using System.Windows;
using System.Windows.Input;
using PcapForensics.App.ViewModels;

namespace PcapForensics.App;

public partial class MainWindow : Window
{
    const double MinZoom = 0.6, MaxZoom = 2.5, ZoomStep = 0.1;

    static readonly string ZoomFile = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "PcapForensics", "zoom.txt");

    readonly MainViewModel _vm = new();
    double _zoom = 1.0;

    public MainWindow()
    {
        InitializeComponent();
        DataContext = _vm;
        SetZoom(LoadZoom(), save: false);
        Loaded += async (_, _) =>
        {
            // 명령줄 인수 또는 파일 연결로 전달된 캡처 파일을 바로 분석
            var args = Environment.GetCommandLineArgs();
            if (args.Length > 1 && File.Exists(args[1])) await _vm.OpenFileAsync(args[1]);
        };
    }

    void Window_DragOver(object sender, DragEventArgs e)
    {
        e.Effects = e.Data.GetDataPresent(DataFormats.FileDrop) ? DragDropEffects.Copy : DragDropEffects.None;
        e.Handled = true;
    }

    async void Window_Drop(object sender, DragEventArgs e)
    {
        if (e.Data.GetData(DataFormats.FileDrop) is string[] { Length: > 0 } files)
            await _vm.OpenFileAsync(files[0]);
    }

    // ---------- 확대/축소 ----------

    void Window_PreviewMouseWheel(object sender, MouseWheelEventArgs e)
    {
        if (Keyboard.Modifiers != ModifierKeys.Control) return;
        SetZoom(_zoom + (e.Delta > 0 ? ZoomStep : -ZoomStep));
        e.Handled = true; // 목록/텍스트 상자가 스크롤되지 않도록
    }

    void Window_PreviewKeyDown(object sender, KeyEventArgs e)
    {
        if (Keyboard.Modifiers != ModifierKeys.Control) return;
        switch (e.Key)
        {
            case Key.OemPlus or Key.Add:
                SetZoom(_zoom + ZoomStep);
                break;
            case Key.OemMinus or Key.Subtract:
                SetZoom(_zoom - ZoomStep);
                break;
            case Key.D0 or Key.NumPad0:
                SetZoom(1.0);
                break;
            default:
                return;
        }
        e.Handled = true;
    }

    void SetZoom(double zoom, bool save = true)
    {
        _zoom = Math.Round(Math.Clamp(zoom, MinZoom, MaxZoom), 2);
        ZoomTransform.ScaleX = ZoomTransform.ScaleY = _zoom;
        ZoomText.Text = $"{_zoom * 100:F0}%";
        if (save) SaveZoom();
    }

    static double LoadZoom()
    {
        try
        {
            return File.Exists(ZoomFile) && double.TryParse(File.ReadAllText(ZoomFile), NumberStyles.Float, CultureInfo.InvariantCulture, out var z) ? z : 1.0;
        }
        catch (IOException) { return 1.0; }
        catch (UnauthorizedAccessException) { return 1.0; }
    }

    void SaveZoom()
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(ZoomFile)!);
            File.WriteAllText(ZoomFile, _zoom.ToString(CultureInfo.InvariantCulture));
        }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }
}
