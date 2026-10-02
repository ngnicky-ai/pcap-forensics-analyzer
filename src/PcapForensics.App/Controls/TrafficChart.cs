using System.Globalization;
using System.Windows;
using System.Windows.Media;
using PcapForensics.Core.Util;

namespace PcapForensics.App.Controls;

/// <summary>시간대별 트래픽량을 영역 그래프로 그리는 경량 컨트롤.</summary>
public sealed class TrafficChart : FrameworkElement
{
    public static readonly DependencyProperty ValuesProperty = DependencyProperty.Register(
        nameof(Values), typeof(IReadOnlyList<double>), typeof(TrafficChart),
        new FrameworkPropertyMetadata(null, FrameworkPropertyMetadataOptions.AffectsRender));

    public static readonly DependencyProperty StartLabelProperty = DependencyProperty.Register(
        nameof(StartLabel), typeof(string), typeof(TrafficChart),
        new FrameworkPropertyMetadata("", FrameworkPropertyMetadataOptions.AffectsRender));

    public static readonly DependencyProperty EndLabelProperty = DependencyProperty.Register(
        nameof(EndLabel), typeof(string), typeof(TrafficChart),
        new FrameworkPropertyMetadata("", FrameworkPropertyMetadataOptions.AffectsRender));

    public IReadOnlyList<double>? Values
    {
        get => (IReadOnlyList<double>?)GetValue(ValuesProperty);
        set => SetValue(ValuesProperty, value);
    }

    public string StartLabel
    {
        get => (string)GetValue(StartLabelProperty);
        set => SetValue(StartLabelProperty, value);
    }

    public string EndLabel
    {
        get => (string)GetValue(EndLabelProperty);
        set => SetValue(EndLabelProperty, value);
    }

    static readonly Brush AxisText = Frozen(new SolidColorBrush(Color.FromRgb(0x64, 0x74, 0x8B)));
    static readonly Pen GridPen = Frozen(new Pen(new SolidColorBrush(Color.FromRgb(0xE2, 0xE8, 0xF0)), 1));
    static readonly Pen LinePen = Frozen(new Pen(new SolidColorBrush(Color.FromRgb(0x25, 0x63, 0xEB)), 1.5));
    static readonly Brush AreaBrush = Frozen(new SolidColorBrush(Color.FromArgb(0x33, 0x25, 0x63, 0xEB)));

    static T Frozen<T>(T f) where T : Freezable
    {
        f.Freeze();
        return f;
    }

    protected override void OnRender(DrawingContext dc)
    {
        double w = ActualWidth, h = ActualHeight;
        dc.DrawRectangle(Brushes.Transparent, null, new Rect(0, 0, w, h));
        var values = Values;
        double dpi = VisualTreeHelper.GetDpi(this).PixelsPerDip;

        if (values is null || values.Count < 2)
        {
            dc.DrawText(Text("데이터 없음", dpi), new Point(8, 8));
            return;
        }

        const double left = 64, right = 8, top = 8, bottom = 22;
        double pw = w - left - right, ph = h - top - bottom;
        if (pw <= 10 || ph <= 10) return;

        double max = Math.Max(1, values.Max());
        for (int i = 0; i <= 4; i++)
        {
            double y = top + ph * i / 4;
            dc.DrawLine(GridPen, new Point(left, y), new Point(left + pw, y));
            var label = Text(TimeFormat.Bytes((long)(max * (4 - i) / 4)), dpi);
            dc.DrawText(label, new Point(left - label.Width - 6, y - label.Height / 2));
        }

        var geo = new StreamGeometry();
        using (var ctx = geo.Open())
        {
            ctx.BeginFigure(new Point(left, top + ph), true, true);
            for (int i = 0; i < values.Count; i++)
                ctx.LineTo(new Point(left + pw * i / (values.Count - 1), top + ph * (1 - values[i] / max)), true, false);
            ctx.LineTo(new Point(left + pw, top + ph), false, false);
        }
        geo.Freeze();
        dc.DrawGeometry(AreaBrush, null, geo);

        var line = new StreamGeometry();
        using (var ctx = line.Open())
        {
            ctx.BeginFigure(new Point(left, top + ph * (1 - values[0] / max)), false, false);
            for (int i = 1; i < values.Count; i++)
                ctx.LineTo(new Point(left + pw * i / (values.Count - 1), top + ph * (1 - values[i] / max)), true, true);
        }
        line.Freeze();
        dc.DrawGeometry(null, LinePen, line);

        var start = Text(StartLabel, dpi);
        var end = Text(EndLabel, dpi);
        dc.DrawText(start, new Point(left, top + ph + 4));
        dc.DrawText(end, new Point(left + pw - end.Width, top + ph + 4));
    }

    static FormattedText Text(string s, double dpi) =>
        new(s, CultureInfo.CurrentUICulture, FlowDirection.LeftToRight, new Typeface("Malgun Gothic"), 11, AxisText, dpi);
}
