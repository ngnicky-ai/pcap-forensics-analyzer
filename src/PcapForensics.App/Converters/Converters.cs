using System.Globalization;
using System.Windows;
using System.Windows.Data;
using System.Windows.Media;
using PcapForensics.Core.Model;

namespace PcapForensics.App.Converters;

public sealed class SeverityBrushConverter : IValueConverter
{
    static readonly Dictionary<Severity, SolidColorBrush> Brushes = new()
    {
        [Severity.Critical] = Make("#B91C1C"),
        [Severity.High] = Make("#EA580C"),
        [Severity.Medium] = Make("#CA8A04"),
        [Severity.Low] = Make("#2563EB"),
        [Severity.Info] = Make("#64748B"),
    };

    public static SolidColorBrush For(Severity s) => Brushes[s];

    static SolidColorBrush Make(string hex)
    {
        var b = new SolidColorBrush((Color)ColorConverter.ConvertFromString(hex));
        b.Freeze();
        return b;
    }

    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        value is Severity s ? Brushes[s] : System.Windows.Media.Brushes.Transparent;

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) => throw new NotSupportedException();
}

public sealed class InverseBoolToVisibilityConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        value is true ? Visibility.Collapsed : Visibility.Visible;

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) => throw new NotSupportedException();
}

/// <summary>null/빈 문자열이면 숨김. ConverterParameter=inverse 이면 반대.</summary>
public sealed class NullToCollapsedConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        bool empty = value is null || (value is string s && s.Length == 0);
        if (parameter as string == "inverse") empty = !empty;
        return empty ? Visibility.Collapsed : Visibility.Visible;
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) => throw new NotSupportedException();
}

public sealed class InverseBoolConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) => value is not true;
    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) => value is not true;
}

public sealed class JoinLinesConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        value is IEnumerable<string> lines ? string.Join(Environment.NewLine, lines.Select(l => "• " + l)) : "";

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) => throw new NotSupportedException();
}
