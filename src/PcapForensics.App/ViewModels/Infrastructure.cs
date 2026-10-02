using System.Collections;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;

namespace PcapForensics.App.ViewModels;

public abstract class ObservableObject : INotifyPropertyChanged
{
    public event PropertyChangedEventHandler? PropertyChanged;

    protected bool Set<T>(ref T field, T value, [CallerMemberName] string? name = null)
    {
        if (EqualityComparer<T>.Default.Equals(field, value)) return false;
        field = value;
        Raise(name!);
        return true;
    }

    protected void Raise(string name) => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}

public sealed class RelayCommand : ICommand
{
    readonly Action<object?> _execute;
    readonly Func<object?, bool>? _canExecute;

    public RelayCommand(Action<object?> execute, Func<object?, bool>? canExecute = null)
    {
        _execute = execute;
        _canExecute = canExecute;
    }

    public event EventHandler? CanExecuteChanged
    {
        add => CommandManager.RequerySuggested += value;
        remove => CommandManager.RequerySuggested -= value;
    }

    public bool CanExecute(object? parameter) => _canExecute?.Invoke(parameter) ?? true;
    public void Execute(object? parameter) => _execute(parameter);
}

public sealed record BarItem(string Label, string Tooltip, double Ratio, string Display, Brush Brush);

/// <summary>
/// 검색어로 거를 수 있는 목록. 공백으로 구분한 모든 단어를 포함하는 항목만 표시한다.
/// '키:값' 형식의 특수 토큰은 <see cref="TokenMatcher"/>가 처리한다.
/// </summary>
public sealed class FilteredList<T> : ObservableObject where T : class
{
    readonly Func<T, string> _text;
    readonly DispatcherTimer _debounce;
    string _filter = "";
    int _total;

    public FilteredList(Func<T, string> text)
    {
        _text = text;
        _debounce = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(250) };
        _debounce.Tick += (_, _) =>
        {
            _debounce.Stop();
            Refresh();
        };
        View = new ListCollectionView(new List<T>());
    }

    public ListCollectionView View { get; private set; }

    /// <summary>특수 토큰 처리: 처리했으면 일치 여부, 일반 토큰이면 null.</summary>
    public Func<T, string, bool?>? TokenMatcher { get; init; }

    /// <summary>검색어 외 추가 조건(예: 분류 선택).</summary>
    public Func<T, bool>? ExtraFilter { get; set; }

    public string Filter
    {
        get => _filter;
        set
        {
            if (!Set(ref _filter, value)) return;
            _debounce.Stop();
            _debounce.Start();
        }
    }

    public string CountText => View.Count == _total ? $"{_total:N0}건" : $"{View.Count:N0} / {_total:N0}건";

    public void SetItems(IList<T> items)
    {
        _total = items.Count;
        View = new ListCollectionView((IList)items) { Filter = Match };
        Raise(nameof(View));
        Raise(nameof(CountText));
    }

    public void SetFilterNow(string filter)
    {
        _filter = filter;
        Raise(nameof(Filter));
        Refresh();
    }

    public void Refresh()
    {
        View.Refresh();
        Raise(nameof(CountText));
    }

    bool Match(object o)
    {
        var item = (T)o;
        if (ExtraFilter is not null && !ExtraFilter(item)) return false;
        if (string.IsNullOrWhiteSpace(_filter)) return true;

        string? text = null;
        foreach (var term in _filter.Split(' ', StringSplitOptions.RemoveEmptyEntries))
        {
            var special = TokenMatcher?.Invoke(item, term);
            if (special.HasValue)
            {
                if (!special.Value) return false;
                continue;
            }
            text ??= _text(item);
            if (!text.Contains(term, StringComparison.OrdinalIgnoreCase)) return false;
        }
        return true;
    }
}
