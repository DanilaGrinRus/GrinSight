import 'package:flutter/material.dart';

/// Монохромная тема делается фильтром поверх всего приложения, а он красит в серое
/// и логотип, и кнопки. Чтобы логотип и кнопка под курсором оставались
/// чёрно-золотыми, их цветная копия рисуется в отдельном слое над фильтром,
/// точно поверх оригинала (CompositedTransformFollower следует за положением,
/// в том числе при прокрутке).
class GoldLayerController extends ChangeNotifier {
  final Map<Object, GoldEntry> _entries = <Object, GoldEntry>{};

  Iterable<GoldEntry> get entries => _entries.values;

  void put(Object key, GoldEntry entry) {
    _entries[key] = entry;
    notifyListeners();
  }

  void remove(Object key) {
    if (_entries.remove(key) != null) notifyListeners();
  }
}

class GoldEntry {
  const GoldEntry({required this.link, required this.size, required this.child});
  final LayerLink link;
  final Size size;
  final Widget child;
}

class GoldLayerScope extends InheritedWidget {
  const GoldLayerScope({super.key, required this.controller, required this.mono, this.onMonoChanged, required super.child});
  final GoldLayerController controller;
  final bool mono;
  /// Переключение темы (цветная / ч/б) из любого экрана — см. UThemeToggle.
  final ValueChanged<bool>? onMonoChanged;

  static GoldLayerScope? maybeOf(BuildContext context) => context.dependOnInheritedWidgetOfExactType<GoldLayerScope>();

  @override
  bool updateShouldNotify(GoldLayerScope oldWidget) => oldWidget.mono != mono || oldWidget.controller != controller;
}

/// Слой цветных копий (над монохромным фильтром). Нажатия проходят насквозь.
class GoldLayerView extends StatelessWidget {
  const GoldLayerView({super.key, required this.controller});
  final GoldLayerController controller;

  @override
  Widget build(BuildContext context) {
    // Слой лежит вне Material и вне темы текста: без этой обёртки Flutter рисует
    // текст копии с жёлтым двойным подчёркиванием («нет Material-предка»).
    return IgnorePointer(
      child: Material(
        type: MaterialType.transparency,
        child: ListenableBuilder(
        listenable: controller,
        builder: (BuildContext context, _) => Stack(
          children: [
            for (final GoldEntry e in controller.entries)
              Positioned(
                left: 0,
                top: 0,
                child: CompositedTransformFollower(
                  link: e.link,
                  showWhenUnlinked: false,
                  child: SizedBox.fromSize(size: e.size, child: e.child),
                ),
              ),
          ],
        ),
      ),
      ),
    );
  }
}

/// Оборачивает элемент: в монохромной теме, когда [active], поверх него
/// показывается цветная версия [gold]. Если открыто окно поверх экрана — не показывает.
class GoldTarget extends StatefulWidget {
  const GoldTarget({super.key, required this.active, required this.gold, required this.child});
  final bool active;
  final Widget gold;
  final Widget child;

  @override
  State<GoldTarget> createState() => _GoldTargetState();
}

class _GoldTargetState extends State<GoldTarget> {
  final LayerLink _link = LayerLink();
  final Object _key = Object();
  GoldLayerController? _controller;

  @override
  Widget build(BuildContext context) {
    final GoldLayerScope? scope = GoldLayerScope.maybeOf(context);
    final bool current = ModalRoute.of(context)?.isCurrent ?? true;
    final bool want = scope != null && scope.mono && widget.active && current;
    final GoldLayerController? controller = scope?.controller;
    if (want || _controller != null) {
      WidgetsBinding.instance.addPostFrameCallback((_) {
        if (!mounted) return;
        if (_controller != null && _controller != controller) _controller!.remove(_key);
        _controller = controller;
        if (controller == null) return;
        final Size? size = context.size;
        if (want && size != null && !size.isEmpty) {
          controller.put(_key, GoldEntry(link: _link, size: size, child: widget.gold));
        } else {
          controller.remove(_key);
          _controller = null;
        }
      });
    }
    return CompositedTransformTarget(link: _link, child: widget.child);
  }

  @override
  void dispose() {
    final GoldLayerController? c = _controller;
    if (c != null) WidgetsBinding.instance.addPostFrameCallback((_) => c.remove(_key));
    super.dispose();
  }
}
