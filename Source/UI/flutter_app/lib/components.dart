import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import 'l10n.dart';
import 'theme.dart';

/// Основная кнопка (мята) или вторичная (тёмная с рамкой).
class UButton extends StatelessWidget {
  const UButton({
    super.key,
    required this.label,
    this.icon,
    this.primary = false,
    this.height = 48,
    this.onTap,
    this.expand = true,
    this.dense = false,
  });

  final String label;
  final IconData? icon;
  final bool primary;
  final double height;
  final VoidCallback? onTap;
  final bool expand;
  final bool dense;

  @override
  Widget build(BuildContext context) {
    final Color bg = primary ? UPalette.mint : UPalette.surface;
    final Color fg = primary ? UPalette.mintInk : UPalette.text2;
    final Color border = primary ? UPalette.mint : UPalette.lineStrong;
    final double radius = height >= 60 ? 18 : 14;
    // Зона касания не ниже 36 (основные кнопки 48+): раньше встречались 30 и 32.
    final double h = height < 36 ? 36 : height;

    final Widget content = Container(
      width: expand ? double.infinity : null,
      height: h,
      padding: EdgeInsets.symmetric(horizontal: dense ? 13 : 18),
      decoration: BoxDecoration(
        color: bg,
        border: Border.all(color: border),
        borderRadius: BorderRadius.circular(radius),
        boxShadow: primary
            ? [
                BoxShadow(
                  // Мягкая тень по форме кнопки: большой blur давал «пятно»,
                  // которое выходило за край экрана.
                  color: UPalette.mint.withValues(alpha: 0.12),
                  blurRadius: 12,
                  offset: const Offset(0, 4),
                ),
              ]
            : null,
      ),
      child: Row(
        mainAxisSize: expand ? MainAxisSize.max : MainAxisSize.min,
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          if (icon != null) Icon(icon, size: dense ? 15 : 18, color: fg),
          if (icon != null) const SizedBox(width: 9),
          if (expand)
            Flexible(
              child: Text(
                label,
                maxLines: 1,
                overflow: TextOverflow.ellipsis,
                textAlign: TextAlign.center,
                style: uiStyle(
                  dense ? 12 : 13,
                  weight: FontWeight.w600,
                  color: fg,
                ),
              ),
            )
          else
            Text(
              label,
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
              style: uiStyle(
                dense ? 12 : 13,
                weight: FontWeight.w600,
                color: fg,
              ),
            ),
        ],
      ),
    );

    if (onTap == null) return content;
    return Material(
      color: Colors.transparent,
      child: InkWell(
        borderRadius: BorderRadius.circular(radius),
        onTap: onTap,
        child: content,
      ),
    );
  }
}

class UIconButton extends StatelessWidget {
  const UIconButton({
    super.key,
    required this.icon,
    this.onTap,
    this.size = 44,
    this.iconSize = 18,
    this.tooltip,
  });

  final IconData icon;
  final VoidCallback? onTap;
  final double size;
  final double iconSize;
  final String? tooltip;

  @override
  Widget build(BuildContext context) {
    // Зона касания не меньше 40x40 (значок остаётся своего размера).
    final double box = size < 40 ? 40 : size;
    final Widget button = Material(
      color: Colors.transparent,
      child: InkWell(
        borderRadius: BorderRadius.circular(box * 0.3),
        onTap: onTap,
        child: SizedBox(
          width: box,
          height: box,
          child: Icon(icon, size: iconSize, color: UPalette.text2),
        ),
      ),
    );
    if (tooltip == null) return button;
    return Tooltip(message: tooltip!, child: button);
  }
}

class UCard extends StatelessWidget {
  const UCard({
    super.key,
    required this.child,
    this.padding = const EdgeInsets.all(22),
    this.width,
    this.radius = 22,
  });

  final Widget child;
  final EdgeInsetsGeometry padding;
  final double? width;
  final double radius;

  @override
  Widget build(BuildContext context) {
    return Container(
      width: width,
      padding: padding,
      decoration: BoxDecoration(
        color: UPalette.surface,
        border: Border.all(color: UPalette.line),
        borderRadius: BorderRadius.circular(radius),
        boxShadow: const [
          BoxShadow(
            color: Color(0x2E000000),
            blurRadius: 40,
            offset: Offset(0, 12),
          ),
        ],
      ),
      child: child,
    );
  }
}

class SectionLabel extends StatelessWidget {
  const SectionLabel(this.text, {super.key, this.color = UPalette.text3});

  final String text;
  final Color color;

  @override
  Widget build(BuildContext context) {
    return Text(
      text.toUpperCase(),
      style: uiStyle(
        10.5,
        weight: FontWeight.w700,
        color: color,
      ).copyWith(letterSpacing: 1.2),
    );
  }
}

/// Сегментированный переключатель на N опций.
class USegmented extends StatelessWidget {
  const USegmented({
    super.key,
    required this.options,
    required this.selected,
    required this.onChanged,
    this.expand = false,
    this.height = 28,
    this.fontSize = 11.5,
  });
  final List<String> options;
  final int selected;
  final ValueChanged<int> onChanged;
  final bool expand;
  final double height;
  final double fontSize;

  @override
  Widget build(BuildContext context) {
    final children = <Widget>[];
    for (var i = 0; i < options.length; i++) {
      final bool active = i == selected;
      final Widget button = Material(
        color: Colors.transparent,
        child: InkWell(
          borderRadius: BorderRadius.circular(8),
          onTap: () => onChanged(i),
          child: Container(
            height: height,
            padding: const EdgeInsets.symmetric(horizontal: 9),
            alignment: Alignment.center,
            decoration: BoxDecoration(
              color: active ? UPalette.surface3 : Colors.transparent,
              borderRadius: BorderRadius.circular(8),
            ),
            child: Text(
              options[i],
              style: uiStyle(
                fontSize,
                weight: FontWeight.w600,
                color: active ? UPalette.text : UPalette.text3,
              ),
            ),
          ),
        ),
      );
      children.add(expand ? Expanded(child: button) : button);
    }

    return Container(
      height: height + 4,
      padding: const EdgeInsets.all(2),
      decoration: BoxDecoration(
        color: UPalette.fieldBg,
        border: Border.all(color: UPalette.lineStrong),
        borderRadius: BorderRadius.circular(10),
      ),
      child: Row(
        mainAxisSize: expand ? MainAxisSize.max : MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: children,
      ),
    );
  }
}

/// Вертикальный список взаимоисключающих опций (радиокнопки).
///
/// Нужен там, где подписи длинные и [USegmented] не помещается: автоприём
/// (4 режима) в настройках и на карточке мессенджера.
class UOptionList extends StatelessWidget {
  const UOptionList({
    super.key,
    required this.options,
    required this.selected,
    required this.onChanged,
    this.compact = false,
  });

  final List<String> options;
  final int selected;
  final ValueChanged<int> onChanged;
  final bool compact;

  @override
  Widget build(BuildContext context) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: <Widget>[
        for (int i = 0; i < options.length; i++)
          Material(
            color: Colors.transparent,
            child: InkWell(
              borderRadius: BorderRadius.circular(9),
              onTap: () => onChanged(i),
              child: Padding(
                padding: EdgeInsets.symmetric(
                  vertical: compact ? 5 : 7,
                  horizontal: 4,
                ),
                child: Row(
                  children: <Widget>[
                    Container(
                      width: 16,
                      height: 16,
                      alignment: Alignment.center,
                      decoration: BoxDecoration(
                        shape: BoxShape.circle,
                        border: Border.all(
                          color: i == selected
                              ? UPalette.mint
                              : UPalette.lineStrong,
                        ),
                      ),
                      child: i == selected
                          ? Container(
                              width: 8,
                              height: 8,
                              decoration: const BoxDecoration(
                                shape: BoxShape.circle,
                                color: UPalette.mint,
                              ),
                            )
                          : null,
                    ),
                    const SizedBox(width: 9),
                    Expanded(
                      child: Text(
                        options[i],
                        style: uiStyle(
                          compact ? 11.5 : 12.5,
                          weight: i == selected
                              ? FontWeight.w600
                              : FontWeight.w400,
                          color: i == selected ? UPalette.text : UPalette.text2,
                        ),
                      ),
                    ),
                  ],
                ),
              ),
            ),
          ),
      ],
    );
  }
}

/// Строка с чекбоксом: заголовок + пояснение.
class UCheckline extends StatelessWidget {
  const UCheckline({
    super.key,
    required this.title,
    required this.subtitle,
    required this.value,
    required this.onChanged,
  });

  final String title;
  final String subtitle;
  final bool value;
  final ValueChanged<bool> onChanged;

  @override
  Widget build(BuildContext context) {
    return GestureDetector(
      onTap: () => onChanged(!value),
      behavior: HitTestBehavior.opaque,
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Container(
            width: 20,
            height: 20,
            margin: const EdgeInsets.only(top: 1),
            decoration: BoxDecoration(
              color: value ? UPalette.mint : UPalette.fieldBg,
              border: Border.all(
                color: value ? UPalette.mint : UPalette.lineStrong,
              ),
              borderRadius: BorderRadius.circular(6),
            ),
            child: value
                ? const Icon(Icons.check, size: 13, color: UPalette.mintInk)
                : null,
          ),
          const SizedBox(width: 10),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(title, style: uiStyle(12.5, weight: FontWeight.w600)),
                const SizedBox(height: 1),
                Text(subtitle, style: uiStyle(10.5, color: UPalette.text3)),
              ],
            ),
          ),
        ],
      ),
    );
  }
}

class USwitch extends StatelessWidget {
  const USwitch({super.key, required this.value, required this.onChanged});

  final bool value;
  final ValueChanged<bool> onChanged;

  @override
  Widget build(BuildContext context) {
    // Зона касания 46x44 вокруг самого переключателя 38x22.
    return GestureDetector(
      behavior: HitTestBehavior.opaque,
      onTap: () => onChanged(!value),
      child: Padding(
        padding: const EdgeInsets.symmetric(horizontal: 4, vertical: 11),
        child: Container(
          width: 38,
          height: 22,
          padding: const EdgeInsets.all(2),
          decoration: BoxDecoration(
            color: value ? UPalette.mintBg : UPalette.surface3,
            border: Border.all(
              color: value ? UPalette.mintLine : UPalette.lineStrong,
            ),
            borderRadius: BorderRadius.circular(999),
          ),
          child: AnimatedAlign(
            duration: const Duration(milliseconds: 150),
            alignment: value ? Alignment.centerRight : Alignment.centerLeft,
            child: Container(
              width: 16,
              height: 16,
              decoration: BoxDecoration(
                color: value ? UPalette.mint : UPalette.text3,
                borderRadius: BorderRadius.circular(999),
              ),
            ),
          ),
        ),
      ),
    );
  }
}

class UTextField extends StatelessWidget {
  const UTextField({
    super.key,
    required this.label,
    required this.controller,
    this.hint,
    this.obscure = false,
    this.maxLines = 1,
    this.minLines,
    this.keyboardType,
    this.fieldKey,
    this.autocorrect = true,
    this.enableSuggestions = true,
    this.suffix,
    this.onSubmitted,
  });

  final String label;
  final TextEditingController controller;
  final String? hint;
  final bool obscure;
  final int maxLines;
  final int? minLines;
  final TextInputType? keyboardType;
  final Key? fieldKey;
  final bool autocorrect;
  final bool enableSuggestions;
  final Widget? suffix;

  /// Enter в поле (например, «войти» после пароля).
  final VoidCallback? onSubmitted;

  @override
  Widget build(BuildContext context) {
    final Widget field = TextField(
      key: fieldKey,
      controller: controller,
      obscureText: obscure,
      autocorrect: autocorrect,
      enableSuggestions: enableSuggestions,
      maxLines: obscure ? 1 : maxLines,
      minLines: obscure ? 1 : minLines,
      keyboardType: keyboardType,
      textInputAction: onSubmitted == null ? null : TextInputAction.done,
      onSubmitted: onSubmitted == null ? null : (_) => onSubmitted!(),
      cursorColor: UPalette.mint,
      style: uiStyle(13.5, color: UPalette.text),
      decoration: InputDecoration(
        hintText: hint,
        hintStyle: uiStyle(13, color: UPalette.text3),
        suffixIcon: suffix,
        filled: true,
        fillColor: UPalette.fieldBg,
        isDense: true,
        contentPadding: EdgeInsets.symmetric(
          horizontal: 14,
          vertical: maxLines > 1 ? 12 : 14,
        ),
        border: OutlineInputBorder(
          borderRadius: BorderRadius.circular(13),
          borderSide: const BorderSide(color: UPalette.lineStrong),
        ),
        enabledBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(13),
          borderSide: const BorderSide(color: UPalette.lineStrong),
        ),
        focusedBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(13),
          borderSide: const BorderSide(color: UPalette.mintLine),
        ),
      ),
    );

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          label,
          style: uiStyle(11.5, weight: FontWeight.w600, color: UPalette.text2),
        ),
        const SizedBox(height: 6),
        field,
      ],
    );
  }
}

class UProgress extends StatelessWidget {
  const UProgress({super.key, required this.value});

  final double value;

  @override
  Widget build(BuildContext context) {
    return Container(
      height: 8,
      decoration: BoxDecoration(
        color: UPalette.surface3,
        border: Border.all(color: UPalette.line),
        borderRadius: BorderRadius.circular(999),
      ),
      child: ClipRRect(
        borderRadius: BorderRadius.circular(999),
        child: Align(
          alignment: Alignment.centerLeft,
          child: FractionallySizedBox(
            widthFactor: value.clamp(0.0, 1.0),
            child: Container(
              decoration: const BoxDecoration(
                gradient: LinearGradient(
                  colors: [Color(0xFF2FBF85), UPalette.mint],
                ),
              ),
            ),
          ),
        ),
      ),
    );
  }
}

/// Маленький «пакетный» индикатор иконки (menu / inbox).
class UIconBadge extends StatelessWidget {
  const UIconBadge({
    super.key,
    required this.icon,
    this.color = UPalette.text2,
    this.background = UPalette.surface3,
    this.border = UPalette.line,
    this.size = 32,
  });

  final IconData icon;
  final Color color;
  final Color background;
  final Color border;
  final double size;

  @override
  Widget build(BuildContext context) {
    return Container(
      width: size,
      height: size,
      decoration: BoxDecoration(
        color: background,
        border: Border.all(color: border),
        borderRadius: BorderRadius.circular(9),
      ),
      child: Icon(icon, size: 15, color: color),
    );
  }
}

void showToast(BuildContext context, String text) {
  final messenger = ScaffoldMessenger.maybeOf(context);
  if (messenger == null) return;
  messenger
    ..hideCurrentSnackBar()
    ..showSnackBar(
      SnackBar(
        content: Text(text, style: uiStyle(12, color: UPalette.text)),
        backgroundColor: UPalette.surface3,
        behavior: SnackBarBehavior.floating,
        elevation: 8,
        margin: const EdgeInsets.only(left: 24, right: 24, bottom: 24),
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(12),
          side: const BorderSide(color: UPalette.lineStrong),
        ),
        duration: const Duration(seconds: 2),
      ),
    );
}

Future<void> copyText(BuildContext context, String value, String toast) async {
  await Clipboard.setData(ClipboardData(text: value));
  if (!context.mounted) return;
  showToast(context, toast);
}

/// Карточка листа/диалога.
class USheetCard extends StatelessWidget {
  const USheetCard({
    super.key,
    required this.title,
    required this.onClose,
    required this.child,
    this.width = 440,
    this.padding = const EdgeInsets.all(22),
    this.radius = 24,
    this.maxHeightFactor = 0.9,
  });

  final String title;
  final VoidCallback onClose;
  final Widget child;
  final double width;
  final EdgeInsetsGeometry padding;
  final double radius;
  final double maxHeightFactor;

  @override
  Widget build(BuildContext context) {
    final double maxHeight =
        MediaQuery.sizeOf(context).height * maxHeightFactor;
    return Container(
      width: width,
      constraints: BoxConstraints(maxHeight: maxHeight),
      padding: padding,
      decoration: BoxDecoration(
        gradient: const LinearGradient(
          begin: Alignment.topCenter,
          end: Alignment.bottomCenter,
          colors: [UPalette.surface2, UPalette.surface],
        ),
        border: Border.all(color: UPalette.lineStrong),
        borderRadius: BorderRadius.circular(radius),
        boxShadow: const [
          BoxShadow(
            color: Color(0x73000000),
            blurRadius: 64,
            offset: Offset(0, 24),
          ),
        ],
      ),
      child: Column(
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Row(
            children: [
              Expanded(
                child: Text(
                  title,
                  style: uiStyle(
                    17,
                    weight: FontWeight.w600,
                  ).copyWith(letterSpacing: -0.2),
                ),
              ),
              UIconButton(
                icon: Icons.close,
                onTap: onClose,
                size: 32,
                iconSize: 17,
              ),
            ],
          ),
          const SizedBox(height: 16),
          Flexible(child: SingleChildScrollView(child: child)),
        ],
      ),
    );
  }
}

/// Открывает лист: на телефоне — снизу, на широком экране — по центру.
///
/// Android рисует приложение edge-to-edge (targetSdk 36), а модальные маршруты
/// находятся вне `SafeArea` страницы. Высокий лист прижимается к низу, и его верх
/// иначе уезжает под статус-бар и вырез камеры — вместе с заголовком и крестиком.
/// Поэтому включён `useSafeArea`: сам Flutter добавляет `SafeArea` сверху и по
/// бокам. Без него модальный лист делает `MediaQuery.removePadding(removeTop: true)`,
/// и `SafeArea` внутри листа на верх не действует. Низ листа `SafeArea` не
/// трогает (`bottom: false`): там нужна клавиатура или системная панель.
Future<T?> showUSheet<T>(
  BuildContext context,
  Widget Function(BuildContext context, VoidCallback close) builder,
) {
  final double width = MediaQuery.sizeOf(context).width;
  if (width < 700) {
    return showModalBottomSheet<T>(
      context: context,
      isScrollControlled: true,
      backgroundColor: Colors.transparent,
      barrierColor: const Color(0xA604070B),
      useSafeArea: true,
      builder: (ctx) {
        void close() => Navigator.of(ctx).pop();
        final EdgeInsets viewPadding = MediaQuery.viewPaddingOf(ctx);
        final EdgeInsets viewInsets = MediaQuery.viewInsetsOf(ctx);
        final double bottomInset = viewInsets.bottom > viewPadding.bottom
            ? viewInsets.bottom
            : viewPadding.bottom;
        return Padding(
          padding: EdgeInsets.only(bottom: bottomInset),
          child: Align(
            alignment: Alignment.bottomCenter,
            child: Padding(
              padding: const EdgeInsets.all(12),
              child: ConstrainedBox(
                constraints: const BoxConstraints(maxWidth: 520),
                child: Material(
                  type: MaterialType.transparency,
                  child: builder(ctx, close),
                ),
              ),
            ),
          ),
        );
      },
    );
  }
  return showDialog<T>(
    context: context,
    barrierColor: const Color(0xA604070B),
    builder: (ctx) {
      void close() => Navigator.of(ctx).pop();
      return SafeArea(
        child: Align(
          alignment: Alignment.center,
          child: Material(
            type: MaterialType.transparency,
            child: builder(ctx, close),
          ),
        ),
      );
    },
  );
}

/// Строка настройки: заголовок + пояснение, справа контрол.
class URowTile extends StatelessWidget {
  const URowTile({
    super.key,
    required this.title,
    required this.hint,
    required this.trailing,
    this.topBorder = true,
  });

  final String title;
  final String hint;
  final Widget trailing;
  final bool topBorder;

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(vertical: 7),
      decoration: BoxDecoration(
        border: topBorder
            ? const Border(top: BorderSide(color: UPalette.line))
            : null,
      ),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.center,
        children: [
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(title, style: uiStyle(13, weight: FontWeight.w600)),
                const SizedBox(height: 1),
                Text(
                  hint,
                  style: uiStyle(11.5, color: UPalette.text3, height: 1.3),
                ),
              ],
            ),
          ),
          const SizedBox(width: 14),
          Flexible(
            child: Align(alignment: Alignment.centerRight, child: trailing),
          ),
        ],
      ),
    );
  }
}

/// Контроллер поля в диалоге нельзя освобождать сразу после закрытия: диалог ещё
/// играет анимацию закрытия и перестраивает поле (иначе «used after being disposed»).
void disposeLater(ChangeNotifier c) => Future<void>.delayed(const Duration(milliseconds: 600), c.dispose);

/// Раскрывающийся блок: заголовок со счётчиком и стрелкой, содержимое сворачивается.
class UExpandSection extends StatefulWidget {
  const UExpandSection({
    super.key,
    required this.title,
    required this.child,
    this.count,
    this.initiallyExpanded = true,
  });

  final Widget title;
  final Widget child;
  final int? count;
  final bool initiallyExpanded;

  @override
  State<UExpandSection> createState() => _UExpandSectionState();
}

class _UExpandSectionState extends State<UExpandSection> {
  late bool _open = widget.initiallyExpanded;

  @override
  Widget build(BuildContext context) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        InkWell(
          borderRadius: BorderRadius.circular(10),
          onTap: () => setState(() => _open = !_open),
          child: Padding(
            padding: const EdgeInsets.symmetric(vertical: 8, horizontal: 2),
            child: Row(
              children: [
                widget.title,
                const Spacer(),
                if (widget.count != null)
                  Container(
                    padding: const EdgeInsets.symmetric(horizontal: 7, vertical: 1),
                    decoration: BoxDecoration(color: UPalette.line, borderRadius: BorderRadius.circular(999)),
                    child: Text('${widget.count}', style: monoStyle(12, weight: FontWeight.w500, color: UPalette.text2, spacing: 0)),
                  ),
                const SizedBox(width: 4),
                AnimatedRotation(
                  turns: _open ? 0.5 : 0,
                  duration: const Duration(milliseconds: 160),
                  child: const Icon(Icons.keyboard_arrow_down_rounded, size: 20, color: UPalette.text3),
                ),
              ],
            ),
          ),
        ),
        AnimatedSize(
          duration: const Duration(milliseconds: 180),
          curve: Curves.easeOut,
          alignment: Alignment.topCenter,
          // Содержимое остаётся в дереве (состояние и загрузка не теряются), просто скрыто.
          child: Offstage(offstage: !_open, child: widget.child),
        ),
      ],
    );
  }
}

/// Компактная кнопка языка для шапки: показывает язык, на который переключит.
class ULanguageChip extends StatelessWidget {
  const ULanguageChip({super.key});

  @override
  Widget build(BuildContext context) {
    final AppLocale locale = AppLocale.of(context);
    final bool en = locale.lang == 'en';
    return Tooltip(
      message: locale.s.language,
      child: Material(
        color: Colors.transparent,
        child: InkWell(
          borderRadius: BorderRadius.circular(12),
          onTap: () => locale.onLangChanged(en ? 'ru' : 'en'),
          child: SizedBox(
            height: 40,
            child: Padding(
              padding: const EdgeInsets.symmetric(horizontal: 10),
              child: Row(
                mainAxisSize: MainAxisSize.min,
                children: [
                  const Icon(Icons.language_rounded, size: 17, color: UPalette.text2),
                  const SizedBox(width: 5),
                  Text(en ? 'EN' : 'RU', style: uiStyle(12.5, weight: FontWeight.w700, color: UPalette.text2)),
                ],
              ),
            ),
          ),
        ),
      ),
    );
  }
}

/// Переключатель языка RU/EN (RU — по умолчанию).
class ULanguageToggle extends StatelessWidget {
  const ULanguageToggle({super.key, this.height = 26});

  final double height;

  @override
  Widget build(BuildContext context) {
    final AppLocale locale = AppLocale.of(context);
    return USegmented(
      options: const <String>['RU', 'EN'],
      selected: locale.lang == 'en' ? 1 : 0,
      height: height,
      fontSize: 12,
      onChanged: (int i) => locale.onLangChanged(i == 1 ? 'en' : 'ru'),
    );
  }
}


/// Состояние идущего обновления проверки (job «open»): его ведёт приложение
/// (main.dart), а полоса проверки на кошельке показывает прогресс и «Отмена».
/// Закрытие листа или клик мимо не теряют обновление: состояние живёт здесь.
class RefreshScope extends InheritedWidget {
  const RefreshScope({
    super.key,
    required this.active,
    required this.phase,
    required this.onCancel,
    required super.child,
  });

  final bool active;
  final String phase;
  final VoidCallback onCancel;

  static RefreshScope? maybeOf(BuildContext context) => context.dependOnInheritedWidgetOfExactType<RefreshScope>();

  @override
  bool updateShouldNotify(RefreshScope old) => active != old.active || phase != old.phase;
}
