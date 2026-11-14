import 'dart:ui' show PointMode;

import 'package:flutter/material.dart';

import 'gold_layer.dart';

/// Палитра, согласованная в HTML-прототипе.
class UPalette {
  UPalette._();

  static const bg = Color(0xFF0A0E14);
  static const surface = Color(0xFF121A25);
  static const surface2 = Color(0xFF17212E);
  static const surface3 = Color(0xFF1D2938);
  static const fieldBg = Color(0xFF0C131C);

  static const text = Color(0xFFE9EEF6);
  static const text2 = Color(0xFFA7B6C7);
  static const text3 = Color(0xFF8496A9);

  static const mint = Color(0xFF3DDC9A);
  static const mintInk = Color(0xFF04130D);
  static const mintBg = Color(0x1A3DDC9A);
  static const mintLine = Color(0x573DDC9A);

  static const blue = Color(0xFF66AAFF);
  static const blueBg = Color(0x1A66AAFF);
  static const blueLine = Color(0x5266AAFF);

  static const amber = Color(0xFFF2B64C);
  static const amberBg = Color(0x1AF2B64C);
  static const amberLine = Color(0x52F2B64C);

  static const violet = Color(0xFFA78BFA);
  static const violetBg = Color(0x1FA78BFA);

  static const red = Color(0xFFFF6B6B);

  /// Фирменное золото знака и «Sight» (docs/brand).
  static const gold = Color(0xFFF5C518);

  static const line = Color(0x2194A3B8);
  static const lineStrong = Color(0x3D94A3B8);
}

/// Релизная сборка: `--dart-define=GS_RELEASE=true`. В ней нет надписей
/// «исследовательский прототип» и других заметок разработки.
const bool kReleaseBuild = bool.fromEnvironment('GS_RELEASE');

const kUiFont = 'Segoe UI';
const List<String> kUiFallback = <String>['Arial', 'Roboto', 'Helvetica Neue'];
const kMonoFont = 'Consolas';
const List<String> kMonoFallback = <String>['Cascadia Mono', 'Roboto Mono', 'Menlo', 'monospace'];

/// Минимальный размер текста во всём интерфейсе (мельче читать трудно).
const double kMinFont = 12;

TextStyle monoStyle(double size, {FontWeight weight = FontWeight.w600, Color color = UPalette.text, double? height, double spacing = -0.2}) {
  return TextStyle(
    fontFamily: kMonoFont,
    fontFamilyFallback: kMonoFallback,
    fontSize: size < kMinFont ? kMinFont : size,
    fontWeight: weight,
    color: color,
    height: height,
    letterSpacing: spacing,
  );
}

TextStyle uiStyle(double size, {FontWeight weight = FontWeight.w400, Color color = UPalette.text, double? height}) {
  return TextStyle(
    fontFamily: kUiFont,
    fontFamilyFallback: kUiFallback,
    fontSize: size < kMinFont ? kMinFont : size,
    fontWeight: weight,
    color: color,
    height: height,
  );
}

ThemeData buildGrinSightTheme() {
  const scheme = ColorScheme.dark(
    primary: UPalette.mint,
    onPrimary: UPalette.mintInk,
    secondary: UPalette.blue,
    surface: UPalette.surface,
    onSurface: UPalette.text,
    error: UPalette.red,
  );
  return ThemeData(
    useMaterial3: true,
    brightness: Brightness.dark,
    scaffoldBackgroundColor: UPalette.bg,
    canvasColor: UPalette.bg,
    colorScheme: scheme,
    fontFamily: kUiFont,
    fontFamilyFallback: kUiFallback,
    splashFactory: InkRipple.splashFactory,
  );
}

/// Логотип GrinSight (значок с медведем) — круглый, с мягкой тенью.
class ULogo extends StatelessWidget {
  const ULogo({super.key, this.size = 32});

  final double size;

  @override
  Widget build(BuildContext context) {
    // В монохромной теме логотип остаётся чёрно-золотым (цветная копия над фильтром).
    final Widget logo = _body();
    return GoldTarget(active: true, gold: logo, child: logo);
  }

  Widget _body() {
    return Container(
      width: size,
      height: size,
      decoration: BoxDecoration(
        shape: BoxShape.circle,
        boxShadow: [
          BoxShadow(
            color: UPalette.mint.withValues(alpha: 0.10),
            blurRadius: size * 0.4,
            offset: Offset(0, size * 0.08),
          ),
          BoxShadow(
            color: Colors.black.withValues(alpha: 0.35),
            blurRadius: size * 0.25,
            offset: Offset(0, size * 0.10),
          ),
        ],
      ),
      child: ClipOval(
        child: Image.asset(
          'assets/icon/app_mark.png',
          width: size,
          height: size,
          fit: BoxFit.cover,
        ),
      ),
    );
  }
}

/// Растровая сетка точек поверх монохромной темы (как дизеринг на grin.mw).
/// Очень бледная: создаёт фактуру «печати», не мешая читать текст.
class HalftonePainter extends CustomPainter {
  const HalftonePainter();

  @override
  void paint(Canvas canvas, Size size) {
    const double step = 4;
    final List<Offset> dots = <Offset>[];
    for (double y = 1; y < size.height; y += step) {
      final double shift = ((y ~/ step) % 2 == 0) ? 0 : step / 2;
      for (double x = 1 + shift; x < size.width; x += step) {
        dots.add(Offset(x, y));
      }
    }
    final Paint paint = Paint()
      // Было 5% белого — на экране не видно. 14% даёт заметную «печать»,
      // текст при этом читается.
      ..color = const Color(0x24FFFFFF)
      ..strokeWidth = 1.5
      ..strokeCap = StrokeCap.round;
    canvas.drawPoints(PointMode.points, dots, paint);
  }

  @override
  bool shouldRepaint(covariant HalftonePainter oldDelegate) => false;
}
