import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:grinsight/components.dart';

void main() {
  testWidgets('лист не уезжает под статус-бар и системную панель', (WidgetTester tester) async {
    const double topInset = 40;
    const double bottomInset = 24;

    // Телефон с вырезом: 400x800, статус-бар 40, панель навигации 24.
    tester.view.physicalSize = const Size(400, 800);
    tester.view.devicePixelRatio = 1.0;
    tester.view.padding = const FakeViewPadding(top: topInset, bottom: bottomInset);
    tester.view.viewPadding = const FakeViewPadding(top: topInset, bottom: bottomInset);
    addTearDown(tester.view.reset);

    await tester.pumpWidget(
      MaterialApp(
        home: Scaffold(
          body: Builder(
            builder: (BuildContext ctx) => Center(
              child: TextButton(
                onPressed: () => showUSheet<void>(
                  ctx,
                  (BuildContext c, VoidCallback close) => USheetCard(
                    title: 'Настройки',
                    onClose: close,
                    maxHeightFactor: 0.98,
                    child: const SizedBox(height: 2000),
                  ),
                ),
                child: const Text('open'),
              ),
            ),
          ),
        ),
      ),
    );

    await tester.tap(find.text('open'));
    await tester.pumpAndSettle();

    // Заголовок и крестик — ниже статус-бара и выреза камеры.
    final Rect closeRect = tester.getRect(find.byIcon(Icons.close));
    final Rect titleRect = tester.getRect(find.text('Настройки'));
    expect(closeRect.top, greaterThanOrEqualTo(topInset));
    expect(titleRect.top, greaterThanOrEqualTo(topInset));

    // Низ карточки — выше системной панели навигации.
    final Rect cardRect = tester.getRect(find.byType(USheetCard));
    expect(cardRect.bottom, lessThanOrEqualTo(800 - bottomInset));
  });
}
