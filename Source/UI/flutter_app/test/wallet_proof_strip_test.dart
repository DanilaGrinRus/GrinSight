import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:grinsight/main.dart';

import 'fake_core.dart';

void main() {
  testWidgets('полоса «нужно обновить» не сжимается в колонку из букв', (WidgetTester tester) async {
    // Узкий телефон: раньше UButton с expand=true забирал всю ширину Row,
    // Expanded-текст получал 0 и каждая буква переносилась на новую строку.
    tester.view.physicalSize = const Size(390, 844);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(tester.view.reset);

    await tester.pumpWidget(
      GrinSightApp(core: FakeWalletCore(proofMissing: true), initialScreen: 'wallet'),
    );
    await tester.pumpAndSettle();

    final Finder text = find.text('Нужно обновить доказательство');
    expect(text, findsOneWidget);
    final Size size = tester.getSize(text);
    expect(size.width, greaterThan(120), reason: 'текст должен занимать строку, а не колонку из букв');
    expect(size.height, lessThan(60), reason: 'не больше двух строк');
  });

  testWidgets('идущее обновление показывает прогресс-полосу и «Отменить», без кнопки «Обновить»', (WidgetTester tester) async {
    tester.view.physicalSize = const Size(390, 844);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(tester.view.reset);

    final FakeWalletCore core = FakeWalletCore(proofMissing: true, slowOpen: true);
    await tester.pumpWidget(GrinSightApp(core: core, initialScreen: 'wallet'));
    await tester.pumpAndSettle();

    await tester.tap(find.text('Обновить'));
    await tester.pump();
    await tester.pump(const Duration(milliseconds: 50));

    expect(find.byKey(const Key('refresh-progress')), findsOneWidget);
    expect(find.text('Отменить'), findsOneWidget);
    expect(find.text('Обновить'), findsNothing);
    expect(core.openCalls, 1);

    // второй клик «мимо» и снова: второго job нет
    core.finishOpen();
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('refresh-progress')), findsNothing);
    expect(core.openCalls, 1);
  });

  testWidgets('ошибка файла баланса: бейдж и полоса проверки говорят одно и то же', (WidgetTester tester) async {
    tester.view.physicalSize = const Size(1180, 900);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(tester.view.reset);

    await tester.pumpWidget(GrinSightApp(core: FakeWalletCore(balanceBroken: true), initialScreen: 'wallet'));
    await tester.pumpAndSettle();

    expect(find.text('НЕ ПРОВЕРЕНО'), findsOneWidget);
    expect(find.text('ДОКАЗАН'), findsNothing);
    expect(find.textContaining('Баланс не доказан'), findsOneWidget);
    expect(find.textContaining('Доказан на проверенной вершине'), findsNothing);
  });
}
