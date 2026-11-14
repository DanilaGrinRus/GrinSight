import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:grinsight/main.dart';
import 'fake_core.dart';

void main() {
  testWidgets('rejects mainnet address in Floonet before review', (tester) async {
    tester.view.physicalSize = const Size(1180, 1000);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    await tester.pumpWidget(GrinSightApp(core: FakeWalletCore(), initialScreen: 'wallet'));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Отправить'));
    await tester.pumpAndSettle();
    await tester.enterText(find.byKey(const Key('send-to')), 'grin1${'a' * 52}');
    await tester.enterText(find.byKey(const Key('send-amount')), '1');
    await tester.tap(find.byKey(const Key('send-continue')));
    await tester.pump();
    expect(find.byKey(const Key('send-submit')), findsNothing);
    expect(find.text('Адрес другой сети'), findsOneWidget);
  });

  testWidgets('rejects malformed recipient before review', (tester) async {
    tester.view.physicalSize = const Size(1180, 1000);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    await tester.pumpWidget(GrinSightApp(core: FakeWalletCore(), initialScreen: 'wallet'));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Отправить'));
    await tester.pumpAndSettle();
    await tester.enterText(find.byKey(const Key('send-to')), 'not-an-address');
    await tester.enterText(find.byKey(const Key('send-amount')), '1');
    await tester.tap(find.byKey(const Key('send-continue')));
    await tester.pump();
    expect(find.byKey(const Key('send-submit')), findsNothing);
    expect(find.text('Введите корректный адрес кошелька Grin'), findsOneWidget);
  });

  testWidgets('accepts a valid Floonet address for review', (tester) async {
    tester.view.physicalSize = const Size(1180, 1000);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    await tester.pumpWidget(GrinSightApp(core: FakeWalletCore(), initialScreen: 'wallet'));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Отправить'));
    await tester.pumpAndSettle();
    await tester.enterText(find.byKey(const Key('send-to')), 'tgrin1${'a' * 52}');
    await tester.enterText(find.byKey(const Key('send-amount')), '1');
    await tester.tap(find.byKey(const Key('send-continue')));
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('send-submit')), findsOneWidget);
  });
}
