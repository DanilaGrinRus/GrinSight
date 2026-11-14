import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:grinsight/main.dart';
import 'fake_core.dart';

void main() {
  testWidgets('GlauxMail selection displays unavailable status', (tester) async {
    tester.view.physicalSize = const Size(1180, 1200);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    await tester.pumpWidget(GrinSightApp(core: FakeWalletCore(), initialScreen: 'wallet'));
    await tester.pumpAndSettle();
    // Способы доставки — явные кнопки, видны сразу.
    expect(find.text('GlauxMail'), findsOneWidget);
    expect(find.text('Relay'), findsNothing);
    await tester.tap(find.text('GlauxMail'));
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('glauxmail-payment-hint')), findsOneWidget);
    expect(find.textContaining('Платежи используют выбранный канал'), findsOneWidget);
    expect(find.text('Доставка платежей'), findsOneWidget);
    await tester.tap(find.byKey(const Key('open-messaging-settings')));
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('nostr-mode')), findsOneWidget);
    expect(find.textContaining('Предлагаемый канал ещё не включён'), findsOneWidget);
    expect(find.byKey(const Key('nostr-ip-notice')), findsOneWidget);
    expect(tester.widget<TextField>(find.byKey(const Key('nostr-url'))).controller!.text, 'wss://relay.primal.net');
    await tester.tap(find.byKey(const Key('nostr-save')));
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('nostr-mode')), findsNothing);
  });
}
