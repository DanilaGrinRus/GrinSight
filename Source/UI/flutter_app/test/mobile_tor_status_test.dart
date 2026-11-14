import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:grinsight/main.dart';
import 'package:grinsight/wallet_model.dart';
import 'fake_core.dart';

class TorCore extends FakeWalletCore {
  TorStatusInfo? current;
  bool fail = false;
  @override
  Future<TorStatusInfo> torStatus() async {
    if (fail) throw Exception('synthetic tor status failure');
    return current ?? const TorStatusInfo(running: false, phase: TorPhase.stopped);
  }
}

void main() {
  test('daemon phase does not claim remote reachability', () {
    expect(TorStatusInfo.phaseFromService(false, 'ready'), TorPhase.stopped);
    expect(TorStatusInfo.phaseFromService(true, null), TorPhase.unknown);
    expect(TorStatusInfo.phaseFromService(true, 'starting'), TorPhase.starting);
    expect(TorStatusInfo.phaseFromService(true, 'ready'), TorPhase.onionStarted);
    expect(TorStatusInfo.phaseFromService(true, 'failed: synthetic'), TorPhase.failed);
  });

  testWidgets('mobile indicator tracks daemon and opens messenger', (tester) async {
    tester.view.physicalSize = const Size(360, 900);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    final core = TorCore()..current = const TorStatusInfo(running: true, phase: TorPhase.starting);
    await tester.pumpWidget(GrinSightApp(core: core, initialScreen: 'wallet'));
    await tester.pumpAndSettle();
    expect(find.text('Tor: процесс запущен, подключение к сети…'), findsOneWidget);
    core.current = const TorStatusInfo(running: true, phase: TorPhase.onionStarted);
    await tester.pump(const Duration(seconds: 11));
    await tester.pump();
    expect(find.text('Tor: подключён к сети'), findsOneWidget);
    final indicator = find.byKey(const Key('mobile-tor-status'));
    await tester.ensureVisible(indicator);
    await tester.tap(indicator);
    await tester.pumpAndSettle();
    expect(find.text('Переписка'), findsOneWidget);
    // Канал сообщений настраивается под GlauxMail.
    // Лист стал выше (кнопки доставки, статус Tor) — прокручиваем к нужным элементам.
    await tester.ensureVisible(find.byKey(const Key('delivery-grinmail')));
    await tester.tap(find.byKey(const Key('delivery-grinmail')));
    await tester.pumpAndSettle();
    await tester.ensureVisible(find.byKey(const Key('open-messaging-settings')));
    await tester.tap(find.byKey(const Key('open-messaging-settings')));
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('nostr-mode')), findsOneWidget);
    expect(find.byKey(const Key('nostr-ip-notice')), findsOneWidget);
  });

  testWidgets('failed status query shows unknown, not ready', (tester) async {
    tester.view.physicalSize = const Size(360, 900);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    await tester.pumpWidget(GrinSightApp(core: TorCore()..fail = true, initialScreen: 'wallet'));
    await tester.pumpAndSettle();
    expect(find.text('Tor: статус неизвестен'), findsOneWidget);
  });
}
