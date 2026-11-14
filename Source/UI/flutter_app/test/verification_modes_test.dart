import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:grinsight/components.dart';
import 'package:grinsight/main.dart';
import 'fake_core.dart';

class ModeCore extends FakeWalletCore {
  bool fail = false;
  @override
  Future<void> setVerifyMode(String mode) async {
    if (fail) throw Exception('synthetic settings failure');
    await super.setVerifyMode(mode);
  }
}

void main() {
  testWidgets('launch restores the saved pre-login mode', (tester) async {
    tester.view.physicalSize = const Size(320, 640);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    final core = ModeCore()..verifyMode = 'header_proof';
    await tester.pumpWidget(GrinSightApp(core: core, menuInitiallyOpen: true));
    await tester.pumpAndSettle();
    expect(tester.widget<USwitch>(find.byKey(const Key('launch-future-switch'))).value, isTrue);
  });
  testWidgets('wallet icon opens options and saves future mode', (tester) async {
    tester.view.physicalSize = const Size(320, 640);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    final core = ModeCore();
    await tester.pumpWidget(GrinSightApp(core: core, initialScreen: 'wallet'));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('wallet-verification-options')));
    await tester.pumpAndSettle();
    final toggle = find.byKey(const Key('wallet-future-switch'));
    await tester.ensureVisible(toggle);
    await tester.tap(toggle);
    await tester.pumpAndSettle();
    expect(core.verifyMode, 'header_proof');
    expect(tester.widget<USwitch>(toggle).value, isTrue);
    expect(find.textContaining('Проверка идёт по header-proof'), findsWidgets);
  });

  testWidgets('failed future mode save leaves switch off', (tester) async {
    tester.view.physicalSize = const Size(320, 640);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    final core = ModeCore()..fail = true;
    await tester.pumpWidget(GrinSightApp(core: core, initialScreen: 'wallet'));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('wallet-verification-options')));
    await tester.pumpAndSettle();
    final toggle = find.byKey(const Key('wallet-future-switch'));
    await tester.ensureVisible(toggle);
    await tester.tap(toggle);
    await tester.pumpAndSettle();
    expect(core.verifyMode, 'checkpoint');
    expect(tester.widget<USwitch>(toggle).value, isFalse);
  });
}

