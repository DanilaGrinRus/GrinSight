import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:grinsight/core.dart';
import 'package:grinsight/main.dart';
import 'fake_core.dart';

class WarningCore extends FakeWalletCore implements WalletInitializationWarnings {
  String? warning = 'messenger_settings_unavailable';
  @override
  String? takeWalletInitializationWarning() { final value = warning; warning = null; return value; }
}

void main() {
  testWidgets('saved wallet remains usable when messenger initialization fails', (tester) async {
    tester.view.physicalSize = const Size(1100, 1200); tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize); addTearDown(tester.view.resetDevicePixelRatio);
    final core = WarningCore();
    await tester.pumpWidget(GrinSightApp(core: core, initialScreen: 'login'));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Восстановить')); await tester.pumpAndSettle();
    await tester.enterText(find.byKey(const Key('login-name')), 'alice');
    await tester.enterText(find.byKey(const Key('login-pass')), 'secret12');
    await tester.enterText(find.byKey(const Key('login-seed')), 'one two three four five six seven eight nine ten eleven twelve');
    await tester.ensureVisible(find.byKey(const Key('login-submit')));
    await tester.tap(find.byKey(const Key('login-submit'))); await tester.pumpAndSettle();
    expect(core.unlockedProfile, 'alice');
    expect(find.text('Кошелёк создан'), findsOneWidget);
    expect(find.textContaining('Кошелёк сохранён, но канал переписки не запустился'), findsOneWidget);
    await tester.tap(find.text('Продолжить')); await tester.pumpAndSettle();
    expect(find.text('ДОСТУПНО'), findsOneWidget);
    expect(tester.takeException(), isNull);
  });
}
