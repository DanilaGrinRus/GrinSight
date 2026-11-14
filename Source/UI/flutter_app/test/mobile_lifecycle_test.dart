import 'package:flutter/widgets.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:grinsight/main.dart';
import 'package:grinsight/screens/wallet.dart';
import 'fake_core.dart';

// Regression for Flutter lifecycle events in a single process only.
// Android process death, device authentication and emulator behaviour are not covered.
void main() {
  testWidgets('inactive paused resumed keeps unlocked session in same process', (tester) async {
    tester.view.physicalSize = const Size(1180, 1400);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    final core = FakeWalletCore();
    await core.unlock(login: 'alex', network: 'floonet', password: 'test');
    await tester.pumpWidget(GrinSightApp(core: core, initialScreen: 'wallet'));
    await tester.pumpAndSettle();
    expect(core.locked, isFalse);
    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.inactive);
    await tester.pump();
    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.hidden);
    await tester.pump();
    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.paused);
    await tester.pump(const Duration(seconds: 2));
    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.hidden);
    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.inactive);
    tester.binding.handleAppLifecycleStateChanged(AppLifecycleState.resumed);
    await tester.pumpAndSettle();
    expect(core.locked, isFalse);
    expect(core.unlockedProfile, 'alex');
    expect(find.byType(WalletScreen), findsOneWidget);
  });
}
