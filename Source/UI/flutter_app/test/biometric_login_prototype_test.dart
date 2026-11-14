import 'dart:async';
import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:grinsight/main.dart';
import 'package:grinsight/core.dart';
import 'fake_core.dart';

class BoundFakeCore extends FakeWalletCore implements BoundWalletUnlock {
  @override Future<bool> isActiveProfile(String login, String network) async => unlockedProfile == login;
  @override Future<String> credentialDigest({required String login, required String network, required String password}) async => "a" * 64;
  @override
  Future<void> unlockBound({required String login, required String network, required String password, required String vaultDigest}) async {
    if (vaultDigest != 'a' * 64) throw StateError('vault changed');
    await unlock(login: login, network: network, password: password);
  }
}

class NoIdentityCore extends BoundFakeCore {
  @override Future<bool> isActiveProfile(String login, String network) async => throw StateError('identity unavailable');
}
class DigestFailCore extends BoundFakeCore {
  @override Future<String> credentialDigest({required String login, required String network, required String password}) async => throw StateError('verification failed');
}
class DelayedUnlockCore extends BoundFakeCore {
  final gate = Completer<void>();
  @override Future<void> unlock({required String login, required String network, required String password}) async {
    await super.unlock(login: login, network: network, password: password);
    await gate.future;
  }
}
class SwitchedProfileCore extends BoundFakeCore {
  @override Future<String> credentialDigest({required String login, required String network, required String password}) async { unlockedProfile = 'other'; throw StateError('wallet changed'); }
}
class LostReplyCore extends BoundFakeCore {
  @override Future<void> unlockBound({required String login, required String network, required String password, required String vaultDigest}) async {
    await unlock(login: login, network: network, password: password);
    throw StateError('response lost');
  }
}
void main() {
  const channel = MethodChannel('grinsight/biometrics');

  Future<void> setup(WidgetTester tester, Future<Object?> Function(MethodCall) handler) async {
    debugDefaultTargetPlatformOverride = TargetPlatform.android;
    addTearDown(() => debugDefaultTargetPlatformOverride = null);
    tester.view.physicalSize = const Size(1100, 1300);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger.setMockMethodCallHandler(channel, handler);
    addTearDown(() => TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger.setMockMethodCallHandler(channel, null));
  }

  testWidgets('opt-in enrollment follows successful wallet password unlock', (tester) async {
    final calls = <String>[];
    await setup(tester, (c) async {
      calls.add(c.method);
      if (c.method == 'available') return true;
      if (c.method == 'hasCredential') return false;
      if (c.method == 'enroll') {
        expect(c.arguments['profile'], 'alex');
        expect(c.arguments['network'], 'floonet');
        return true;
      }
      return null;
    });
    final core = BoundFakeCore();
    await tester.pumpWidget(GrinSightApp(core: core, initialScreen: 'login'));
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('biometric-enroll')), findsOneWidget);
    await tester.enterText(find.byKey(const Key('login-pass')), 'test-only-password');
    await tester.ensureVisible(find.byKey(const Key('biometric-enroll')));
    await tester.tap(find.byKey(const Key('biometric-enroll')));
    await tester.ensureVisible(find.byKey(const Key('login-submit')));
    await tester.tap(find.byKey(const Key('login-submit')));
    await tester.pumpAndSettle();
    expect(calls, contains('enroll'));
    expect(core.unlockedProfile, 'alex');
    expect(find.text('ДОСТУПНО'), findsOneWidget);
    debugDefaultTargetPlatformOverride = null;
  });

  testWidgets('global removal is available without current credential', (tester) async {
    final calls = <String>[];
    await setup(tester, (c) async { calls.add(c.method); if (c.method == 'forgetAll' || c.method == 'supported') return true; return false; });
    await tester.pumpWidget(GrinSightApp(core: BoundFakeCore(), initialScreen: 'login'));
    await tester.pumpAndSettle();
    await tester.ensureVisible(find.byKey(const Key('biometric-advanced')));
    await tester.tap(find.byKey(const Key('biometric-advanced')));
    await tester.pumpAndSettle();
    await tester.ensureVisible(find.byKey(const Key('biometric-forget-all')));
    await tester.tap(find.byKey(const Key('biometric-forget-all')));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Удалить').last);
    await tester.pumpAndSettle();
    expect(calls, contains('forgetAll'));
    debugDefaultTargetPlatformOverride = null;
  });
  testWidgets('ordinary login does not require credential identity', (tester) async {
    await setup(tester, (c) async => false);
    final core = NoIdentityCore();
    await tester.pumpWidget(GrinSightApp(core: core, initialScreen: 'login'));
    await tester.pumpAndSettle();
    await tester.enterText(find.byKey(const Key('login-pass')), 'test-only-password');
    await tester.ensureVisible(find.byKey(const Key('login-submit')));
    await tester.tap(find.byKey(const Key('login-submit')));
    await tester.pumpAndSettle();
    expect(core.locked, isFalse);
    expect(find.text('ДОСТУПНО'), findsOneWidget);
    debugDefaultTargetPlatformOverride = null;
  });
  testWidgets('optional enrollment failure leaves the opened wallet visible', (tester) async {
    await setup(tester, (c) async { if (c.method == 'available') return true; return false; });
    final core = DigestFailCore();
    await tester.pumpWidget(GrinSightApp(core: core, initialScreen: 'login'));
    await tester.pumpAndSettle();
    await tester.enterText(find.byKey(const Key('login-pass')), 'test-only-password');
    await tester.ensureVisible(find.byKey(const Key('biometric-enroll')));
    await tester.tap(find.byKey(const Key('biometric-enroll')));
    await tester.ensureVisible(find.byKey(const Key('login-submit')));
    await tester.tap(find.byKey(const Key('login-submit')));
    await tester.pumpAndSettle();
    expect(core.locked, isFalse);
    expect(find.text('ДОСТУПНО'), findsOneWidget);
    debugDefaultTargetPlatformOverride = null;
  });
  testWidgets('profile switch during setup locks instead of opening wrong profile', (tester) async {
    await setup(tester, (c) async { if (c.method == 'available') return true; return false; });
    final core = SwitchedProfileCore();
    await tester.pumpWidget(GrinSightApp(core: core, initialScreen: 'login'));
    await tester.pumpAndSettle();
    await tester.enterText(find.byKey(const Key('login-pass')), 'test-only-password');
    await tester.ensureVisible(find.byKey(const Key('biometric-enroll')));
    await tester.tap(find.byKey(const Key('biometric-enroll')));
    await tester.ensureVisible(find.byKey(const Key('login-submit')));
    await tester.tap(find.byKey(const Key('login-submit')));
    await tester.pumpAndSettle();
    expect(core.locked, isTrue);
    expect(find.byKey(const Key('login-pass')), findsOneWidget);
    debugDefaultTargetPlatformOverride = null;
  });
  testWidgets('disposing login during enrollment locks backend', (tester) async {
    final pending = Completer<Object?>();
    await setup(tester, (c) async {
      if (c.method == 'available') return true;
      if (c.method == 'enroll') return pending.future;
      return false;
    });
    final core = BoundFakeCore();
    await tester.pumpWidget(GrinSightApp(core: core, initialScreen: 'login'));
    await tester.pumpAndSettle();
    await tester.enterText(find.byKey(const Key('login-pass')), 'test-only-password');
    await tester.ensureVisible(find.byKey(const Key('biometric-enroll')));
    await tester.tap(find.byKey(const Key('biometric-enroll')));
    await tester.ensureVisible(find.byKey(const Key('login-submit')));
    await tester.tap(find.byKey(const Key('login-submit')));
    await tester.pump();
    expect(core.locked, isFalse);
    await tester.pumpWidget(const SizedBox());
    pending.complete(false);
    await tester.pumpAndSettle();
    expect(core.locked, isTrue);
    debugDefaultTargetPlatformOverride = null;
  });
  testWidgets('disposing login during pending unlock locks backend', (tester) async {
    await setup(tester, (c) async => false);
    final core = DelayedUnlockCore();
    await tester.pumpWidget(GrinSightApp(core: core, initialScreen: 'login'));
    await tester.pumpAndSettle();
    await tester.enterText(find.byKey(const Key('login-pass')), 'test-only-password');
    await tester.ensureVisible(find.byKey(const Key('login-submit')));
    await tester.tap(find.byKey(const Key('login-submit')));
    await tester.pump();
    expect(core.locked, isFalse);
    await tester.pumpWidget(const SizedBox());
    core.gate.complete();
    await tester.pumpAndSettle();
    expect(core.locked, isTrue);
    debugDefaultTargetPlatformOverride = null;
  });
  testWidgets('lost unlock reply locks backend before returning to login', (tester) async {
    await setup(tester, (c) async {
      if (c.method == 'available' || c.method == 'hasCredential') return true;
      if (c.method == 'unlockSecret') return {'password': 'test-only-password', 'vault_digest': 'a' * 64};
      return false;
    });
    final core = LostReplyCore(); core.locked = true;
    await tester.pumpWidget(GrinSightApp(core: core, initialScreen: 'login'));
    await tester.pumpAndSettle();
    await tester.ensureVisible(find.byKey(const Key('biometric-unlock')));
    await tester.tap(find.byKey(const Key('biometric-unlock')));
    await tester.pumpAndSettle();
    expect(core.locked, isTrue);
    expect(find.byKey(const Key('login-pass')), findsOneWidget);
    debugDefaultTargetPlatformOverride = null;
  });
  testWidgets('cancelled prompt keeps wallet locked and password fallback', (tester) async {
    await setup(tester, (c) async {
      if (c.method == 'available' || c.method == 'hasCredential') return true;
      if (c.method == 'unlockSecret') throw PlatformException(code: 'biometric_cancelled');
      return null;
    });
    final core = FakeWalletCore(); core.locked = true;
    await tester.pumpWidget(GrinSightApp(core: core, initialScreen: 'login'));
    await tester.pumpAndSettle();
    await tester.ensureVisible(find.byKey(const Key('biometric-unlock')));
    await tester.tap(find.byKey(const Key('biometric-unlock')));
    await tester.pumpAndSettle();
    expect(core.locked, isTrue);
    expect(find.byKey(const Key('login-pass')), findsOneWidget);
    debugDefaultTargetPlatformOverride = null;
  });

  testWidgets('stored credential uses correct profile on biometric login', (tester) async {
    await setup(tester, (c) async {
      if (c.method == 'available' || c.method == 'hasCredential') return true;
      if (c.method == 'unlockSecret') {
        expect(c.arguments['profile'], 'alex');
        expect(c.arguments['network'], 'floonet');
        return {'password': 'test-only-password', 'vault_digest': 'a' * 64};
      }
      return null;
    });
    final core = BoundFakeCore(); core.locked = true;
    await tester.pumpWidget(GrinSightApp(core: core, initialScreen: 'login'));
    await tester.pumpAndSettle();
    await tester.ensureVisible(find.byKey(const Key('biometric-unlock')));
    await tester.tap(find.byKey(const Key('biometric-unlock')));
    await tester.pumpAndSettle();
    expect(core.locked, isFalse);
    expect(core.unlockedProfile, 'alex');
    debugDefaultTargetPlatformOverride = null;
  });
}
