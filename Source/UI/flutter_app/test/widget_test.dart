import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:grinsight/main.dart';
import 'package:grinsight/wallet_model.dart';
import 'package:qr_flutter/qr_flutter.dart';

import 'fake_core.dart';

void main() {
  testWidgets('checkpoint can be checked from genesis before login', (WidgetTester tester) async {
    tester.view.physicalSize = const Size(1180, 900);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);

    await tester.pumpWidget(GrinSightApp(core: FakeWalletCore()));
    await tester.pumpAndSettle();
    if (find.byKey(const Key('launch-own-checkpoint')).evaluate().isEmpty) {
      await tester.tap(find.text('Опции'));
      await tester.pumpAndSettle();
    }
    await tester.tap(find.byKey(const Key('launch-own-checkpoint')));
    await tester.pumpAndSettle();

    expect(find.text('Проверка чекпоинта с нуля'), findsOneWidget);
    expect(find.textContaining('Чекпоинт в поставке'), findsOneWidget);
    expect(find.text('Начать проверку'), findsOneWidget);
  });

  testWidgets('launch → login → wallet', (WidgetTester tester) async {
    await tester.pumpWidget(GrinSightApp(core: FakeWalletCore(), ));

    expect(find.text('Войти'), findsOneWidget);
    expect(find.text('Опции'), findsOneWidget);

    await tester.tap(find.byKey(const Key('launch-login')));
    await tester.pumpAndSettle();

    expect(find.text('Вход'), findsOneWidget);
    expect(find.text('Профиль и сеть'), findsOneWidget);

    expect(find.text('alex'), findsWidgets);
    await tester.enterText(find.byKey(const Key('login-pass')), 'secret12');
    await tester.tap(find.byKey(const Key('login-submit')));
    await tester.pumpAndSettle();

    expect(find.text('ДОСТУПНО'), findsOneWidget);
    expect(find.text('11.00 tGRIN'), findsOneWidget);
    expect(find.text('Операции'), findsOneWidget);
    expect(find.text('Отправить'), findsOneWidget);
  });

  testWidgets('login validates empty fields', (WidgetTester tester) async {
    await tester.pumpWidget(GrinSightApp(core: FakeWalletCore(), initialScreen: 'login'));
    await tester.pumpAndSettle();

    await tester.tap(find.byKey(const Key('login-submit')));
    await tester.pump();
    expect(find.text('Введите пароль'), findsOneWidget);
  });

  testWidgets('restore mode shows protected seed field', (WidgetTester tester) async {
    await tester.pumpWidget(GrinSightApp(core: FakeWalletCore(), initialScreen: 'login'));
    await tester.pumpAndSettle();

    await tester.tap(find.text('Восстановить'));
    await tester.pumpAndSettle();

    final Finder seedFinder = find.byKey(const Key('login-seed'));
    expect(seedFinder, findsOneWidget);
    final TextField seed = tester.widget<TextField>(seedFinder);
    expect(seed.obscureText, isTrue);
    expect(seed.autocorrect, isFalse);
    expect(seed.enableSuggestions, isFalse);
  });

  testWidgets('wide wallet shows balance, proof line and history', (WidgetTester tester) async {
    tester.view.physicalSize = const Size(1180, 800);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);

    await tester.pumpWidget(GrinSightApp(core: FakeWalletCore(), initialScreen: 'wallet'));
    await tester.pumpAndSettle();

    expect(find.text('Мессенджер'), findsOneWidget);
    expect(find.text('не подключён'), findsOneWidget);
    expect(find.text('Включить'), findsOneWidget);
    expect(find.text('11.00 tGRIN'), findsOneWidget);
    expect(find.textContaining('Доказан на проверенной вершине 4 100 208'), findsOneWidget);
    expect(find.text('Операции'), findsOneWidget);
    expect(find.text('Отправить'), findsOneWidget);
  });

  testWidgets('narrow wallet shows balance and actions', (WidgetTester tester) async {
    tester.view.physicalSize = const Size(390, 844);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);

    await tester.pumpWidget(GrinSightApp(core: FakeWalletCore(), initialScreen: 'wallet'));
    await tester.pumpAndSettle();

    expect(find.text('11.00 tGRIN'), findsOneWidget);
    expect(find.text('Отправить'), findsOneWidget);
    expect(find.text('Операции'), findsOneWidget);
  });

  testWidgets('verification sheet shows kernel lines', (WidgetTester tester) async {
    tester.view.physicalSize = const Size(1180, 800);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);

    await tester.pumpWidget(GrinSightApp(core: FakeWalletCore(), initialScreen: 'wallet', initialSheet: 'verification'));
    await tester.pumpAndSettle();

    expect(find.text('Доказательство баланса'), findsOneWidget);
    expect(find.text('AVAILABLE'), findsNothing);
    await tester.tap(find.text('Показать технические детали'));
    await tester.pumpAndSettle();
    expect(find.text('AVAILABLE'), findsOneWidget);
    expect(find.text('CURRENT_TIP_STATE'), findsOneWidget);
    expect(find.text('PEER_INDEPENDENCE'), findsOneWidget);
  });

  testWidgets('send sheet builds and reviews', (WidgetTester tester) async {
    tester.view.physicalSize = const Size(1180, 800);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);

    await tester.pumpWidget(GrinSightApp(core: FakeWalletCore(), initialScreen: 'wallet'));
    await tester.pumpAndSettle();

    await tester.tap(find.text('Отправить'));
    await tester.pumpAndSettle();
    expect(find.text('Продолжить'), findsOneWidget);

    await tester.enterText(find.byKey(const Key('send-to')), 'grin1demo');
    await tester.enterText(find.byKey(const Key('send-amount')), '1.0');
    await tester.tap(find.byKey(const Key('send-continue')));
    await tester.pumpAndSettle();

    expect(find.text('Проверьте перевод'), findsOneWidget);
    expect(find.byKey(const Key('send-submit')), findsOneWidget);
    await tester.tap(find.byKey(const Key('send-submit')));
    await tester.pumpAndSettle();
    expect(find.text('S1 SLATEPACK TEST'), findsOneWidget);
  });
  testWidgets('english locale renders EN strings', (WidgetTester tester) async {
    tester.view.physicalSize = const Size(1180, 800);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);

    await tester.pumpWidget(GrinSightApp(core: FakeWalletCore(), initialScreen: 'wallet', initialLanguage: 'en'));
    await tester.pumpAndSettle();

    expect(find.text('AVAILABLE'), findsOneWidget);
    expect(find.text('Activity'), findsOneWidget);
    expect(find.text('Send'), findsOneWidget);
    // статус проверки показан одной строкой на кошельке (пилюли в шапке больше нет)
    expect(find.textContaining('4 100 208'), findsOneWidget);
  });

  testWidgets('language toggle switches to English', (WidgetTester tester) async {
    await tester.pumpWidget(GrinSightApp(core: FakeWalletCore(), initialScreen: 'login'));
    await tester.pumpAndSettle();

    expect(find.text('Вход'), findsOneWidget);
    await tester.tap(find.text('EN'));
    await tester.pumpAndSettle();

    expect(find.text('Sign in'), findsOneWidget);
    expect(find.text('Profile & network'), findsOneWidget);
  });

  testWidgets('create flow hides phrase before verification', (WidgetTester tester) async {
    await tester.pumpWidget(GrinSightApp(core: FakeWalletCore(), initialScreen: 'login'));
    await tester.pumpAndSettle();

    await tester.tap(find.text('Создать'));
    await tester.pumpAndSettle();
    await tester.enterText(find.byKey(const Key('login-name')), 'alex');
    await tester.enterText(find.byKey(const Key('login-pass')), 'secret12');
    // форма стала выше (выбор длины фразы): кнопка может быть за краем экрана
    await tester.ensureVisible(find.byKey(const Key('login-submit')));
    await tester.tap(find.byKey(const Key('login-submit')));
    await tester.pumpAndSettle();

    expect(find.text('Я записал(а) фразу'), findsOneWidget);
    expect(find.textContaining('Слово №'), findsNothing);
    await tester.ensureVisible(find.text('Я записал(а) фразу'));
    await tester.tap(find.text('Я записал(а) фразу'));
    await tester.pumpAndSettle();
    await tester.ensureVisible(find.byKey(const Key('login-submit')));
    await tester.tap(find.byKey(const Key('login-submit')));
    await tester.pumpAndSettle();

    // два слова для проверки на случайных позициях
    expect(find.textContaining('Слово №'), findsNWidgets(2));
  });

  testWidgets('send rejects amount above available with a clear message', (WidgetTester tester) async {
    tester.view.physicalSize = const Size(1180, 800);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);

    await tester.pumpWidget(GrinSightApp(core: FakeWalletCore(), initialScreen: 'wallet'));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Отправить'));
    await tester.pumpAndSettle();

    await tester.enterText(find.byKey(const Key('send-to')), 'grin1demo');
    await tester.enterText(find.byKey(const Key('send-amount')), '999');
    await tester.tap(find.byKey(const Key('send-continue')));
    await tester.pumpAndSettle();

    expect(find.text('Недостаточно средств с учётом комиссии'), findsOneWidget);
    expect(find.text('Проверьте перевод'), findsNothing);
  });

  testWidgets('dev auto-login does nothing if the profile is missing', (WidgetTester tester) async {
    await tester.pumpWidget(GrinSightApp(core: FakeWalletCore(), autoProfile: 'missing', autoPassword: 'password'));
    await tester.pumpAndSettle();

    expect(find.text('Войти'), findsOneWidget);
    expect(find.text('ДОСТУПНО'), findsNothing);
  });

  testWidgets('checkpoint section shows shipped source and create action', (WidgetTester tester) async {
    tester.view.physicalSize = const Size(1180, 800);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);

    await tester.pumpWidget(GrinSightApp(core: FakeWalletCore(), initialScreen: 'wallet', initialSheet: 'verification'));
    await tester.pumpAndSettle();

    expect(find.text('Контрольная точка'), findsOneWidget);
    expect(find.text('из поставки'), findsWidgets);
    expect(find.text('Создать свою'), findsWidgets);
  });

  testWidgets('receive sheet shows an address QR', (WidgetTester tester) async {
    tester.view.physicalSize = const Size(1180, 800);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);

    await tester.pumpWidget(GrinSightApp(core: FakeWalletCore(), initialScreen: 'wallet'));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Получить'));
    await tester.pumpAndSettle();

    expect(find.byType(QrImageView), findsOneWidget);
  });

  testWidgets('short slatepack has a QR switch', (WidgetTester tester) async {
    tester.view.physicalSize = const Size(1180, 800);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);

    await tester.pumpWidget(GrinSightApp(core: FakeWalletCore(), initialScreen: 'wallet'));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Отправить'));
    await tester.pumpAndSettle();
    await tester.enterText(find.byKey(const Key('send-to')), 'grin1demo');
    await tester.enterText(find.byKey(const Key('send-amount')), '1.0');
    await tester.tap(find.byKey(const Key('send-continue')));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('send-submit')));
    await tester.pumpAndSettle();

    expect(find.text('QR'), findsOneWidget);
    await tester.tap(find.text('QR'));
    await tester.pumpAndSettle();
    expect(find.byType(QrImageView), findsOneWidget);
  });

  testWidgets('login does not auto-select a floonet profile', (WidgetTester tester) async {
    await tester.pumpWidget(GrinSightApp(core: _OnlyFloonetCore(), initialScreen: 'login'));
    await tester.pumpAndSettle();
    expect(find.text('Выберите профиль'), findsOneWidget);
  });

  testWidgets('login falls back to the first mainnet profile', (WidgetTester tester) async {
    await tester.pumpWidget(GrinSightApp(core: _MainnetAndFloonetCore(), initialScreen: 'login'));
    await tester.pumpAndSettle();
    expect(find.text('main-profile'), findsWidgets);
  });


}


class _OnlyFloonetCore extends FakeWalletCore {
  @override
  Future<List<WalletProfile>> profiles() async => const <WalletProfile>[
        WalletProfile(name: 'test-profile', network: 'floonet', installed: true),
      ];
}

class _MainnetAndFloonetCore extends FakeWalletCore {
  @override
  Future<List<WalletProfile>> profiles() async => const <WalletProfile>[
        WalletProfile(name: 'test-profile', network: 'floonet', installed: true),
        WalletProfile(name: 'main-profile', network: 'mainnet', installed: true),
      ];
}


