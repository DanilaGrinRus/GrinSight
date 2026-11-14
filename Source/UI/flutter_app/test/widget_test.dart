import 'package:grinsight/qr_widgets.dart';
import 'dart:async';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:grinsight/main.dart';
import 'package:grinsight/core.dart';
import 'package:grinsight/l10n.dart';
import 'package:grinsight/sheets.dart';
import 'package:grinsight/wallet_model.dart';
import 'package:qr_flutter/qr_flutter.dart';

import 'fake_core.dart';

class SlowTorSendCore extends FakeWalletCore {
  final sendGate = Completer<void>();
  final queueGate = Completer<void>();
  String? sendId;

  @override
  Future<WalletJob> sendJob({required String to, required int amountNano, Map<String, String>? backupIntent}) async {
    final job = await super.sendJob(to: to, amountNano: amountNano, backupIntent: backupIntent);
    sendId = job.id;
    return job;
  }

  @override
  Future<JobProgress> waitJob(String id, {void Function(JobProgress)? onProgress}) async {
    if (id == sendId) await sendGate.future;
    return super.waitJob(id, onProgress: onProgress);
  }

  @override
  Future<void> deliverTor(String txId) async {
    await queueGate.future;
    return super.deliverTor(txId);
  }
}

void main() {
  for (final size in [const Size(1180, 1000), const Size(400, 850)]) {
    testWidgets('send cannot dismiss while building or queueing at width ${size.width}', (tester) async {
      tester.view.physicalSize = size;
      tester.view.devicePixelRatio = 1;
      addTearDown(tester.view.resetPhysicalSize);
      addTearDown(tester.view.resetDevicePixelRatio);
      final core = SlowTorSendCore();
      // Сценарий доставки через Tor; по умолчанию теперь ручная.
      await tester.pumpWidget(GrinSightApp(core: core, initialScreen: 'wallet', initialDelivery: 'tor'));
      await tester.pumpAndSettle();
      await tester.tap(find.text('Отправить').first);
      await tester.pumpAndSettle();
      await tester.enterText(find.byKey(const Key('send-to')), 'tgrin1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');
      await tester.enterText(find.byKey(const Key('send-amount')), '1');
      await tester.ensureVisible(find.byKey(const Key('send-continue')));
      await tester.tap(find.byKey(const Key('send-continue')));
      await tester.pumpAndSettle();
      await tester.ensureVisible(find.byKey(const Key('send-submit')));
      await tester.tap(find.byKey(const Key('send-submit')));
      await tester.pump();
      expect(core.sendCalls, 1);

      Future<void> checkProtected() async {
        await tester.tap(find.byIcon(Icons.close).last);
        await tester.pump();
        expect(find.byType(SendFlowSheet), findsOneWidget);
        await tester.tapAt(const Offset(3, 3));
        await tester.pump();
        expect(find.byType(SendFlowSheet), findsOneWidget);
        await tester.binding.handlePopRoute();
        await tester.pump();
        expect(find.byType(SendFlowSheet), findsOneWidget);
        if (size.width < 700) {
          await tester.drag(find.byType(SendFlowSheet), const Offset(0, 500));
          await tester.pump();
          expect(find.byType(SendFlowSheet), findsOneWidget);
        }
      }

      await checkProtected();
      core.sendGate.complete();
      await tester.pump();
      await tester.pump();
      expect(find.text('Платёж создан'), findsWidgets);
      await checkProtected();
      core.queueGate.complete();
      await tester.pumpAndSettle();
      expect(core.torDeliveries, ['tx-send']);
      await tester.tap(find.byIcon(Icons.close).last);
      await tester.pumpAndSettle();
      expect(find.byType(SendFlowSheet), findsNothing);
    });
  }
  Future<void> openDeliverySheet(WidgetTester tester, FakeWalletCore core, String delivery) async {
    tester.view.physicalSize = const Size(1180, 1200);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    final status = await core.status();
    await tester.pumpWidget(AppLocale(s: const S('ru'), lang: 'ru', onLangChanged: (_) {},
      child: MaterialApp(home: Scaffold(body: SendFlowSheet(onClose: () {}, core: core, status: status, delivery: delivery)))));
    await tester.pumpAndSettle();
  }

  testWidgets('manual delivery does not enqueue Tor and exposes S2', (tester) async {
    final core = FakeWalletCore();
    await openDeliverySheet(tester, core, 'manual');
    await tester.enterText(find.byKey(const Key('send-to')), 'tgrin1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');
    await tester.enterText(find.byKey(const Key('send-amount')), '1');
    await tester.tap(find.byKey(const Key('send-continue')));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('send-submit')));
    await tester.pumpAndSettle();
    expect(core.sendCalls, 1);
    expect(core.torDeliveries, isEmpty);
    expect(find.byKey(const Key('send-answer')), findsOneWidget);
    final slatepack = find.byType(SlatepackQrView);
    expect(slatepack, findsOneWidget);
    final slateTop = tester.getTopLeft(slatepack).dy;
    for (final key in ['send-copy-slatepack', 'send-answer', 'send-finalize', 'send-check-confirmation']) {
      expect(tester.getTopLeft(find.byKey(Key(key))).dy, lessThan(slateTop), reason: '$key must precede the long Slatepack');
    }
  });

  testWidgets('unsupported Relay never creates or queues a payment', (tester) async {
    final core = FakeWalletCore();
    await openDeliverySheet(tester, core, 'grinmail');
    await tester.enterText(find.byKey(const Key('send-to')), 'tgrin1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');
    await tester.enterText(find.byKey(const Key('send-amount')), '1');
    await tester.tap(find.byKey(const Key('send-continue')));
    await tester.pump();
    expect(core.sendCalls, 0);
    expect(core.torDeliveries, isEmpty);
    expect(find.byKey(const Key('send-submit')), findsNothing);
  });
  testWidgets('unfinished outgoing payment can be cancelled', (WidgetTester tester) async {
    tester.view.physicalSize = const Size(1180, 1000);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);

    final FakeWalletCore core = FakeWalletCore();
    await tester.pumpWidget(GrinSightApp(core: core, initialScreen: 'wallet'));
    await tester.pumpAndSettle();

    expect(find.byKey(const Key('cancel-tx1')), findsNothing, reason: 'incoming confirmed: nothing to cancel');
    await tester.ensureVisible(find.byKey(const Key('cancel-tx2')));
    await tester.tap(find.byKey(const Key('cancel-tx2')));
    await tester.pumpAndSettle();
    expect(find.text('Отменить платёж?'), findsOneWidget);
    await tester.tap(find.widgetWithText(TextButton, 'Отменить').last);
    await tester.pumpAndSettle();
    expect(core.cancelled, <String>['tx2']);
  });

  testWidgets('broadcast payment does not offer unsafe cancellation', (WidgetTester tester) async {
    tester.view.physicalSize = const Size(1180, 1000);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    final core = FakeWalletCore()..broadcastTx2 = true;
    await tester.pumpWidget(GrinSightApp(core: core, initialScreen: 'wallet'));
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('cancel-tx2')), findsNothing);
  });

  testWidgets('a delayed Tor failure is visible in payment history', (WidgetTester tester) async {
    tester.view.physicalSize = const Size(1180, 1000);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    final core = FakeWalletCore()..failedTorTx2 = true;
    await tester.pumpWidget(GrinSightApp(core: core, initialScreen: 'wallet'));
    await tester.pumpAndSettle();
    expect(find.textContaining('Ошибка обработки Tor'), findsOneWidget);
  });

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
    expect(find.byKey(const Key('wallet-history')), findsOneWidget);
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
    // Tor включается переключателем в строке статуса, независимо от мессенджера.
    expect(find.byKey(const Key('tor-switch')), findsOneWidget);
    expect(find.byKey(const Key('tor-bridges-status')), findsOneWidget);
    expect(find.text('11.00 tGRIN'), findsOneWidget);
    expect(find.textContaining('Доказан на проверенной вершине 4 100 208'), findsOneWidget);
    expect(find.byKey(const Key('wallet-history')), findsOneWidget);
    expect(find.text('Отправить'), findsOneWidget);
  });

  testWidgets('wide wallet starts at top and keeps recovery actions in menu', (WidgetTester tester) async {
    tester.view.physicalSize = const Size(1180, 1100);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    await tester.pumpWidget(GrinSightApp(core: FakeWalletCore(), initialScreen: 'wallet'));
    await tester.pumpAndSettle();
    expect(tester.getTopLeft(find.text('Мессенджер')).dy, lessThan(150));
    expect(tester.getTopLeft(find.byKey(const Key('wallet-history'))).dx, greaterThan(700));
    expect(find.text('Необработанные сообщения'), findsNothing);
    await tester.tap(find.byKey(const Key('messenger-tools')));
    await tester.pumpAndSettle();
    expect(find.text('Необработанные сообщения'), findsOneWidget);
    expect(find.text('Карантин сообщений'), findsOneWidget);
    expect(tester.takeException(), isNull);
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
    expect(find.byKey(const Key('wallet-history')), findsOneWidget);
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

    await tester.enterText(find.byKey(const Key('send-to')), 'tgrin1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');
    await tester.enterText(find.byKey(const Key('send-amount')), '1.0');
    await tester.tap(find.byKey(const Key('send-continue')));
    await tester.pumpAndSettle();

    expect(find.text('Проверьте перевод'), findsOneWidget);
    expect(find.byKey(const Key('send-submit')), findsOneWidget);
    await tester.tap(find.byKey(const Key('send-submit')));
    await tester.pumpAndSettle();
    expect(find.text('S1 SLATEPACK TEST'), findsOneWidget);
  });
  testWidgets('send queues Tor once and does not claim delivery', (WidgetTester tester) async {
    tester.view.physicalSize = const Size(1180, 1000);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    final core = FakeWalletCore();
    await tester.pumpWidget(GrinSightApp(core: core, initialScreen: 'wallet'));
    await tester.pumpAndSettle();
    // По умолчанию доставка ручная — выбираем Tor.
    await tester.tap(find.byKey(const Key('messenger-delivery-toggle')));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Tor'));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Отправить'));
    await tester.pumpAndSettle();
    await tester.enterText(find.byKey(const Key('send-to')), 'tgrin1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');
    await tester.enterText(find.byKey(const Key('send-amount')), '1');
    await tester.tap(find.byKey(const Key('send-continue')));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('send-submit')));
    await tester.pumpAndSettle();
    expect(core.sendCalls, 1);
    expect(core.torDeliveries, ['tx-send']);
    expect(find.textContaining('поставлен в очередь Tor'), findsOneWidget);
    expect(find.byKey(const Key('send-answer')), findsNothing);
  });

  testWidgets('Tor queue error preserves the created payment for manual delivery', (WidgetTester tester) async {
    tester.view.physicalSize = const Size(1180, 1000);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    final core = FakeWalletCore()..failTorDelivery = true;
    await tester.pumpWidget(GrinSightApp(core: core, initialScreen: 'wallet'));
    await tester.pumpAndSettle();
    // По умолчанию доставка ручная — выбираем Tor.
    await tester.tap(find.byKey(const Key('messenger-delivery-toggle')));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Tor'));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Отправить'));
    await tester.pumpAndSettle();
    await tester.enterText(find.byKey(const Key('send-to')), 'tgrin1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');
    await tester.enterText(find.byKey(const Key('send-amount')), '1');
    await tester.tap(find.byKey(const Key('send-continue')));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('send-submit')));
    await tester.pumpAndSettle();
    expect(core.sendCalls, 1);
    expect(core.torDeliveries, ['tx-send']);
    expect(find.text('S1 SLATEPACK TEST'), findsOneWidget);
    // Точный фрагмент: «не удалось» встречается и в пустом списке «Файлы slatepack»,
    // который на главном экране теперь раскрыт.
    expect(find.textContaining('в очередь Tor не удалось'), findsOneWidget);
    expect(find.byKey(const Key('send-answer')), findsNothing);
    expect(find.byKey(const Key('send-submit')), findsNothing);
  });

  testWidgets('english locale renders EN strings', (WidgetTester tester) async {
    tester.view.physicalSize = const Size(1180, 800);
    tester.view.devicePixelRatio = 1.0;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);

    await tester.pumpWidget(GrinSightApp(core: FakeWalletCore(), initialScreen: 'wallet', initialLanguage: 'en'));
    await tester.pumpAndSettle();

    expect(find.text('AVAILABLE'), findsOneWidget);
    expect(find.byKey(const Key('wallet-history')), findsOneWidget);
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

    await tester.enterText(find.byKey(const Key('send-to')), 'tgrin1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');
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
    await tester.enterText(find.byKey(const Key('send-to')), 'tgrin1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');
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


