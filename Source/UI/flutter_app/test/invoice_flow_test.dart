import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:grinsight/core.dart';
import 'package:grinsight/main.dart';
import 'package:grinsight/wallet_model.dart';
import 'fake_core.dart';

class InvoiceCore extends FakeWalletCore {
  String? finalizedId;
  String? finalizedAnswer;
  @override
  Future<List<WalletTx>> payments() async => <WalletTx>[
    const WalletTx(txId: 'persisted-invoice', kind: 'invoice', direction: TxDirection.incoming,
      stage: TxStage.waitingAnswer, amountNano: 100000000, counterparty: '', confirmationsNeeded: 10),
    const WalletTx(txId: 'not-invoice', kind: 'receive', direction: TxDirection.incoming,
      stage: TxStage.waitingAnswer, amountNano: 200000000, counterparty: '', confirmationsNeeded: 10),
  ];

  @override
  Future<WalletJob> finalizeJob({required String txId, required String answer}) async {
    finalizedId = txId;
    finalizedAnswer = answer;
    return super.finalizeJob(txId: txId, answer: answer);
  }
}

void main() {
  setUp(() { TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger.setMockMethodCallHandler(SystemChannels.platform, (call) async => null); });
  tearDown(() { TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger.setMockMethodCallHandler(SystemChannels.platform, null); });

  testWidgets('existing invoice can be selected and finalized with I2', (tester) async {
    tester.view.physicalSize = const Size(1180, 1100);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    final core = InvoiceCore();
    await tester.pumpWidget(GrinSightApp(core: core, initialScreen: 'wallet'));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Получить'));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Счёт'));
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('invoice-select')), findsOneWidget);
    final answer = find.byKey(const Key('invoice-answer'));
    await tester.ensureVisible(answer);
    await tester.enterText(answer, 'I2 ANSWER TEST');
    final button = find.byKey(const Key('invoice-finalize'));
    await tester.ensureVisible(button);
    await tester.tap(button);
    await tester.pumpAndSettle();
    expect(core.finalizedId, 'persisted-invoice');
    expect(core.finalizedAnswer, 'I2 ANSWER TEST');
  });

  testWidgets('paid invoice answer exposes a copy action', (tester) async {
    tester.view.physicalSize = const Size(1180, 1100);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    await tester.pumpWidget(GrinSightApp(core: InvoiceCore(), initialScreen: 'wallet'));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Получить'));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Оплатить'));
    await tester.pumpAndSettle();
    await tester.enterText(find.byKey(const Key('pay-invoice')), 'I1 TEST');
    await tester.tap(find.text('Оплатить счёт'));
    await tester.pumpAndSettle();
    expect(find.text('Скопировать slatepack'), findsOneWidget);
  });
}
