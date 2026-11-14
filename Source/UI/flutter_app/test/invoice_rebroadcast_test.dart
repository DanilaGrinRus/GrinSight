import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:grinsight/core.dart';
import 'package:grinsight/main.dart';
import 'package:grinsight/wallet_model.dart';
import 'fake_core.dart';

class BroadcastFailureCore extends FakeWalletCore {
  BroadcastFailureCore({this.stage = TxStage.waitingAnswer});
  TxStage stage;
  int finalizations = 0;
  int broadcasts = 0;
  @override
  Future<List<WalletTx>> payments() async => [WalletTx(
    txId: 'invoice-id', kind: 'invoice', direction: TxDirection.incoming,
    stage: stage, amountNano: 100000000, counterparty: '', confirmationsNeeded: 10,
  )];
  @override
  Future<WalletJob> finalizeJob({required String txId, required String answer}) async {
    finalizations++;
    return WalletJob(id: 'test-finalize', core: this);
  }
  @override
  Future<WalletJob> broadcastJob(String txId) async {
    broadcasts++;
    return WalletJob(id: 'test-broadcast', core: this);
  }
  @override
  Future<JobProgress> waitJob(String id, {void Function(JobProgress)? onProgress}) async {
    if (id == 'test-finalize') {
      stage = TxStage.finalized;
      return JobProgress(id: id, state: 'failed', phase: 'broadcast', lines: const [], error: 'broadcast failed');
    }
    if (id == 'test-broadcast') {
      stage = TxStage.broadcast;
      return JobProgress(id: id, state: 'done', phase: 'done', lines: const []);
    }
    return super.waitJob(id, onProgress: onProgress);
  }
}

Future<void> openInvoice(WidgetTester tester, BroadcastFailureCore core) async {
  tester.view.physicalSize = const Size(1180, 1100);
  tester.view.devicePixelRatio = 1;
  addTearDown(tester.view.resetPhysicalSize);
  addTearDown(tester.view.resetDevicePixelRatio);
  await tester.pumpWidget(GrinSightApp(core: core, initialScreen: 'wallet'));
  await tester.pumpAndSettle();
  await tester.tap(find.text('Получить'));
  await tester.pumpAndSettle();
  await tester.tap(find.text('Счёт'));
  await tester.pumpAndSettle();
}

void main() {
  test('finalized does not mean broadcast', () {
    expect(txStageFromService('finalized'), TxStage.finalized);
    expect(txStageFromService('broadcast'), TxStage.broadcast);
  });
  testWidgets('after broadcast failure retry only broadcasts the saved transaction', (tester) async {
    final core = BroadcastFailureCore();
    await openInvoice(tester, core);
    await tester.enterText(find.byKey(const Key('invoice-answer')), 'I2 TEST');
    await tester.ensureVisible(find.byKey(const Key('invoice-finalize')));
    await tester.tap(find.byKey(const Key('invoice-finalize')));
    await tester.pumpAndSettle();
    expect(core.finalizations, 1);
    expect(find.byKey(const Key('invoice-finalize')), findsNothing);
    final retry = find.byKey(const Key('invoice-broadcast-invoice-id'));
    expect(retry, findsOneWidget);
    expect(find.text('Счёт завершён, рассылка не подтверждена'), findsOneWidget);
    await tester.ensureVisible(retry);
    await tester.tap(retry);
    await tester.pumpAndSettle();
    expect(core.broadcasts, 1);
    expect(core.finalizations, 1);
    expect(find.byKey(const Key('invoice-broadcast-invoice-id')), findsNothing);
  });
  testWidgets('previously finalized invoice is recoverable after reopening', (tester) async {
    final core = BroadcastFailureCore(stage: TxStage.finalized);
    await openInvoice(tester, core);
    expect(find.byKey(const Key('invoice-broadcast-invoice-id')), findsOneWidget);
    expect(find.byKey(const Key('invoice-finalize')), findsNothing);
    expect(core.finalizations, 0);
  });
}
