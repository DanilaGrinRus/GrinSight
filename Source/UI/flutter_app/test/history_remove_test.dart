import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:grinsight/main.dart';
import 'package:grinsight/wallet_model.dart';
import 'fake_core.dart';

class HistoryDeletionCore extends FakeWalletCore {
  final removed = <String>[];
  @override
  Future<void> hideCancelled(String txId) async { removed.add(txId); }
  @override
  Future<List<WalletTx>> payments() async => [
    for (final id in ['cancel-a', 'cancel-b'])
      if (!removed.contains(id)) WalletTx(txId: id, kind: 'send', direction: TxDirection.outgoing,
        stage: TxStage.cancelled, amountNano: 1000, counterparty: '', confirmationsNeeded: 10),
    const WalletTx(txId: 'active', kind: 'send', direction: TxDirection.outgoing,
      stage: TxStage.waitingAnswer, amountNano: 1000, counterparty: '', confirmationsNeeded: 10),
  ];
}

void main() {
  testWidgets('remove one and confirm removing remaining cancelled entries', (tester) async {
    tester.view.physicalSize = const Size(1180, 1400);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    final core = HistoryDeletionCore();
    await tester.pumpWidget(GrinSightApp(core: core, initialScreen: 'wallet'));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('wallet-history')));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Отменённые'));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('hide-cancelled-cancel-a')));
    await tester.pumpAndSettle();
    expect(core.removed, ['cancel-a']);
    expect(find.byKey(const Key('resume-active')), findsOneWidget);
    await tester.tap(find.byKey(const Key('hide-all-cancelled')));
    await tester.pumpAndSettle();
    expect(core.removed, ['cancel-a']);
    await tester.tap(find.byKey(const Key('confirm-hide-all')));
    await tester.pumpAndSettle();
    expect(core.removed, ['cancel-a', 'cancel-b']);
    expect(find.byKey(const Key('resume-active')), findsOneWidget);
  });
}
