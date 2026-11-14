import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:grinsight/main.dart';
import 'package:grinsight/sheets.dart';
import 'package:grinsight/wallet_model.dart';
import 'fake_core.dart';

class LayoutCore extends FakeWalletCore {
  @override
  Future<List<WalletTx>> payments() async => const [
    WalletTx(txId: 'cancelled', kind: 'send', direction: TxDirection.outgoing, stage: TxStage.cancelled, amountNano: 100000, counterparty: '', confirmationsNeeded: 10),
    WalletTx(txId: 'incoming', kind: 'receive', direction: TxDirection.incoming, stage: TxStage.confirmed, amountNano: 100000, counterparty: '', confirmationsNeeded: 10, confirmations: 20),
    WalletTx(txId: 'outgoing', kind: 'send', direction: TxDirection.outgoing, stage: TxStage.broadcast, amountNano: 100000, counterparty: '', confirmationsNeeded: 10),
  ];
}

void main() {
  Future<void> launch(WidgetTester tester, Size size) async {
    tester.view.physicalSize = size;
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    await tester.pumpWidget(GrinSightApp(core: LayoutCore(), initialScreen: 'wallet'));
    await tester.pumpAndSettle();
  }
  testWidgets('desktop groups are three adjacent columns with semantic status', (tester) async {
    await launch(tester, const Size(1500, 1600));
    expect(find.byKey(const Key('recent-operations')), findsOneWidget);
    // Все действия шапки — значками в линию (без меню «⋯»).
    expect(find.byKey(const Key('wallet-own-checkpoint')), findsOneWidget);
    expect(find.byKey(const Key('history-columns')), findsNothing);
    await tester.tap(find.byKey(const Key('wallet-history')));
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('history-columns')), findsOneWidget);
    final a = tester.getTopLeft(find.byKey(const Key('history-group-cancelled')));
    final b = tester.getTopLeft(find.byKey(const Key('history-group-incoming')));
    final c = tester.getTopLeft(find.byKey(const Key('history-group-outgoing')));
    expect(a.dx < b.dx && b.dx < c.dx, isTrue);
    expect(a.dy, b.dy);
    expect(b.dy, c.dy);
    expect(find.byTooltip('ПОДТВЕРЖДЁН · 20 БЛОКОВ'), findsOneWidget);
    await tester.tap(find.byKey(const Key('history-back')));
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('recent-operations')), findsOneWidget);
  });
  testWidgets('top action opens genesis verification without starting it', (tester) async {
    await launch(tester, const Size(1100, 1000));
    await tester.tap(find.byKey(const Key('wallet-own-checkpoint')));
    await tester.pumpAndSettle();
    expect(find.byType(OwnCheckpointSheet), findsOneWidget);
  });
  testWidgets('narrow screens stack groups without truncating into three columns', (tester) async {
    await launch(tester, const Size(390, 1600));
    await tester.tap(find.byKey(const Key('wallet-history')));
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('history-columns')), findsNothing);
    final a = tester.getTopLeft(find.byKey(const Key('history-group-cancelled')));
    final b = tester.getTopLeft(find.byKey(const Key('history-group-incoming')));
    final c = tester.getTopLeft(find.byKey(const Key('history-group-outgoing')));
    expect(a.dy < b.dy && b.dy < c.dy, isTrue);
  });
}
