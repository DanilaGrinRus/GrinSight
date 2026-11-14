import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:grinsight/core.dart';
import 'package:grinsight/main.dart';
import 'package:grinsight/wallet_model.dart';

import 'fake_core.dart';

class HistoryCore extends FakeWalletCore {
  final checked = <String>[];
  bool verified = false;
  bool failConfirmation = false;
  Completer<void>? gate;
  String? finalizedId;
  String? finalizedAnswer;

  @override
  Future<WalletJob> finalizeJob({required String txId, required String answer}) async {
    finalizedId = txId;
    finalizedAnswer = answer;
    return super.finalizeJob(txId: txId, answer: answer);
  }

  @override
  Future<List<WalletTx>> payments() async => <WalletTx>[
    WalletTx(txId: 'send-ready', kind: 'send', direction: TxDirection.outgoing,
        stage: verified ? TxStage.inBlock : TxStage.broadcast, amountNano: 100000000,
        counterparty: '', confirmationsNeeded: 10, height: verified ? 123 : null),
    const WalletTx(txId: 'send-wait', kind: 'send', direction: TxDirection.outgoing,
        stage: TxStage.waitingAnswer, amountNano: 100000000, counterparty: '', confirmationsNeeded: 10),
    const WalletTx(txId: 'paid-invoice', kind: 'pay_invoice', direction: TxDirection.outgoing,
        stage: TxStage.broadcast, amountNano: 100000000, counterparty: '', confirmationsNeeded: 10),
    const WalletTx(txId: 'receive', kind: 'receive', direction: TxDirection.incoming,
        stage: TxStage.inBlock, amountNano: 100000000, counterparty: '', confirmationsNeeded: 10),
  ];

  @override
  Future<WalletJob> confirmJob(String txId) async {
    checked.add(txId);
    if (gate != null) await gate!.future;
    if (failConfirmation) throw Exception('confirmation failed');
    verified = true;
    return super.confirmJob(txId);
  }
}

void main() {
  testWidgets('resume uses the selected existing send and its S2', (tester) async {
    tester.view.physicalSize = const Size(1180, 1400);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    final core = HistoryCore();
    await tester.pumpWidget(GrinSightApp(core: core, initialScreen: 'wallet'));
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('resume-send-ready')), findsNothing);
    expect(find.byKey(const Key('resume-receive')), findsNothing);
    final resume = find.byKey(const Key('resume-send-wait'));
    await tester.ensureVisible(resume);
    await tester.tap(resume);
    await tester.pumpAndSettle();
    await tester.enterText(find.byKey(const Key('resume-answer')), 'test S2');
    await tester.tap(find.byKey(const Key('resume-finalize')));
    await tester.pumpAndSettle();
    expect(core.finalizedId, 'send-wait');
    expect(core.finalizedAnswer, 'test S2');
    expect(core.sendCalls, 0);
  });

  testWidgets('mobile layout opens messenger', (tester) async {
    tester.view.physicalSize = const Size(400, 900);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    await tester.pumpWidget(GrinSightApp(core: FakeWalletCore(), initialScreen: 'wallet'));
    await tester.pumpAndSettle();
    final button = find.byKey(const Key('mobile-messenger'));
    await tester.ensureVisible(button);
    await tester.tap(button);
    await tester.pumpAndSettle();
    expect(find.text('Переписка'), findsOneWidget);
  });
  testWidgets('history can check a sent payment and reload its status', (tester) async {
    tester.view.physicalSize = const Size(1180, 1400);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    final core = HistoryCore();
    await tester.pumpWidget(GrinSightApp(core: core, initialScreen: 'wallet'));
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('confirm-send-wait')), findsNothing);
    expect(find.byKey(const Key('confirm-paid-invoice')), findsNothing);
    expect(find.byKey(const Key('confirm-receive')), findsNothing);
    final button = find.byKey(const Key('confirm-send-ready'));
    expect(button, findsOneWidget);
    await tester.ensureVisible(button);
    await tester.tap(button);
    await tester.pumpAndSettle();
    expect(core.checked, ['send-ready']);
    expect(find.textContaining('123'), findsWidgets);
  });

  testWidgets('history avoids duplicate starts while a job is being created', (tester) async {
    tester.view.physicalSize = const Size(1180, 1400);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    final core = HistoryCore()..gate = Completer<void>();
    await tester.pumpWidget(GrinSightApp(core: core, initialScreen: 'wallet'));
    await tester.pumpAndSettle();
    final button = find.byKey(const Key('confirm-send-ready'));
    await tester.ensureVisible(button);
    await tester.tap(button);
    await tester.pump();
    expect(tester.widget<TextButton>(button).onPressed, isNull);
    expect(core.checked, ['send-ready']);
    core.gate!.complete();
    await tester.pumpAndSettle();
  });

  testWidgets('history shows confirmation errors and allows retry', (tester) async {
    tester.view.physicalSize = const Size(1180, 1400);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    final core = HistoryCore()..failConfirmation = true;
    await tester.pumpWidget(GrinSightApp(core: core, initialScreen: 'wallet'));
    await tester.pumpAndSettle();
    final button = find.byKey(const Key('confirm-send-ready'));
    await tester.ensureVisible(button);
    await tester.tap(button);
    await tester.pump();
    await tester.pump(const Duration(milliseconds: 200));
    expect(find.textContaining('confirmation failed'), findsOneWidget);
    expect(tester.widget<TextButton>(button).onPressed, isNotNull);
  });
}
