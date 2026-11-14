import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:grinsight/core.dart';
import 'package:grinsight/l10n.dart';
import 'package:grinsight/qr_widgets.dart';
import 'package:grinsight/sheets.dart';
import 'fake_core.dart';

class NotFinalizedCore extends FakeWalletCore {
  int confirmCalls = 0;
  @override
  Future<WalletJob> confirmJob(String txId) async {
    confirmCalls++;
    throw Exception('this payment is not finalized here (nothing to confirm)');
  }
}

void main() {
  testWidgets('confirmation before finalization shows explanation above slatepack', (tester) async {
    tester.view.physicalSize = const Size(1180, 1500);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    final core = NotFinalizedCore();
    final status = await core.status();
    await tester.pumpWidget(AppLocale(s: const S('ru'), lang: 'ru', onLangChanged: (_) {}, child: MaterialApp(home: Scaffold(body: SendFlowSheet(onClose: () {}, core: core, status: status, delivery: 'tor')))));
    await tester.pumpAndSettle();
    await tester.enterText(find.byKey(const Key('send-to')), 'tgrin1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');
    await tester.enterText(find.byKey(const Key('send-amount')), '1');
    await tester.tap(find.byKey(const Key('send-continue')));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('send-submit')));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('send-check-confirmation')));
    await tester.pumpAndSettle();
    final message = find.textContaining('Пока нечего проверять');
    expect(core.confirmCalls, 1);
    expect(message, findsOneWidget);
    expect(tester.getTopLeft(message).dy < tester.getTopLeft(find.byType(SlatepackQrView)).dy, isTrue);
  });
}
