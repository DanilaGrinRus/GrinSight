import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:grinsight/l10n.dart';
import 'package:grinsight/sheets.dart';
import 'package:grinsight/wallet_model.dart';
import 'fake_core.dart';

class ContactOfferCore extends FakeWalletCore {
  bool? saved;
  @override
  Future<PendingDecision> torDecide({required String slateId, required bool accept, bool addContact = true, String name = ''}) async {
    saved = addContact;
    return PendingDecision(accepted: accept);
  }
}

void main() {
  testWidgets('signed messenger key offers contact even without claimed wallet address', (tester) async {
    tester.view.physicalSize = const Size(900, 1400);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    final core = ContactOfferCore();
    const pending = PendingPayment(slateId: 'one', amountNano: 1, channel: 'messenger', messengerPeer: 'tgrin1verified');
    await tester.pumpWidget(AppLocale(lang: 'ru', s: const S('ru'), onLangChanged: (_) {}, child: MaterialApp(home: Builder(builder: (c) => Scaffold(body: TextButton(onPressed: () => showDialog<void>(context: c, builder: (_) => Material(child: PendingPaymentDialog(core: core, pending: pending))), child: const Text('open')))))));
    await tester.tap(find.text('open'));
    await tester.pumpAndSettle();
    expect(find.text('Сохранить в адресную книгу'), findsOneWidget);
    expect(find.textContaining('Автоматический приём не включается'), findsOneWidget);
    await tester.tap(find.text('Сохранить в адресную книгу'));
    await tester.tap(find.byKey(const Key('pending-accept')));
    await tester.pumpAndSettle();
    expect(core.saved, true);
  });
  testWidgets('unverified messenger address is not labelled verified or offered as trusted', (tester) async {
    final core = ContactOfferCore();
    const pending = PendingPayment(slateId: 'two', amountNano: 1, channel: 'messenger', from: 'tgrin1claimed');
    await tester.pumpWidget(AppLocale(lang: 'ru', s: const S('ru'), onLangChanged: (_) {}, child: MaterialApp(home: Builder(builder: (c) => Scaffold(body: TextButton(onPressed: () => showDialog<void>(context: c, builder: (_) => Material(child: PendingPaymentDialog(core: core, pending: pending))), child: const Text('open')))))));
    await tester.tap(find.text('open'));
    await tester.pumpAndSettle();
    expect(find.text('Сохранить в адресную книгу'), findsNothing);
    expect(find.textContaining('Адрес указан отправителем и не подтверждён'), findsOneWidget);
  });

  testWidgets('foreign address can be saved only with explicit unverified warning', (tester) async {
    tester.view.physicalSize = const Size(900, 1400);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    final core = ContactOfferCore();
    const pending = PendingPayment(slateId: 'three', amountNano: 1, channel: 'tor-foreign', from: 'tgrin1claimed');
    await tester.pumpWidget(AppLocale(lang: 'ru', s: const S('ru'), onLangChanged: (_) {}, child: MaterialApp(home: Builder(builder: (c) => Scaffold(body: TextButton(onPressed: () => showDialog<void>(context: c, builder: (_) => Material(child: PendingPaymentDialog(core: core, pending: pending))), child: const Text('open')))))));
    await tester.tap(find.text('open'));
    await tester.pumpAndSettle();
    expect(find.textContaining('Адрес заявлен отправителем и не подтверждён'), findsOneWidget);
    await tester.tap(find.text('Сохранить в адресную книгу'));
    await tester.tap(find.byKey(const Key('pending-accept')));
    await tester.pumpAndSettle();
    expect(core.saved, true);
  });

}
