import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:grinsight/l10n.dart';
import 'package:grinsight/sheets.dart';
import 'package:grinsight/core.dart';
import 'package:grinsight/wallet_model.dart';
import 'fake_core.dart';

class BackupCore extends FakeWalletCore {
  String mode = 'nostr_direct';
  String route = 'route-original';
  String? deliveredPeer;
  String? deliveredMode;
  int backupQueues = 0;
  int retries = 0;
  @override
  Future<Map<String, dynamic>> backupPaymentRetryInfo(String txId) async => {'available': true, 'mode': mode};
  @override
  Future<void> retryBackupPayment(String txId) async { retries++; }
  @override
  Future<Map<String, dynamic>> backupPaymentContacts() async => {'mode': mode, 'route': route, 'contacts': [{'name': 'Alice', 'address': 'tgrinmsg1testcontact'}]};
  @override
  Future<void> deliverBackup(String txId, {required String peer, required String mode, required String route}) async { deliveredPeer = peer; deliveredMode = mode; backupQueues++; }
}

class BackupInvoiceCore extends BackupCore {
  int invoices = 0;
  String? payer;
  Map<String, String>? intent;
  @override
  Future<InvoiceResult> invoice({required int amountNano, String? payer, Map<String, String>? backupIntent}) async {
    invoices++; this.payer = payer; intent = backupIntent;
    return const InvoiceResult(txId: 'existing-invoice', slatepack: 'BEGINSLATEPACK. x. ENDSLATEPACK.');
  }
}

class BackupInboxCore extends FakeWalletCore {
  bool failValidation = false;
  bool failQueue = false;
  int paid = 0;
  int queued = 0;
  @override
  Future<List<InboxItem>> torInbox() async => [const InboxItem(file: 'invoice-test.txt', kind: 'invoice', transportMode: 'nostr_direct')];
  @override
  Future<void> validateBackupInboxInvoice(String file) async { if (failValidation) throw StateError('route changed'); }
  @override
  Future<WalletJob> payInvoiceInboxJob(String file) async { paid++; return super.payInvoiceInboxJob(file); }
  @override
  Future<void> deliverBackupInboxInvoice(String file, String txId) async { if (failQueue) throw StateError('queue failed'); queued++; }
}

void main() {
  Future<void> open(WidgetTester tester, BackupCore core) async {
    tester.view.physicalSize = const Size(1100, 1600); tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize); addTearDown(tester.view.resetDevicePixelRatio);
    final status = await core.status();
    await tester.pumpWidget(AppLocale(lang: 'ru', s: const S('ru'), onLangChanged: (_) {}, child: MaterialApp(home: Scaffold(body: SendFlowSheet(onClose: () {}, core: core, status: status, delivery: 'grinmail')))));
    await tester.pumpAndSettle();
    await tester.enterText(find.byKey(const Key('send-to')), 'tgrin1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');
    await tester.enterText(find.byKey(const Key('send-amount')), '1');
  }
  testWidgets('backup payment requires explicit signed contact and pins direct Nostr route', (tester) async {
    final core = BackupCore(); await open(tester, core);
    await tester.tap(find.byKey(const Key('send-continue'))); await tester.pumpAndSettle();
    expect(core.sendCalls, 0);
    await tester.tap(find.byKey(const Key('payment-backup-peer'))); await tester.pumpAndSettle();
    await tester.tap(find.textContaining('Alice').last); await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('send-continue'))); await tester.pumpAndSettle();
    expect(find.text('Nostr напрямую'), findsWidgets);
    await tester.tap(find.byKey(const Key('send-submit'))); await tester.pumpAndSettle();
    expect(core.sendCalls, 1); expect(core.backupQueues, 1);
    expect(core.lastBackupIntent, {'peer': 'tgrinmsg1testcontact', 'mode': 'nostr_direct', 'route': 'route-original'});
    expect(core.deliveredMode, 'nostr_direct'); expect(core.deliveredPeer, 'tgrinmsg1testcontact');
    expect(core.torDeliveries, isEmpty);
  });
  testWidgets('channel change before send does not reserve inputs', (tester) async {
    final core = BackupCore(); await open(tester, core);
    await tester.tap(find.byKey(const Key('payment-backup-peer'))); await tester.pumpAndSettle();
    await tester.tap(find.textContaining('Alice').last); await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('send-continue'))); await tester.pumpAndSettle();
    core.mode = 'i2p_direct';
    await tester.tap(find.byKey(const Key('send-submit'))); await tester.pumpAndSettle();
    expect(core.sendCalls, 0); expect(core.backupQueues, 0); expect(core.torDeliveries, isEmpty);
  });
  testWidgets('server change in the same mode before send does not reserve inputs', (tester) async {
    final core = BackupCore(); await open(tester, core);
    await tester.tap(find.byKey(const Key('payment-backup-peer'))); await tester.pumpAndSettle();
    await tester.tap(find.textContaining('Alice').last); await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('send-continue'))); await tester.pumpAndSettle();
    core.route = 'route-changed';
    await tester.tap(find.byKey(const Key('send-submit'))); await tester.pumpAndSettle();
    expect(core.sendCalls, 0); expect(core.backupQueues, 0); expect(core.torDeliveries, isEmpty);
  });

  testWidgets('history retry reuses existing payment without creating another', (tester) async {
    tester.view.physicalSize = const Size(1100, 1000); tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize); addTearDown(tester.view.resetDevicePixelRatio);
    final core = BackupCore();
    await tester.pumpWidget(AppLocale(lang: 'ru', s: const S('ru'), onLangChanged: (_) {}, child: MaterialApp(home: Scaffold(body: ResumeSendSheet(onClose: () {}, core: core, txId: 'existing', network: 'floonet')))));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('retry-backup-payment'))); await tester.pumpAndSettle();
    expect(core.retries, 1); expect(core.sendCalls, 0); expect(core.torDeliveries, isEmpty);
    expect(find.byKey(const Key('retry-backup-notice')), findsOneWidget);
  });

  testWidgets('incoming invoice validates original route before reserving funds', (tester) async {
    tester.view.physicalSize = const Size(1100, 1000); tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize); addTearDown(tester.view.resetDevicePixelRatio);
    final core = BackupInboxCore()..failValidation = true;
    await tester.pumpWidget(AppLocale(lang: 'ru', s: const S('ru'), onLangChanged: (_) {}, child: MaterialApp(home: Scaffold(body: InboxPanel(core: core, network: 'floonet')))));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('inbox-pay-invoice-test.txt'))); await tester.pumpAndSettle();
    expect(core.paid, 0); expect(core.queued, 0); expect(core.torDeliveries, isEmpty);
  });
  testWidgets('failed I2 queue preserves saved response for manual handover', (tester) async {
    tester.view.physicalSize = const Size(1100, 1000); tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize); addTearDown(tester.view.resetDevicePixelRatio);
    final core = BackupInboxCore()..failQueue = true;
    await tester.pumpWidget(AppLocale(lang: 'ru', s: const S('ru'), onLangChanged: (_) {}, child: MaterialApp(home: Scaffold(body: InboxPanel(core: core, network: 'floonet')))));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('inbox-pay-invoice-test.txt'))); await tester.pumpAndSettle();
    expect(core.paid, 1); expect(core.queued, 0); expect(core.torDeliveries, isEmpty);
    expect(find.byKey(const Key('inbox-delivery-notice')), findsOneWidget);
    expect(find.textContaining('не поставлен в очередь'), findsOneWidget);
    expect(find.text('Скопировать slatepack'), findsOneWidget);
  });

  testWidgets('backup invoice requires payer wallet and signed contact before creation', (tester) async {
    tester.view.physicalSize = const Size(1100, 1500); tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize); addTearDown(tester.view.resetDevicePixelRatio);
    final core = BackupInvoiceCore();
    await tester.pumpWidget(AppLocale(lang: 'ru', s: const S('ru'), onLangChanged: (_) {}, child: MaterialApp(home: Scaffold(body: ReceiveSheet(core: core, onClose: () {}, address: 'tgrin1mine', network: 'floonet', delivery: 'grinmail')))));
    await tester.pumpAndSettle(); await tester.tap(find.text('Счёт')); await tester.pumpAndSettle();
    await tester.enterText(find.byKey(const Key('invoice-amount')), '1');
    await tester.tap(find.text('Создать счёт')); await tester.pumpAndSettle();
    expect(core.invoices, 0);
    await tester.enterText(find.byKey(const Key('invoice-payer')), 'tgrin1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');
    await tester.tap(find.byKey(const Key('invoice-backup-peer'))); await tester.pumpAndSettle();
    await tester.tap(find.textContaining('Alice').last); await tester.pumpAndSettle();
    await tester.tap(find.text('Создать счёт')); await tester.pumpAndSettle();
    expect(core.invoices, 1); expect(core.payer, startsWith('tgrin1'));
    expect(core.intent, {'peer': 'tgrinmsg1testcontact', 'mode': 'nostr_direct', 'route': 'route-original'});
    expect(core.backupQueues, 1); expect(core.torDeliveries, isEmpty);
    expect(find.byKey(const Key('invoice-delivery-notice')), findsOneWidget);
  });

  testWidgets('invoice or received reply uses retry-only view without false finalization', (tester) async {
    tester.view.physicalSize = const Size(1100, 1000); tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize); addTearDown(tester.view.resetDevicePixelRatio);
    final core = BackupCore();
    await tester.pumpWidget(AppLocale(lang: 'ru', s: const S('ru'), onLangChanged: (_) {}, child: MaterialApp(home: Scaffold(body: ResumeSendSheet(onClose: () {}, core: core, txId: 'existing', network: 'floonet', retryOnly: true)))));
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('resume-answer')), findsNothing);
    expect(find.byKey(const Key('resume-finalize')), findsNothing);
    expect(find.byKey(const Key('resume-copy-slatepack')), findsOneWidget);
    await tester.tap(find.byKey(const Key('retry-backup-payment'))); await tester.pumpAndSettle();
    expect(core.retries, 1); expect(core.sendCalls, 0); expect(core.torDeliveries, isEmpty);
  });

}
