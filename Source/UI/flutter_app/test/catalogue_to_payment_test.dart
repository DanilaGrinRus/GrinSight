import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:grinsight/catalogue_api.dart';
import 'package:grinsight/chat.dart';
import 'package:grinsight/core.dart';
import 'package:grinsight/main.dart';
import 'fake_core.dart';

class FlowCore extends FakeWalletCore implements CatalogueApi {
  bool added = false;
  bool checked = false;
  String? lastQuery;
  static const walletAddress='tgrin1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
  static const peer='tgrinmsg1testcontact';
  @override
  Future<List<ContactInfo>> contacts() async => added ? [ContactInfo(id:walletAddress,name:'alice',messenger:peer,identityChecked:checked)] : [];
  @override
  Future<Map<String,dynamic>> catalogueOwnCode() async => {'comparison_code':'0000-0000-0000'};
  @override
  Future<Map<String,dynamic>> catalogueSearch(String name) async { lastQuery=name; return {'results':[{'comparison_code':'1234-5678-abcd','profile':{'claims':{'name':'alice','wallet_address':walletAddress,'binding':{'owner':peer}}}}]}; }
  @override
  Future<void> catalogueAdd(Map<String,dynamic> profile,String name,{required bool identityChecked}) async { added=true;checked=identityChecked; }
  @override
  Future<Map<String,dynamic>> cataloguePublish(String name,{required bool revoked,required bool consentPublic}) async => {};
  @override
  Future<Map<String,dynamic>> backupPaymentContacts() async => {'mode':'nostr_direct','route':'route','contacts':[{'name':'alice','address':peer}]};
}

class ContactReloadFailureCore extends FlowCore {
  @override
  Future<List<ContactInfo>> contacts() async {
    if (added) throw StateError('contact book unavailable');
    return [];
  }
}

void main() {
  testWidgets('does not open a stale chat when reloading contact book fails', (tester) async {
    tester.view.physicalSize=const Size(1180,1400); tester.view.devicePixelRatio=1;
    addTearDown(tester.view.resetPhysicalSize); addTearDown(tester.view.resetDevicePixelRatio);
    final core=ContactReloadFailureCore();
    await tester.pumpWidget(GrinSightApp(core:core,initialScreen:'wallet'));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('open-contact-catalogue'))); await tester.pumpAndSettle();
    await tester.enterText(find.byKey(const Key('catalogue-query')), 'ant ash bay bee cafe cold');
    await tester.tap(find.text('Найти')); await tester.pumpAndSettle();
    await tester.tap(find.text('Добавить').last); await tester.pumpAndSettle();
    await tester.tap(find.text('Сверил код')); await tester.pumpAndSettle();
    expect(core.added, isTrue);
    expect(find.byType(ChatSheet), findsNothing);
    expect(find.textContaining('канал переписки недоступен'), findsOneWidget);
  });

  testWidgets('search, confirm contact code and start a payment using bound channel', (tester) async {
    tester.view.physicalSize=const Size(1180,1400); tester.view.devicePixelRatio=1;
    addTearDown(tester.view.resetPhysicalSize); addTearDown(tester.view.resetDevicePixelRatio);
    final core=FlowCore();
    await tester.pumpWidget(GrinSightApp(core:core,initialScreen:'wallet'));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('open-contact-catalogue'))); await tester.pumpAndSettle();
    await tester.enterText(find.byKey(const Key('catalogue-query')), 'ant ash bay bee cafe cold');
    await tester.tap(find.text('Найти')); await tester.pumpAndSettle();
    expect(core.lastQuery, 'ant-ash-bay-bee-cafe-cold');
    await tester.tap(find.text('Добавить').last); await tester.pumpAndSettle();
    await tester.tap(find.text('Сверил код')); await tester.pumpAndSettle();
    expect(core.added,isTrue);expect(core.checked,isTrue);
    expect(find.byType(ChatSheet), findsOneWidget);
    await tester.tap(find.byKey(const Key('chat-advanced'))); await tester.pumpAndSettle();
    expect(tester.widget<TextField>(find.byKey(const Key('chat-peer-manual'))).controller?.text, FlowCore.peer);
    await tester.tap(find.descendant(of: find.byType(ChatSheet), matching: find.byIcon(Icons.close))); await tester.pumpAndSettle();
    await tester.tap(find.text('alice').first); await tester.pumpAndSettle();
    expect(find.text('Код сверён пользователем'),findsOneWidget);
    await tester.tap(find.byKey(const Key('contact-send'))); await tester.pumpAndSettle();
    final peer=find.byKey(const Key('payment-backup-peer'));
    expect(peer,findsOneWidget);
    expect(tester.state<FormFieldState<String>>(peer).value,FlowCore.peer);
  });
}
