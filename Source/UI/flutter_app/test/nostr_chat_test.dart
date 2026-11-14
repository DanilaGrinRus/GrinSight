import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:grinsight/chat.dart';
import 'package:grinsight/l10n.dart';
import 'fake_core.dart';

class NostrChatCore extends FakeWalletCore {
  Map<String,dynamic>? saved; String? name;
  @override
  Future<Map<String,dynamic>> chatInfo() async => {'ready':true,'address':'tgrin1mine','mode':'nostr_direct'};
  @override
  Future<void> chatNostrAdd(Map<String,dynamic> binding,String name) async {saved=binding;this.name=name;}
}

void main() {
  testWidgets('Nostr contact is submitted for verification and direct mode shows IP warning', (tester) async {
    tester.view.physicalSize=const Size(900,1600);tester.view.devicePixelRatio=1;
    addTearDown(tester.view.resetPhysicalSize);addTearDown(tester.view.resetDevicePixelRatio);
    final core=NostrChatCore();
    await tester.pumpWidget(AppLocale(lang:'ru',s:const S('ru'),onLangChanged:(_){},child:MaterialApp(home:Scaffold(body:ChatSheet(core:core,onClose:(){})))));
    await tester.pump(); await tester.pump(const Duration(milliseconds:100));
    expect(find.textContaining('сервер видит ваш IP'),findsOneWidget);
    await tester.tap(find.byKey(const Key('chat-advanced'))); await tester.pumpAndSettle();
    await tester.tap(find.text('Добавить Nostr-контакт')); await tester.pumpAndSettle();
    await tester.enterText(find.byKey(const Key('nostr-contact-name')),'Alice');
    await tester.enterText(find.byKey(const Key('nostr-contact-binding')),jsonEncode({'owner':'tgrin1test','signature_hex':'test'}));
    await tester.tap(find.byKey(const Key('nostr-contact-save'))); await tester.pumpAndSettle();
    expect(core.name,'Alice'); expect(core.saved?['owner'],'tgrin1test');
  });
}
