import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:grinsight/chat.dart';
import 'package:grinsight/l10n.dart';
import 'package:grinsight/messenger.dart';
import 'fake_core.dart';

class RecordingChatCore extends FakeWalletCore {
  String? recipient;
  String? text;
  @override
  Future<Map<String, dynamic>> chatSend(String to, String message) async {
    recipient = to; text = message; return {};
  }
}

void main() {
  testWidgets('choose and search a saved messaging contact without exposing manual settings', (tester) async {
    tester.view.physicalSize = const Size(1080, 1800);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    final core = RecordingChatCore();
    final contacts = [UContact(name: 'Alice', fullAddress: 'wallet-a', messenger: 'peer-a', verified: true),
      UContact(name: 'Bob', fullAddress: 'wallet-b', messenger: 'peer-b'),
      UContact(name: 'No messenger', fullAddress: 'wallet-c')];
    await tester.pumpWidget(MaterialApp(home: AppLocale(lang: 'ru', s: const S('ru'), onLangChanged: (_) {},
      child: Scaffold(body: ChatSheet(core: core, onClose: () {}, contacts: contacts)))));
    await tester.pump(); await tester.pump(const Duration(milliseconds: 100));
    expect(find.text('Выберите контакт'), findsOneWidget);
    expect(find.text('No messenger'), findsNothing);
    expect(find.byKey(const Key('chat-peer-manual')), findsNothing);
    await tester.enterText(find.byKey(const Key('chat-contact-search')), 'bo'); await tester.pump();
    expect(find.text('Alice'), findsNothing);
    await tester.tap(find.byKey(const ValueKey('chat-contact-wallet-b'))); await tester.pump();
    expect(find.text('Bob'), findsOneWidget);
    await tester.enterText(find.byKey(const Key('chat-message')), 'Привет'); await tester.pump();
    await tester.tap(find.text('Отправить')); await tester.pump();
    expect(core.recipient, 'peer-b'); expect(core.text, 'Привет');
    await tester.tap(find.byKey(const Key('chat-change-contact'))); await tester.pump();
    expect(find.text('Выберите контакт'), findsOneWidget);
  });
  testWidgets('mobile empty state offers contact search; selected contact skips picker', (tester) async {
    tester.view.physicalSize = const Size(390, 844);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    var opened = false;
    await tester.pumpWidget(MaterialApp(home: AppLocale(lang: 'ru', s: const S('ru'), onLangChanged: (_) {},
      child: Scaffold(body: ChatSheet(core: RecordingChatCore(), onClose: () {}, onFindContact: () { opened = true; })))));
    await tester.pump(); await tester.pump(const Duration(milliseconds: 100));
    expect(find.text('Пока нет контактов с перепиской.'), findsOneWidget);
    await tester.tap(find.byKey(const Key('chat-find-contact'))); await tester.pump();
    expect(opened, isTrue);
    await tester.pumpWidget(MaterialApp(home: AppLocale(lang: 'ru', s: const S('ru'), onLangChanged: (_) {},
      child: Scaffold(body: ChatSheet(key: const Key('selected'), core: RecordingChatCore(), onClose: () {}, initialPeer: 'peer-a',
        contacts: [UContact(name: 'Alice', fullAddress: 'wallet-a', messenger: 'peer-a')])))));
    await tester.pump(); await tester.pump(const Duration(milliseconds: 100));
    expect(find.text('Alice'), findsOneWidget);
    expect(find.text('Выберите контакт'), findsNothing);
    expect(tester.takeException(), isNull);
  });

}
