import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:grinsight/chat.dart';
import 'package:grinsight/l10n.dart';
import 'fake_core.dart';

class ChatCore extends FakeWalletCore {
  @override
  Future<Map<String, dynamic>> chatMessages([int after = 0]) async => <String, dynamic>{'next': 1, 'epoch': 'test', 'messages': after == 0 ? <Map<String, dynamic>>[
    <String, dynamic>{'peer':'tgrin1signed', 'direction':'incoming', 'text':'signed text', 'verified':true},
    <String, dynamic>{'peer':'tgrin1unknown', 'direction':'incoming', 'text':'old text', 'verified':false},
  ] : <Map<String, dynamic>>[]};
}

class FailedSendChatCore extends FakeWalletCore {
  @override
  Future<Map<String, dynamic>> chatSend(String to, String text) async =>
      throw Exception('arti: tor: connect: Failed to obtain hidden service circuit');
}

void main() {
  testWidgets('only verified incoming messages show verified signature', (tester) async {
    tester.view.physicalSize = const Size(1000, 1600);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    await tester.pumpWidget(MaterialApp(home: AppLocale(lang: 'ru', s: const S('ru'), onLangChanged: (_) {}, child: Scaffold(body: ChatSheet(core: ChatCore(), onClose: () {})))));
    await tester.pump();
    await tester.pump(const Duration(milliseconds: 100));
    expect(find.textContaining('Подпись ключа проверена'), findsOneWidget);
    expect(find.textContaining('Подпись не подтверждена'), findsOneWidget);
  });
  testWidgets('Tor connection failure survives automatic refresh and preserves text', (tester) async {
    tester.view.physicalSize = const Size(1000, 1800);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    await tester.pumpWidget(MaterialApp(home: AppLocale(lang: 'ru', s: const S('ru'), onLangChanged: (_) {}, child: Scaffold(body: ChatSheet(core: FailedSendChatCore(), onClose: () {})))));
    await tester.pump();
    await tester.tap(find.byKey(const Key('chat-advanced'))); await tester.pumpAndSettle();
    await tester.enterText(find.byKey(const Key('chat-peer-manual')), 'tgrin1recipient');
    await tester.enterText(find.byKey(const Key('chat-message')), 'Привет'); await tester.pump();
    await tester.tap(find.text('Отправить'));
    await tester.pump();
    expect(find.textContaining('Не удалось соединиться с собеседником через Tor'), findsOneWidget);
    expect(find.textContaining('отдельно настроить I2P или Nostr'), findsOneWidget);
    await tester.pump(const Duration(seconds: 11));
    await tester.pump();
    expect(find.byKey(const Key('chat-send-error')), findsOneWidget);
    expect(tester.widget<TextField>(find.byKey(const Key('chat-message'))).controller!.text, 'Привет');
  });

}
