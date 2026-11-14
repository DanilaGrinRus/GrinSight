import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:grinsight/l10n.dart';
import 'package:grinsight/messenger.dart';
import 'fake_core.dart';

class StatusCore extends FakeWalletCore {
  String? error;
  @override
  Future<Map<String, dynamic>> chatStatus() async => {'last_error': error, 'phase': 'ready'};
}

void main() {
  testWidgets('history startup failure displays safe clear notice', (tester) async {
    final core=StatusCore()..error='message_history_unavailable';
    await tester.pumpWidget(AppLocale(lang:'ru',s:const S('ru'),onLangChanged:(_){},
      child:MaterialApp(home:Scaffold(body:MessengerNetworkNotice(core:core)))));
    await tester.pump();
    expect(find.textContaining('История переписки недоступна или повреждена'), findsOneWidget);
    expect(find.textContaining('message_history_unavailable'), findsNothing);
  });

  testWidgets('last error survives a successful poll, hides secrets and can be dismissed', (tester) async {
    final core=StatusCore()..error='history write for secret-token-and-address failed: disk error';
    await tester.pumpWidget(AppLocale(lang:'ru',s:const S('ru'),onLangChanged:(_){},
      child:MaterialApp(home:Scaffold(body:MessengerNetworkNotice(core:core)))));
    await tester.pump();
    expect(find.textContaining('Последняя ошибка:'), findsOneWidget);
    expect(find.textContaining('историю'), findsOneWidget);
    expect(find.textContaining('secret-token-and-address'), findsNothing);
    core.error=null;
    await tester.pump(const Duration(seconds: 10)); await tester.pump();
    expect(find.byKey(const Key('messenger-last-error')), findsOneWidget);
    await tester.tap(find.byKey(const Key('messenger-error-dismiss'))); await tester.pump();
    expect(find.byKey(const Key('messenger-last-error')), findsNothing);
    core.error='payment message storage full; no payment request was deleted';
    await tester.pump(const Duration(seconds: 10)); await tester.pump();
    expect(find.textContaining('Хранилище входящих платежей заполнено'), findsOneWidget);
  });

  testWidgets('text quota has a clear message without raw details', (tester) async {
    final core=StatusCore()..error='text history full; payment message reserve remains available';
    await tester.pumpWidget(AppLocale(lang:'en',s:const S('en'),onLangChanged:(_){},
      child:MaterialApp(home:Scaffold(body:MessengerNetworkNotice(core:core)))));
    await tester.pump();
    expect(find.textContaining('Last error:'), findsOneWidget);
    expect(find.textContaining('Conversation storage is full'), findsOneWidget);
  });
  testWidgets('full Nostr receive page is reported without raw payload', (tester) async {
    final core=StatusCore()..error='Nostr receive page is full; delivery may be incomplete';
    await tester.pumpWidget(AppLocale(lang:'ru',s:const S('ru'),onLangChanged:(_){},
      child:MaterialApp(home:Scaffold(body:MessengerNetworkNotice(core:core)))));
    await tester.pump();
    expect(find.textContaining('некоторые входящие могут быть не получены'), findsOneWidget);
  });

  testWidgets('dismissed error reappears after a clear status and recurrence', (tester) async {
    const err='fetch: network unavailable';
    final core=StatusCore()..error=err;
    await tester.pumpWidget(AppLocale(lang:'ru',s:const S('ru'),onLangChanged:(_){},
      child:MaterialApp(home:Scaffold(body:MessengerNetworkNotice(core:core)))));
    await tester.pump();
    await tester.tap(find.byKey(const Key('messenger-error-dismiss'))); await tester.pump();
    await tester.pump(const Duration(seconds:10)); await tester.pump();
    expect(find.byKey(const Key('messenger-last-error')),findsNothing);
    core.error=null;
    await tester.pump(const Duration(seconds:10)); await tester.pump();
    core.error=err;
    await tester.pump(const Duration(seconds:10)); await tester.pump();
    expect(find.byKey(const Key('messenger-last-error')),findsOneWidget);
  });

}
