import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:grinsight/l10n.dart';
import 'package:grinsight/sheets.dart';
import 'fake_core.dart';

class NostrCore extends FakeWalletCore {
  String? mode; String? url; String? proxy; bool? consent; bool? expiry; int? historyDays; bool? savedAutoPublish;
  @override
  Future<void> setNostrSettings({required String mode, required String url, required String proxy, required bool consent, required bool expiry, required int historyDays, bool? catalogueAutoPublish}) async {
    this.mode=mode; this.url=url; this.proxy=proxy; this.consent=consent; this.expiry=expiry; this.historyDays=historyDays; savedAutoPublish=catalogueAutoPublish;
  }
}

class PublishedNostrCore extends NostrCore {
  @override
  Future<Map<String, dynamic>> nostrSettings() async => {'mode':'direct', 'url':'wss://relay.example', 'proxy':'', 'expiry':false, 'historyDays':0, 'catalogueAutoPublish':true};
}

void main() {
  testWidgets('direct Nostr saves with a visible IP notice and no checkbox', (tester) async {
    tester.view.physicalSize=const Size(1100,1600); tester.view.devicePixelRatio=1;
    addTearDown(tester.view.resetPhysicalSize); addTearDown(tester.view.resetDevicePixelRatio);
    final core=NostrCore();
    await tester.pumpWidget(AppLocale(lang:'ru',s:const S('ru'),onLangChanged:(_){},child:MaterialApp(home:Scaffold(body:Builder(builder:(context)=>TextButton(key:const Key('nostr-settings-open'),onPressed:()=>showMessagingChannelSettings(context,core),child:const Text('Каналы')))))));
    await tester.pumpAndSettle(); await tester.ensureVisible(find.byKey(const Key('nostr-settings-open')));
    await tester.tap(find.byKey(const Key('nostr-settings-open'))); await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('channel-direct'))); await tester.pumpAndSettle();
    expect(tester.widget<TextField>(find.byKey(const Key('nostr-url'))).controller!.text, 'wss://relay.primal.net');
    expect(find.byKey(const Key('nostr-server-trust')), findsOneWidget);
    await tester.enterText(find.byKey(const Key('nostr-url')), 'wss://relay.example');
    expect(find.byKey(const Key('nostr-ip-notice')), findsOneWidget);
    expect(find.byKey(const Key('nostr-consent')), findsNothing);
    expect(find.text('Запрашивать истечение на сервере через 15 минут'), findsOneWidget);
    await tester.ensureVisible(find.byKey(const Key('nostr-expiry')));
    await tester.tap(find.byKey(const Key('nostr-expiry'))); await tester.pumpAndSettle();
    await tester.ensureVisible(find.byKey(const Key('history-retention')));
    await tester.tap(find.byKey(const Key('history-retention'))); await tester.pumpAndSettle();
    await tester.tap(find.text('Удалять через 30 дней').last); await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('nostr-save'))); await tester.pumpAndSettle();
    expect(core.mode,'direct'); expect(core.url,'wss://relay.example'); expect(core.consent,isTrue); expect(core.expiry,isTrue); expect(core.historyDays,30);
  });

  testWidgets('publication can be disabled without changing direct route', (tester) async {
    tester.view.physicalSize=const Size(1100,1600); tester.view.devicePixelRatio=1;
    addTearDown(tester.view.resetPhysicalSize); addTearDown(tester.view.resetDevicePixelRatio);
    final core=PublishedNostrCore();
    await tester.pumpWidget(AppLocale(lang:'ru',s:const S('ru'),onLangChanged:(_){},child:MaterialApp(home:Scaffold(body:Builder(builder:(context)=>TextButton(key:const Key('nostr-settings-open'),onPressed:()=>showMessagingChannelSettings(context,core),child:const Text('Каналы')))))));
    await tester.pumpAndSettle(); await tester.ensureVisible(find.byKey(const Key('nostr-settings-open')));
    await tester.tap(find.byKey(const Key('nostr-settings-open'))); await tester.pumpAndSettle();
    await tester.ensureVisible(find.byKey(const Key('catalogue-auto-publish')));
    expect(find.textContaining('серверы могут сохранить ранее опубликованное'), findsOneWidget);
    await tester.tap(find.byKey(const Key('catalogue-auto-publish'))); await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('nostr-save'))); await tester.pumpAndSettle();
    expect(core.savedAutoPublish, isFalse); expect(core.mode,'direct'); expect(core.url,'wss://relay.example');
  });

  testWidgets('direct I2P accepts a local SAM endpoint without a Nostr server', (tester) async {
    tester.view.physicalSize=const Size(1100,1600); tester.view.devicePixelRatio=1;
    addTearDown(tester.view.resetPhysicalSize); addTearDown(tester.view.resetDevicePixelRatio);
    final core=NostrCore();
    await tester.pumpWidget(AppLocale(lang:'ru',s:const S('ru'),onLangChanged:(_){},child:MaterialApp(home:Scaffold(body:Builder(builder:(context)=>TextButton(key:const Key('nostr-settings-open'),onPressed:()=>showMessagingChannelSettings(context,core),child:const Text('Каналы')))))));
    await tester.pumpAndSettle(); await tester.ensureVisible(find.byKey(const Key('nostr-settings-open')));
    await tester.tap(find.byKey(const Key('nostr-settings-open'))); await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('channel-i2p_direct'))); await tester.pumpAndSettle();
    expect(find.byKey(const Key('nostr-url')),findsNothing);
    await tester.enterText(find.byKey(const Key('nostr-proxy')),'127.0.0.1:7656');
    await tester.tap(find.byKey(const Key('nostr-save'))); await tester.pumpAndSettle();
    expect(core.mode,'i2p_direct');expect(core.proxy,'127.0.0.1:7656');expect(core.consent,isFalse);
  });
}
