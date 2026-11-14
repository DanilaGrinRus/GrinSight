import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:grinsight/chat.dart';
import 'package:grinsight/l10n.dart';
import 'fake_core.dart';
class NostrWarningCore extends FakeWalletCore {
  @override
  Future<Map<String, dynamic>> chatInfo() async => {'ready':true,'address':'test','mode':'nostr_direct'};
}
void main() {
  testWidgets('Nostr chat warns server acceptance is not recipient receipt', (tester) async {
    tester.view.physicalSize=const Size(1100,1800);tester.view.devicePixelRatio=1;
    addTearDown(tester.view.resetPhysicalSize);addTearDown(tester.view.resetDevicePixelRatio);
    await tester.pumpWidget(AppLocale(lang:'en',s:const S('en'),onLangChanged:(_){},child:MaterialApp(home:Scaffold(body:ChatSheet(core:NostrWarningCore(),onClose:(){})))));
    await tester.pump();await tester.pump();
    expect(find.byKey(const Key('chat-nostr-server-trust')),findsOneWidget);
    expect(find.textContaining('Server acceptance does not confirm receipt'),findsOneWidget);
  });
}
