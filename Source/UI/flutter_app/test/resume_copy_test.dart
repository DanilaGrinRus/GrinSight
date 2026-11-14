import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:grinsight/l10n.dart';
import 'package:grinsight/sheets.dart';
import 'fake_core.dart';

class CopyCore extends FakeWalletCore {
  String? requested;
  @override
  Future<String> slatepack(String txId) async {
    requested = txId;
    return 'BEGINSLATEPACK. SAVED .ENDSLATEPACK.';
  }
}

void main() {
  testWidgets('copy existing S1 from resumed payment without sending', (tester) async {
    String? clipboard;
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger.setMockMethodCallHandler(SystemChannels.platform, (call) async {
      if (call.method == 'Clipboard.setData') clipboard = (call.arguments as Map)['text'] as String?;
      return null;
    });
    addTearDown(() => TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger.setMockMethodCallHandler(SystemChannels.platform, null));
    final core = CopyCore();
    await tester.pumpWidget(MaterialApp(home: AppLocale(lang: 'ru', s: const S('ru'), onLangChanged: (_) {}, child: Scaffold(body: ResumeSendSheet(core: core, txId: 'existing', network: 'floonet', onClose: () {})))));
    await tester.tap(find.byKey(const Key('resume-copy-slatepack')));
    await tester.pumpAndSettle();
    expect(core.requested, 'existing');
    expect(clipboard, 'BEGINSLATEPACK. SAVED .ENDSLATEPACK.');
    expect(core.sendCalls, 0);
  });
}
