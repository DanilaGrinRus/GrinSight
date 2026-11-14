import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:grinsight/l10n.dart';
import 'package:grinsight/sheets.dart';
import 'fake_core.dart';

class BridgeCore extends FakeWalletCore {
  String? mode;
  String? line;
  String? binary;
  @override
  Future<void> setTorBridgeSettings({required String mode, required String line, required String binary}) async {
    this.mode = mode; this.line = line; this.binary = binary;
  }
}

void main() {
  testWidgets('desktop bridge form saves selected mode and inputs', (tester) async {
    debugDefaultTargetPlatformOverride = TargetPlatform.windows;
    addTearDown(() => debugDefaultTargetPlatformOverride = null);
    tester.view.physicalSize = const Size(1100, 1600);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    final core = BridgeCore();
    await tester.pumpWidget(AppLocale(lang: 'ru', s: const S('ru'), onLangChanged: (_) {}, child: MaterialApp(home: Scaffold(body: Builder(builder: (context) => TextButton(key: const Key('tor-bridge-open'), onPressed: () => showTorBridgeSettings(context, core), child: const Text('Tor')))))));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('tor-bridge-open')));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('tor-bridge-mode')));
    await tester.pumpAndSettle();
    await tester.tap(find.text('obfs4').last);
    await tester.pumpAndSettle();
    await tester.enterText(find.byKey(const Key('tor-bridge-line')), 'obfs4 example:443 test');
    expect(tester.widget<TextField>(find.byKey(const Key('tor-bridge-line'))).controller!.text, startsWith('obfs4 '));
    await tester.tap(find.byKey(const Key('tor-bridge-advanced')));
    await tester.pumpAndSettle();
    expect(tester.widget<TextField>(find.byKey(const Key('tor-bridge-binary'))).controller!.text, 'bundled');
    await tester.enterText(find.byKey(const Key('tor-bridge-binary')), r'C:\test\obfs4proxy.exe');
    await tester.tap(find.byKey(const Key('tor-bridge-save')));
    await tester.pumpAndSettle();
    expect(core.mode, 'obfs4');
    expect(core.line, 'obfs4 example:443 test');
    expect(core.binary, r'C:\test\obfs4proxy.exe');
    debugDefaultTargetPlatformOverride = null;
  });
  testWidgets('Snowflake uses the bundled program and a default bridge without manual input', (tester) async {
    debugDefaultTargetPlatformOverride = TargetPlatform.windows;
    addTearDown(() => debugDefaultTargetPlatformOverride = null);
    tester.view.physicalSize = const Size(1100, 1600);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    final core = BridgeCore();
    await tester.pumpWidget(AppLocale(lang: 'ru', s: const S('ru'), onLangChanged: (_) {}, child: MaterialApp(home: Scaffold(body: Builder(builder: (context) => TextButton(key: const Key('tor-bridge-open'), onPressed: () => showTorBridgeSettings(context, core), child: const Text('Tor')))))));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('tor-bridge-open')));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('tor-bridge-mode')));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Snowflake').last);
    await tester.pumpAndSettle();
    expect(tester.widget<TextField>(find.byKey(const Key('tor-bridge-line'))).controller!.text, startsWith('snowflake '));
    await tester.tap(find.byKey(const Key('tor-bridge-save')));
    await tester.pumpAndSettle();
    expect(core.mode, 'snowflake');
    expect(core.binary, 'bundled');
    expect(core.line, startsWith('snowflake '));
    debugDefaultTargetPlatformOverride = null;
  });

}
