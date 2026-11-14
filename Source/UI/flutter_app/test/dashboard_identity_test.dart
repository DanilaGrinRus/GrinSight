import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:grinsight/catalogue_api.dart';
import 'package:grinsight/main.dart';
import 'fake_core.dart';

class IdentityCore extends FakeWalletCore implements CatalogueIdentityApi {
  IdentityCore({this.failIdentity = false});
  final bool failIdentity;
  @override
  Future<Map<String, dynamic>> nostrSettings() async => {'mode':'direct','url':'wss://relay.example'};
  @override
  Future<Map<String, dynamic>> catalogueIdentity() async {
    if (failIdentity) throw Exception('backend unavailable');
    return {'search_phrase': 'bala-deme-fola-gina-hora-juna', 'comparison_code': '1234-5678-9012', 'publication': 'published'};
  }
}

class PendingIdentityCore extends IdentityCore {
  int calls = 0;
  @override
  Future<Map<String, dynamic>> catalogueIdentity() async {
    calls++;
    return {'search_phrase':'ant-ash-bay-bee-cafe-cold', 'publication': calls == 1 ? 'pending' : 'published'};
  }
}

void main() {
  for (final width in [390.0, 1180.0]) {
    testWidgets('dashboard exposes public address and phrase at width $width', (tester) async {
      tester.view.physicalSize = Size(width, 1000);
      tester.view.devicePixelRatio = 1;
      addTearDown(tester.view.resetPhysicalSize);
      addTearDown(tester.view.resetDevicePixelRatio);
      String? copied;
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger.setMockMethodCallHandler(SystemChannels.platform, (call) async {
        if (call.method == 'Clipboard.setData') copied = (call.arguments as Map)['text'] as String?;
        return null;
      });
      addTearDown(() => TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger.setMockMethodCallHandler(SystemChannels.platform, null));
      await tester.pumpWidget(GrinSightApp(core: IdentityCore(), initialScreen: 'wallet'));
      await tester.pumpAndSettle();
      expect(find.byKey(const Key('dashboard-wallet-address')), findsOneWidget);
      expect(find.byKey(const Key('dashboard-contact-phrase')), findsOneWidget);
      expect(find.text('bala-deme-fola-gina-hora-juna'), findsOneWidget);
      expect(find.text('1234-5678-9012'), findsNothing);
      expect(find.byKey(const Key('dashboard-ip-notice')), findsOneWidget);
      expect(find.byKey(const Key('dashboard-contact-published')), findsOneWidget);
      await tester.tap(find.byKey(const Key('dashboard-contact-phrase')));
      expect(copied, 'bala-deme-fola-gina-hora-juna');
      expect(tester.takeException(), isNull);
    });
  }
  testWidgets('pending publication refreshes and timer stops on widget disposal', (tester) async {
    final core = PendingIdentityCore();
    await tester.pumpWidget(GrinSightApp(core: core, initialScreen: 'wallet'));
    await tester.pumpAndSettle();
    expect(find.text('Публикация контакта ожидается'), findsOneWidget);
    await tester.pump(const Duration(seconds: 15));
    await tester.pump();
    expect(find.byKey(const Key('dashboard-contact-published')), findsOneWidget);
    await tester.pumpWidget(const SizedBox.shrink());
    final last = core.calls;
    await tester.pump(const Duration(seconds: 30));
    expect(core.calls, last);
  });

  testWidgets('unavailable identity does not invent a phrase', (tester) async {
    await tester.pumpWidget(GrinSightApp(core: IdentityCore(failIdentity: true), initialScreen: 'wallet'));
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('dashboard-contact-phrase')), findsNothing);
    expect(find.byKey(const Key('dashboard-contact-status')), findsOneWidget);
  });
}
