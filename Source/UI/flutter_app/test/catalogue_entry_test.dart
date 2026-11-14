import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:grinsight/catalogue_api.dart';
import 'package:grinsight/main.dart';
import 'fake_core.dart';

class CatalogueCore extends FakeWalletCore implements CatalogueApi {
  @override
  Future<Map<String, dynamic>> catalogueOwnCode() async => {};
  @override
  Future<Map<String, dynamic>> catalogueSearch(String name) async => {'results': []};
  @override
  Future<void> catalogueAdd(Map<String, dynamic> profile, String name, {required bool identityChecked}) async {}
  @override
  Future<Map<String, dynamic>> cataloguePublish(String name, {required bool revoked, required bool consentPublic}) async => {};
}

void main() {
  testWidgets('open contact directory from the address book', (tester) async {
    tester.view.physicalSize = const Size(1180, 1200);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    await tester.pumpWidget(GrinSightApp(core: CatalogueCore(), initialScreen: 'wallet'));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('open-contact-catalogue')));
    await tester.pumpAndSettle();
    expect(find.text('Найти контакт'), findsOneWidget);
  });

  testWidgets('open contact directory from the mobile messenger', (tester) async {
    tester.view.physicalSize = const Size(360, 900);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    await tester.pumpWidget(GrinSightApp(core: CatalogueCore(), initialScreen: 'wallet'));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('mobile-tor-status')));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('open-contact-catalogue')));
    await tester.pumpAndSettle();
    expect(find.text('Найти контакт'), findsOneWidget);
  });
}
