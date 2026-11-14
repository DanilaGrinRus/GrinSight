import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:grinsight/main.dart';
import 'fake_core.dart';

class ContactCore extends FakeWalletCore {
  String? storedAddress;
  String? storedName;
  bool fail = false;
  @override
  Future<void> addContact(String address, String name) async {
    if (fail) throw StateError('synthetic address book unavailable');
    storedAddress = address;
    storedName = name;
  }
}

void main() {
  testWidgets('add contact from the address book requires name and address', (tester) async {
    tester.view.physicalSize = const Size(1180, 1200);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    final core = ContactCore();
    await tester.pumpWidget(GrinSightApp(core: core, initialScreen: 'wallet'));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('add-wallet-contact')));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('contact-save')));
    await tester.pumpAndSettle();
    expect(find.text('Укажите имя и адрес кошелька.'), findsOneWidget);
    expect(core.storedAddress, isNull);
    await tester.enterText(find.byKey(const Key('contact-name')), 'Alice');
    await tester.enterText(find.byKey(const Key('contact-wallet-address')), 'tgrin1test');
    await tester.tap(find.byKey(const Key('contact-save')));
    await tester.pumpAndSettle();
    expect(core.storedAddress, 'tgrin1test');
    expect(core.storedName, 'Alice');
  });

  testWidgets('backend failure keeps the contact dialog open', (tester) async {
    tester.view.physicalSize = const Size(1180, 1200);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    final core = ContactCore()..fail = true;
    await tester.pumpWidget(GrinSightApp(core: core, initialScreen: 'wallet'));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('add-wallet-contact')));
    await tester.pumpAndSettle();
    await tester.enterText(find.byKey(const Key('contact-name')), 'Alice');
    await tester.enterText(find.byKey(const Key('contact-wallet-address')), 'tgrin1test');
    await tester.tap(find.byKey(const Key('contact-save')));
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('contact-wallet-address')), findsOneWidget);
    expect(core.storedAddress, isNull);
  });
}
