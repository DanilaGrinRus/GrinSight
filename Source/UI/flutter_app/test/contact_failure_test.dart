import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:grinsight/core.dart';
import 'package:grinsight/main.dart';
import 'fake_core.dart';

class ContactsCore extends FakeWalletCore {
  bool fail = false;
  @override
  Future<List<ContactInfo>> contacts() async {
    if (fail) throw StateError('address book unavailable');
    return super.contacts();
  }
}

void main() {
  testWidgets('read failure keeps previous contacts and warns they may be stale', (tester) async {
    tester.view.physicalSize = const Size(1180, 1200);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    final core = ContactsCore();
    await tester.pumpWidget(GrinSightApp(core: core, initialScreen: 'wallet'));
    await tester.pumpAndSettle();
    expect(find.text('Carol'), findsOneWidget);
    core.fail = true;
    await tester.tap(find.byKey(const Key('open-contact-catalogue')));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Закрыть'));
    await tester.pumpAndSettle();
    expect(find.text('Carol'), findsOneWidget);
    expect(find.byKey(const Key('contacts-load-error')), findsOneWidget);
  });

  testWidgets('initial read failure does not claim the address book is empty', (tester) async {
    tester.view.physicalSize = const Size(1180, 1200);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    await tester.pumpWidget(GrinSightApp(core: ContactsCore()..fail = true, initialScreen: 'wallet'));
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('contacts-load-error')), findsOneWidget);
    expect(find.text('Контактов пока нет'), findsNothing);
  });
}
