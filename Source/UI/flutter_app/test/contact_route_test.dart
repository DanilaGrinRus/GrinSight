import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:grinsight/core.dart';
import 'package:grinsight/main.dart';
import 'fake_core.dart';

class RouteCore extends FakeWalletCore {
  bool available = true;
  @override
  Future<List<ContactInfo>> contacts() async => const [ContactInfo(id:'tgrin1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', name:'Alice', messenger:'tgrinmsg1testcontact')];
  @override
  Future<Map<String, dynamic>> backupPaymentContacts() async => available
      ? {'mode':'nostr_direct','route':'current-route','contacts':[{'name':'Alice','address':'tgrinmsg1testcontact'}]}
      : {'mode':'nostr_direct','route':'current-route','contacts':[]};
}

void main() {
  for (final available in [true, false]) {
    testWidgets('contact payment uses only current bound GlauxMail route: $available', (tester) async {
      tester.view.physicalSize=const Size(1180,1200); tester.view.devicePixelRatio=1;
      addTearDown(tester.view.resetPhysicalSize); addTearDown(tester.view.resetDevicePixelRatio);
      final core=RouteCore()..available=available;
      await tester.pumpWidget(GrinSightApp(core:core,initialScreen:'wallet'));
      await tester.pumpAndSettle();
      await tester.tap(find.text('Alice').first);
      await tester.pumpAndSettle();
      await tester.tap(find.byKey(const Key('contact-send')));
      await tester.pumpAndSettle();
      if (available) {
        final peer=find.byKey(const Key('payment-backup-peer'));
        expect(peer,findsOneWidget);
        expect(tester.state<FormFieldState<String>>(peer).value,'tgrinmsg1testcontact');
        expect(find.textContaining('Nostr напрямую'),findsWidgets);
      } else {
        expect(find.byKey(const Key('payment-backup-peer')),findsNothing);
        expect(find.textContaining('Контакт недоступен в выбранном канале'),findsOneWidget);
      }
    });
  }
}
