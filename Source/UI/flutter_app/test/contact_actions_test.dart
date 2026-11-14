import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:grinsight/l10n.dart';
import 'package:grinsight/sheets.dart';
import 'backup_payment_test.dart' show BackupCore;

void main() {
  testWidgets('only the contact signed peer is preselected; changing the wallet address clears it', (tester) async {
    tester.view.physicalSize = const Size(1100, 1600);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    final core = BackupCore();
    final status = await core.status();
    const wallet = 'tgrin1aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
    await tester.pumpWidget(AppLocale(lang:'ru',s:const S('ru'),onLangChanged:(_){},child:MaterialApp(home:Scaffold(body:SendFlowSheet(onClose:(){},core:core,status:status,delivery:'grinmail',initialTo:wallet,initialBackupPeer:'tgrinmsg1testcontact')))));
    await tester.pumpAndSettle();
    final peer = find.byKey(const Key('payment-backup-peer'));
    expect(tester.state<FormFieldState<String>>(peer).value, 'tgrinmsg1testcontact');
    await tester.enterText(find.byKey(const Key('send-to')), 'tgrin1bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb');
    await tester.pumpAndSettle();
    expect(tester.state<FormFieldState<String>>(peer).value, isNull);
  });

  testWidgets('an unrecognised messenger peer is never preselected', (tester) async {
    final core = BackupCore();
    final status = await core.status();
    await tester.pumpWidget(AppLocale(lang:'ru',s:const S('ru'),onLangChanged:(_){},child:MaterialApp(home:Scaffold(body:SendFlowSheet(onClose:(){},core:core,status:status,delivery:'grinmail',initialTo:'tgrin1test',initialBackupPeer:'wrong-peer')))));
    await tester.pumpAndSettle();
    expect(tester.state<FormFieldState<String>>(find.byKey(const Key('payment-backup-peer'))).value, isNull);
  });
}
