import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter/services.dart';
import 'package:grinsight/quarantine_events.dart';
import 'fake_core.dart';
class QCore extends FakeWalletCore {
  bool deleted=false; bool? corruptConfirmed; bool cleaned=false; bool good=false;
  @override Future<Map<String,dynamic>> chatQuarantineList() async => {'items':[{'id':'11111111-2222-4333-8444-555555555555','digest':'a'*64,'kind':good?'envelope':'unknown','corrupt':!good}]};
  @override Future<Map<String,dynamic>> chatQuarantineExport(String id,String digest) async => {'envelope':'encrypted-synthetic-envelope'};
  @override Future<void> chatQuarantineDiscard(String id,String digest,bool corrupt) async {deleted=true;corruptConfirmed=corrupt;}
  @override Future<void> chatQuarantineCleanup() async {cleaned=true;}
}
class InvalidCore extends QCore {
 String? token;
 @override Future<Map<String,dynamic>> chatQuarantineList() async => {'items':[{'id':'','digest':'','name_token':'b'*64,'kind':'invalid_name','corrupt':true}]};
 @override Future<void> chatQuarantineInvalidDiscard(String value) async {token=value;}
}
void main(){
 testWidgets('corrupt delete and temp cleanup both require confirmation',(t) async {
  final core=QCore();await t.pumpWidget(MaterialApp(home: Scaffold(body:QuarantineEventsDialog(core:core,english:true))));await t.pumpAndSettle();
  expect(find.text('Damaged'),findsOneWidget);await t.tap(find.byKey(const Key('quarantine-delete-0')));await t.pumpAndSettle();expect(core.deleted,false);
  await t.tap(find.byKey(const Key('quarantine-confirm')));await t.pumpAndSettle();expect(core.deleted,true);expect(core.corruptConfirmed,true);
  await t.tap(find.byKey(const Key('quarantine-cleanup')));await t.pumpAndSettle();expect(core.cleaned,false);
  await t.tap(find.byKey(const Key('quarantine-confirm')));await t.pumpAndSettle();expect(core.cleaned,true);
 });
 testWidgets('copies only the explicitly selected encrypted envelope',(t) async {
  String? copied;
  TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger.setMockMethodCallHandler(SystemChannels.platform, (call) async { if (call.method=='Clipboard.setData') { copied=(call.arguments as Map)['text'] as String; return null; } return null; });
  final core=QCore()..good=true;await t.pumpWidget(MaterialApp(home: Scaffold(body:QuarantineEventsDialog(core:core,english:true))));await t.pumpAndSettle();
  await t.tap(find.byKey(const Key('quarantine-copy-0')));await t.pumpAndSettle();
  expect(copied,'encrypted-synthetic-envelope');expect(find.textContaining('Encrypted envelope copied'),findsOneWidget);
 });
 testWidgets('invalid name uses opaque token for confirmed deletion',(t) async {
  final core=InvalidCore();await t.pumpWidget(MaterialApp(home: Scaffold(body:QuarantineEventsDialog(core:core,english:true))));await t.pumpAndSettle();
  await t.tap(find.byKey(const Key('quarantine-delete-0')));await t.pumpAndSettle();expect(core.token,null);
  await t.tap(find.byKey(const Key('quarantine-confirm')));await t.pumpAndSettle();expect(core.token,'b'*64);
 });
}
