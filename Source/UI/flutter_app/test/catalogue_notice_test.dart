import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:grinsight/catalogue_api.dart';
import 'package:grinsight/catalogue_sheet.dart';
import 'package:grinsight/l10n.dart';
import 'fake_core.dart';
class TestCore extends FakeWalletCore implements CatalogueApi {
  bool? revoked;
  @override Future<Map<String,dynamic>> catalogueOwnCode() async => {};
  @override Future<Map<String,dynamic>> catalogueSearch(String name) async => {'results':[]};
  @override Future<void> catalogueAdd(Map<String,dynamic> profile,String name,{required bool identityChecked}) async {}
  @override Future<Map<String,dynamic>> cataloguePublish(String name,{required bool revoked,required bool consentPublic}) async {this.revoked=revoked;return {'comparison_code':'1234-abcd-5678'};}
}
void main() {
 testWidgets('revocation reports server acceptance, not assured disappearance', (tester) async {
  tester.view.physicalSize=const Size(1100,1600);tester.view.devicePixelRatio=1;
  addTearDown(tester.view.resetPhysicalSize);addTearDown(tester.view.resetDevicePixelRatio);
  final core=TestCore();
  await tester.pumpWidget(AppLocale(lang:'ru',s:const S('ru'),onLangChanged:(_){},child:MaterialApp(home:Scaffold(body:Builder(builder:(c)=>TextButton(onPressed:()=>showContactCatalogue(c,core),child:const Text('Open')))))));
  await tester.tap(find.text('Open'));await tester.pumpAndSettle();
  await tester.enterText(find.byKey(const Key('catalogue-query')), 'alice');
  await tester.tap(find.text('Дополнительно'));await tester.pumpAndSettle();
  await tester.ensureVisible(find.byType(CheckboxListTile));await tester.tap(find.byType(CheckboxListTile));await tester.pumpAndSettle();
  await tester.ensureVisible(find.text('Отозвать'));await tester.tap(find.text('Отозвать'));await tester.pumpAndSettle();
  expect(core.revoked,true);
  expect(find.textContaining('Сервер принял запрос на отзыв, но профиль может оставаться доступным'),findsOneWidget);
 });
}
