import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:grinsight/l10n.dart';
import 'package:grinsight/messenger.dart';
import 'package:grinsight/sheets.dart';

void main() {
  for (final checked in [false, true]) {
    testWidgets('contact code comparison status $checked', (tester) async {
      await tester.pumpWidget(AppLocale(lang:'ru',s:const S('ru'),onLangChanged:(_){},child:MaterialApp(home:Scaffold(body:ContactFeedSheet(onClose:(){},contact:UContact(name:'Alice',fullAddress:'tgrin1test',verified:checked))))));
      await tester.pumpAndSettle();
      expect(find.text(checked ? 'Код сверён пользователем' : 'Код не сверён'), findsOneWidget);
      expect(find.text('Личность подтверждена'), findsNothing);
    });
  }
}
