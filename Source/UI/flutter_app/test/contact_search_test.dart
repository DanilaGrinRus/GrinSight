import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:grinsight/main.dart';
import 'fake_core.dart';

void main() {
  testWidgets('contact search matches name and address', (tester) async {
    tester.view.physicalSize = const Size(1180, 1100);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    await tester.pumpWidget(GrinSightApp(core: FakeWalletCore(), initialScreen: 'wallet'));
    await tester.pumpAndSettle();
    final search = find.widgetWithText(TextField, 'Поиск по имени');
    expect(search, findsOneWidget);
    await tester.enterText(search, 'CAR');
    await tester.pumpAndSettle();
    expect(find.text('Carol'), findsOneWidget);
    await tester.enterText(search, 'grin1car');
    await tester.pumpAndSettle();
    expect(find.text('Carol'), findsOneWidget);
    await tester.enterText(search, 'unmatched');
    await tester.pumpAndSettle();
    expect(find.text('Carol'), findsNothing);
  });
}
