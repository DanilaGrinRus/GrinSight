import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:grinsight/main.dart';
import 'package:grinsight/backend/grinsight_service.dart';
import 'package:grinsight/backend/real_core.dart';
import 'fake_core.dart';

class UnreadablePolicyCore extends FakeWalletCore {
  @override
  Future<String?> autoAcceptPolicy() async => throw Exception('read failed');
}

class FailedWritePolicyCore extends FakeWalletCore {
  @override
  Future<void> autoAccept(String mode) async => throw Exception('write failed');
}

class BookService implements GrinSightService {
  BookService(this.policy);
  final Object? policy;
  @override
  Future<Map<String, dynamic>> contacts() async => <String, dynamic>{'auto_accept': policy};
  @override
  dynamic noSuchMethod(Invocation invocation) => super.noSuchMethod(invocation);
}

class EmptyNameBook extends BookService {
  EmptyNameBook() : super('ask_all');
  @override
  Future<Map<String, dynamic>> contacts() async => <String, dynamic>{'contacts': <Map<String, dynamic>>[
    <String, dynamic>{'id': 'tgrin1example', 'name': ''},
  ]};
}

void main() {
  setUp(() {});
  test('saved contact without a name uses its address', () async {
    final contacts = await RealWalletCore(EmptyNameBook()).contacts();
    expect(contacts.single.name, 'tgrin1example');
  });
  test('real core reads valid saved modes and rejects unknown values', () async {
    for (final mode in <String>['ask_all', 'ask', 'contacts', 'all', 'off']) {
      expect(await RealWalletCore(BookService(mode)).autoAcceptPolicy(), mode);
    }
    expect(await RealWalletCore(BookService('unexpected')).autoAcceptPolicy(), isNull);
    expect(await RealWalletCore(BookService(null)).autoAcceptPolicy(), isNull);
  });
  Future<void> launch(WidgetTester tester, FakeWalletCore core) async {
    tester.view.physicalSize = const Size(1180, 1100);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    await tester.pumpWidget(GrinSightApp(core: core, initialScreen: 'wallet'));
    await tester.pumpAndSettle();
    // Автоприём на главном экране спрятан за строкой «Доставка · Настроить».
    await tester.tap(find.byKey(const Key('messenger-delivery-toggle')));
    await tester.pumpAndSettle();
  }

  testWidgets('saved all policy is shown when opening wallet', (tester) async {
    final core = FakeWalletCore()..savedAutoAccept = 'all';
    await launch(tester, core);
    expect(find.text('все'), findsOneWidget);
    expect(find.text('Спрашивать о новых'), findsNothing);
  });

  testWidgets('failed policy read is unknown, not assumed ask', (tester) async {
    await launch(tester, UnreadablePolicyCore());
    expect(find.text('Неизвестно'), findsOneWidget);
    expect(find.text('Спрашивать о новых'), findsNothing);
  });

  testWidgets('failed policy change is shown as unknown', (tester) async {
    await launch(tester, FailedWritePolicyCore());
    await tester.tap(find.text('спрашивать о новых'));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Включить').last);
    await tester.pumpAndSettle();
    expect(find.text('Неизвестно'), findsOneWidget);
  });
  testWidgets('enable selects ask_all; disable selects off', (tester) async {
    final core = FakeWalletCore()..savedAutoAccept = 'off';
    await launch(tester, core);
    await tester.tap(find.text('Выключить'));
    await tester.pumpAndSettle();
    expect(find.text('Включить'), findsWidgets);
    expect(find.text('Выключить'), findsWidgets);
    await tester.tap(find.text('Включить').last);
    await tester.pumpAndSettle();
    expect(core.savedAutoAccept, 'ask_all');
    await tester.tap(find.text('Включить').last);
    await tester.pumpAndSettle();
    await tester.tap(find.text('Выключить').last);
    await tester.pumpAndSettle();
    expect(core.savedAutoAccept, 'off');
  });

}
