import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:grinsight/deferred_events.dart';
import 'fake_core.dart';

class DeferredCore extends FakeWalletCore {
  int retries = 0;
  final deleted = <String>[];
  final routes = <String>[];
  String activeRoute = 'b' * 64;
  bool fail = false;
  bool corrupt = false;
  bool more = false;
  @override
  Future<Map<String, dynamic>> chatDeferredList() async {
    if (fail) throw StateError('private token should not be displayed');
    return {'items': [{'id': 'a' * 64, 'received_at': corrupt ? 0 : 1, 'route': 'b' * 64, 'corrupt': corrupt}], 'limit': 1000, 'more': more};
  }
  @override
  Future<void> chatDeferredRetry(String route) async { routes.add(route); if (route != activeRoute) throw StateError('route changed'); retries++; }
  @override
  Future<void> chatDeferredDiscard(String id, String route) async { routes.add(route); deleted.add('$route:$id'); }
}

void main() {
  testWidgets('retry refreshes, deletion requires explicit confirmation', (tester) async {
    final core = DeferredCore();
    await tester.pumpWidget(MaterialApp(home: Scaffold(body: DeferredEventsDialog(core: core, english: true))));
    await tester.pumpAndSettle();
    expect(find.text('a' * 64), findsOneWidget);
    await tester.tap(find.byKey(const Key('deferred-retry')));
    await tester.pumpAndSettle();
    expect(core.retries, 1);
    expect(find.textContaining('delivery is not guaranteed'), findsOneWidget);
    await tester.tap(find.byKey(const Key('deferred-delete-0')));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Cancel'));
    await tester.pumpAndSettle();
    expect(core.deleted, isEmpty);
    await tester.tap(find.byKey(const Key('deferred-delete-0')));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('deferred-confirm-delete')));
    await tester.pumpAndSettle();
    expect(core.deleted, ['${'b' * 64}:${'a' * 64}']);
    expect(core.routes, ['b' * 64, 'b' * 64]);
  });
  testWidgets('errors never expose raw exception', (tester) async {
    final core = DeferredCore()..fail = true;
    await tester.pumpWidget(MaterialApp(home: Scaffold(body: DeferredEventsDialog(core: core, english: true))));
    await tester.pumpAndSettle();
    expect(find.textContaining('Could not load'), findsOneWidget);
    expect(find.textContaining('private token'), findsNothing);
  });
  testWidgets('corrupt records are labelled and require a specific warning', (tester) async {
    final core = DeferredCore()..corrupt = true;
    await tester.pumpWidget(MaterialApp(home: Scaffold(body: DeferredEventsDialog(core: core, english: true))));
    await tester.pumpAndSettle();
    expect(find.text('Corrupt record; time unknown'), findsOneWidget);
    await tester.tap(find.byKey(const Key('deferred-delete-0')));
    await tester.pumpAndSettle();
    expect(find.textContaining('corrupt and cannot be read'), findsOneWidget);
    expect(core.deleted, isEmpty);
  });
  testWidgets('route change after listing cannot delete a different route', (tester) async {
    final core = DeferredCore();
    await tester.pumpWidget(MaterialApp(home: Scaffold(body: DeferredEventsDialog(core: core, english: true))));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('deferred-delete-0')));
    await tester.pumpAndSettle();
    core.activeRoute = 'c' * 64;
    await tester.tap(find.byKey(const Key('deferred-confirm-delete')));
    await tester.pumpAndSettle();
    expect(core.deleted, ['${'b' * 64}:${'a' * 64}']);
    expect(core.routes, ['b' * 64]);
  });
  testWidgets('indicates when more records are available', (tester) async {
    final core = DeferredCore()..more = true;
    await tester.pumpWidget(MaterialApp(home: Scaffold(body: DeferredEventsDialog(core: core, english: true))));
    await tester.pumpAndSettle();
    expect(find.textContaining('more records available'), findsOneWidget);
  });
}
