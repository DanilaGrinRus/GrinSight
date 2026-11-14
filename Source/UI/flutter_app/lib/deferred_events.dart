import 'package:flutter/material.dart';
import 'core.dart';

/// A deliberately metadata-only view of events the daemon could not process.
class DeferredEventsDialog extends StatefulWidget {
  const DeferredEventsDialog({super.key, required this.core, required this.english});
  final WalletCore core;
  final bool english;
  @override
  State<DeferredEventsDialog> createState() => _DeferredEventsDialogState();
}

class _DeferredEventsDialogState extends State<DeferredEventsDialog> {
  List<Map<String, dynamic>>? items;
  int limit = 1000;
  bool more = false;
  bool busy = false;
  String? notice;
  String tr(String ru, String en) => widget.english ? en : ru;
  @override
  void initState() { super.initState(); _load(); }

  Future<void> _load({bool retried = false}) async {
    setState(() { busy = true; notice = null; });
    try {
      final data = await widget.core.chatDeferredList();
      final raw = data['items'];
      final max = data['limit'];
      final hasMore = data['more'];
      if (hasMore is! bool) throw const FormatException();
      if (raw is! List || max is! int || max < 1 || max > 1000 || raw.length > max) throw const FormatException();
      final parsed = <Map<String, dynamic>>[];
      for (final item in raw) {
        if (item is! Map || item['id'] is! String || !RegExp(r'^[a-f0-9]{64}$').hasMatch(item['id'] as String) || item['received_at'] is! int || (item['received_at'] as int) < 0 || (item['received_at'] as int) > 253402300799) throw const FormatException();
        if (item['route'] is! String || !RegExp(r'^[a-f0-9]{64}$').hasMatch(item['route'] as String)) throw const FormatException();
        if (item['corrupt'] != null && item['corrupt'] is! bool) throw const FormatException();
        parsed.add({'id': item['id'], 'received_at': item['received_at'], 'route': item['route'], 'corrupt': item['corrupt'] == true});
      }
      if (!mounted) return;
      setState(() { items = parsed; limit = max; more = hasMore; notice = retried ? tr('Повторная проверка выполнена. Список обновлён; доставка не гарантирована.', 'Retry attempted. The list is refreshed; delivery is not guaranteed.') : null; });
    } catch (_) {
      if (!mounted) return;
      setState(() { items = null; notice = tr('Не удалось получить список. Проверьте запуск мессенджера и состояние хранилища.', 'Could not load the list. Check that the messenger is running and its storage is accessible.'); });
    } finally { if (mounted) setState(() => busy = false); }
  }

  Future<void> _retry() async {
    setState(() { busy = true; notice = null; });
    try {
      final routes = items!.map((item) => item['route'] as String).toSet();
      for (final route in routes) { await widget.core.chatDeferredRetry(route); }
      if (!mounted) return;
      await _load(retried: true);
    } catch (_) {
      if (!mounted) return;
      setState(() { busy = false; notice = tr('Не удалось повторить обработку. Проверьте мессенджер и свободное место.', 'Retry failed. Check the messenger and available storage.'); });
    }
  }

  Future<void> _discard(String id, String route, bool corrupt) async {
    final confirmed = await showDialog<bool>(context: context, builder: (context) => AlertDialog(
      title: Text(tr('Удалить безвозвратно?', 'Delete permanently?')),
      content: Text(corrupt ? tr('Запись повреждена и не может быть прочитана. Она может содержать сообщение или платёж. После удаления восстановить её нельзя.', 'This record is corrupt and cannot be read. It may contain a message or payment. It cannot be recovered after deletion.') : tr('Эта запись может содержать сообщение или платёж, иметь неизвестный формат, быть повреждена или просрочена. После удаления восстановить её нельзя.', 'This record may contain a message or payment, use an unknown format, be damaged or expired. It cannot be recovered after deletion.')),
      actions: [TextButton(onPressed: () => Navigator.pop(context, false), child: Text(tr('Отмена', 'Cancel'))), TextButton(key: const Key('deferred-confirm-delete'), onPressed: () => Navigator.pop(context, true), child: Text(tr('Удалить навсегда', 'Delete permanently')))],
    ));
    if (confirmed != true || !mounted) return;
    setState(() { busy = true; notice = null; });
    try {
      await widget.core.chatDeferredDiscard(id, route);
      if (mounted) await _load();
    } catch (_) {
      if (mounted) setState(() { busy = false; notice = tr('Не удалось удалить запись. Обновите список и проверьте хранилище.', 'Could not delete the record. Refresh the list and check storage.'); });
    }
  }

  @override
  Widget build(BuildContext context) => AlertDialog(
    title: Text(tr('Необработанные сообщения', 'Unprocessed messages')),
    content: SizedBox(width: 440, height: 340, child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
      Text(tr('Содержимое скрыто. Записи могут быть повреждены, просрочены или использовать новый формат.', 'Content is hidden. Records may be damaged, expired or use a newer format.')),
      if (items != null) Text('${items!.length} / $limit${more ? tr(' — показаны не все записи', ' — more records available') : ''}'),
      if (notice != null) Text(notice!, key: const Key('deferred-notice')),
      if (busy) const LinearProgressIndicator(),
      Expanded(child: items == null ? const SizedBox.shrink() : items!.isEmpty ? Center(child: Text(tr('Нет записей', 'No records'))) : ListView.builder(itemCount: items!.length, itemBuilder: (context, index) {
        final item = items![index];
        final id = item['id'] as String;
        final when = DateTime.fromMillisecondsSinceEpoch((item['received_at'] as int) * 1000, isUtc: true).toLocal();
        final corrupt = item['corrupt'] == true;
        return ListTile(title: SelectableText(id), subtitle: Text(corrupt ? tr('Запись повреждена; время неизвестно', 'Corrupt record; time unknown') : when.toString()), trailing: IconButton(key: Key('deferred-delete-$index'), tooltip: tr('Удалить', 'Delete'), onPressed: busy ? null : () => _discard(id, item['route'] as String, corrupt), icon: const Icon(Icons.delete_outline)));
      })),
    ])),
    actions: [TextButton(onPressed: busy ? null : () => _load(), child: Text(tr('Обновить', 'Refresh'))), TextButton(key: const Key('deferred-retry'), onPressed: busy || items == null || items!.isEmpty ? null : _retry, child: Text(tr('Повторить обработку', 'Retry processing'))), TextButton(onPressed: busy ? null : () => Navigator.pop(context), child: Text(tr('Закрыть', 'Close')))],
  );
}
