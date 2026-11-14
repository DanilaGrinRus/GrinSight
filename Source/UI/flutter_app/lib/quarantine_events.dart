import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'core.dart';

/// Metadata-only recovery. The exported envelope remains encrypted.
class QuarantineEventsDialog extends StatefulWidget {
  const QuarantineEventsDialog({super.key, required this.core, required this.english});
  final WalletCore core;
  final bool english;
  @override
  State<QuarantineEventsDialog> createState() => _QuarantineEventsDialogState();
}

class _QuarantineEventsDialogState extends State<QuarantineEventsDialog> {
  List<Map<String, dynamic>>? items;
  String? notice;
  bool busy = false;
  String tr(String ru, String en) => widget.english ? en : ru;
  @override
  void initState() { super.initState(); _load(); }
  Future<void> _load() async {
    setState(() {busy = true; notice = null;});
    try {
      final data = await widget.core.chatQuarantineList();
      final raw = data['items'];
      if (raw is! List || raw.length > 1000) throw const FormatException();
      final parsed = <Map<String, dynamic>>[];
      final idRe = RegExp(r'^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$');
      final digestRe = RegExp(r'^[a-f0-9]{64}$');
      for (final item in raw) {
        if (item is! Map || item['corrupt'] is! bool || !const ['envelope','malformed','unknown','invalid_name'].contains(item['kind'])) throw const FormatException();
        if (item['kind'] == 'invalid_name') {
          if (item['name_token'] is! String || !digestRe.hasMatch(item['name_token'] as String) || item['corrupt'] != true) throw const FormatException();
        } else if (item['id'] is! String || !idRe.hasMatch(item['id'] as String) || item['digest'] is! String || !digestRe.hasMatch(item['digest'] as String)) { throw const FormatException(); }
        parsed.add(Map<String, dynamic>.from(item));
      }
      if (mounted) setState(() {items = parsed;});
    } catch (_) { if (mounted) setState(() {items = null; notice = tr('Не удалось открыть карантин. Проверьте состояние хранилища.', 'Could not open quarantine. Check storage.');}); }
    finally {if (mounted) setState(() {busy = false;});}
  }
  Future<bool> _confirm(String description) async => await showDialog<bool>(context: context, builder: (ctx) => AlertDialog(
    title: Text(tr('Подтвердите действие', 'Confirm action')), content: Text(description),
    actions: [TextButton(onPressed: () => Navigator.pop(ctx, false), child: Text(tr('Отмена','Cancel'))), TextButton(key: const Key('quarantine-confirm'), onPressed: () => Navigator.pop(ctx,true), child: Text(tr('Подтвердить','Confirm')))],
  )) ?? false;
  Future<void> _copy(Map<String,dynamic> item) async {
    setState(() {busy=true; notice=null;});
    try {
      final value=item['kind']=='invalid_name' ? await widget.core.chatQuarantineInvalidExport(item['name_token'] as String) : await widget.core.chatQuarantineExport(item['id'] as String,item['digest'] as String);
      final encrypted=value['envelope'];
      if (encrypted is! String || encrypted.isEmpty || encrypted.length > 65536) throw const FormatException();
      await Clipboard.setData(ClipboardData(text:encrypted));
      if (mounted) setState(() {notice=tr('Зашифрованный конверт скопирован.', 'Encrypted envelope copied.');});
    } catch (_) {if (mounted) setState(() {notice=tr('Не удалось скопировать конверт.', 'Could not copy envelope.');});}
    finally {if (mounted) setState(() {busy=false;});}
  }
  Future<void> _discard(Map<String,dynamic> item) async {
    final corrupt=item['corrupt'] == true;
    final ok=await _confirm(corrupt ? tr('Запись повреждена и может содержать сообщение или платёж. Удалить безвозвратно?', 'The damaged record may contain a message or payment. Delete permanently?') : tr('Запись может содержать сообщение или платёж. Удалить безвозвратно?', 'The record may contain a message or payment. Delete permanently?'));
    if (!ok || !mounted) return;
    setState(() {busy=true; notice=null;});
    try {if (item['kind']=='invalid_name') {await widget.core.chatQuarantineInvalidDiscard(item['name_token'] as String);} else {await widget.core.chatQuarantineDiscard(item['id'] as String,item['digest'] as String,corrupt);} if (mounted) await _load();}
    catch (_) {if (mounted) setState(() {busy=false; notice=tr('Не удалось удалить запись.', 'Could not delete record.');});}
  }
  Future<void> _cleanup() async {
    final ok=await _confirm(tr('Удалить незавершённые временные файлы карантина после сбоя?', 'Remove abandoned temporary quarantine files?'));
    if (!ok || !mounted) return;
    setState(() {busy=true; notice=null;});
    try {await widget.core.chatQuarantineCleanup(); if (mounted) await _load();}
    catch (_) {if (mounted) setState(() {busy=false; notice=tr('Не удалось очистить временные файлы.', 'Could not clear temporary files.');});}
  }
  @override
  Widget build(BuildContext context) => AlertDialog(
    title: Text(tr('Карантин сообщений','Message quarantine')),
    content: SizedBox(width:440,height:340,child:Column(crossAxisAlignment:CrossAxisAlignment.start,children:[
      Text(tr('Конверты сохранены в зашифрованном виде. Неизвестные и повреждённые записи могут содержать платёж.', 'Envelopes are encrypted. Unknown and damaged records may contain a payment.')),
      if (notice!=null) Text(notice!,key:const Key('quarantine-notice')),
      if (busy) const LinearProgressIndicator(),
      Expanded(child: items==null ? const SizedBox.shrink() : items!.isEmpty ? Center(child:Text(tr('Нет записей','No records'))) : ListView.builder(itemCount:items!.length,itemBuilder:(context,i){
        final item=items![i];final invalid=item['kind']=='invalid_name';final canCopy=invalid || (item['kind']=='envelope' && item['corrupt']==false);
        return ListTile(title:SelectableText(invalid ? item['name_token'] as String : item['id'] as String),subtitle:Text(item['corrupt']==true ? tr('Повреждена','Damaged') : item['kind']=='envelope' ? tr('Зашифрованный конверт','Encrypted envelope') : tr('Некорректная запись','Malformed record')),trailing:Wrap(children:[
          if (canCopy) IconButton(key:Key('quarantine-copy-$i'),tooltip:tr('Скопировать','Copy'),onPressed:busy?null:()=>_copy(item),icon:const Icon(Icons.copy)),
          IconButton(key:Key('quarantine-delete-$i'),tooltip:tr('Удалить','Delete'),onPressed:busy?null:()=>_discard(item),icon:const Icon(Icons.delete_outline)),
        ]));
      })),
    ])),
    actions:[TextButton(key:const Key('quarantine-cleanup'),onPressed:busy?null:_cleanup,child:Text(tr('Очистить временные','Clear temporary'))),TextButton(onPressed:busy?null:_load,child:Text(tr('Обновить','Refresh'))),TextButton(onPressed:busy?null:()=>Navigator.pop(context),child:Text(tr('Закрыть','Close')))],
  );
}
