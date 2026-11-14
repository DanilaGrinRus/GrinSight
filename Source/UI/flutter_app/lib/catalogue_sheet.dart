import 'package:flutter/material.dart';
import 'catalogue_api.dart';
import 'core.dart';
import 'l10n.dart';

/// The relay can omit, retain or return colliding records.
Future<String?> showContactCatalogue(BuildContext context, WalletCore wallet) async {
  if (wallet is! CatalogueApi) {
    await showDialog<void>(context: context, builder: (c) => AlertDialog(content: const Text('Каталог недоступен на этой платформе.'), actions: [TextButton(onPressed: () => Navigator.pop(c), child: const Text('Закрыть'))]));
    return null;
  }
  final api = wallet as CatalogueApi;
  return showDialog<String>(context: context, builder: (_) => _CatalogueDialog(api: api));
}

class _CatalogueDialog extends StatefulWidget {
  const _CatalogueDialog({required this.api});
  final CatalogueApi api;
  @override
  State<_CatalogueDialog> createState() => _CatalogueDialogState();
}

class _CatalogueDialogState extends State<_CatalogueDialog> {
  final name = TextEditingController();
  List<Map<String, dynamic>> results = [];
  bool busy = false, searched = false, publicConsent = false;
  String? error, notice;
  String? ownCode;
  bool get en => AppLocale.of(context).lang == 'en';
  String t(String ru, String english) => en ? english : ru;
  @override
  void initState() { super.initState(); _loadCode(); }
  Future<void> _loadCode() async {
    try { final result=await widget.api.catalogueOwnCode(); if(mounted) setState(()=>ownCode=result['comparison_code']?.toString()); }
    catch (_) { if(mounted) setState(()=>ownCode=null); }
  }
  @override
  void dispose() { name.dispose(); super.dispose(); }

  Future<void> search() async {
    setState(() { busy=true; error=null; notice=null; searched=false; });
    try {
      final query = name.text.trim().replaceAll(RegExp(r'\s+'), '-');
      final response=await widget.api.catalogueSearch(query);
      final raw=response['results'];
      if (raw is! List) throw const FormatException('Invalid directory response');
      if (mounted) setState(() {results=raw.whereType<Map>().map((e)=>Map<String,dynamic>.from(e)).toList(); searched=true;});
    } catch(e) { if(mounted) setState(()=>error=e.toString()); }
    finally { if(mounted) setState(()=>busy=false); }
  }

  Future<void> publish(bool revoke) async {
    if(!publicConsent) {setState(()=>error=t('Подтвердите публикацию данных.','Confirm public disclosure.'));return;}
    setState(() {busy=true;error=null;notice=null;});
    try {
      final response=await widget.api.cataloguePublish(name.text.trim(),revoked:revoke,consentPublic:true);
      final code=response['comparison_code']?.toString() ?? '';
      if(mounted) setState(()=>notice=revoke?t('Сервер принял запрос на отзыв, но профиль может оставаться доступным. Проверьте поиск и при необходимости повторите позже. Серверы могут хранить копии.','The server accepted the revocation request, but the profile may still be available. Check search and retry later if needed. Servers may retain copies.'):'${t('Сервер принял профиль, но доступность в поиске не подтверждена. Ваш код для сверки:', 'The server accepted the profile, but its availability in search is not confirmed. Your comparison code:')} $code');
    } catch(e) {if(mounted) setState(()=>error=e.toString());}
    finally {if(mounted) setState(()=>busy=false);}
  }

  Future<void> add(Map<String,dynamic> result) async {
    final raw=result['profile'];
    if(raw is! Map) {setState(()=>error=t('Повреждённая карточка.','Invalid profile.'));return;}
    final profile=Map<String,dynamic>.from(raw);
    final claims=profile['claims'];
    if(claims is! Map) {setState(()=>error=t('Повреждённая карточка.','Invalid profile.'));return;}
    final label=(claims['name']??'').toString(), address=(claims['wallet_address']??'').toString(), code=(result['comparison_code']??'').toString();
    if (label.isEmpty || address.isEmpty || code.isEmpty) {setState(()=>error=t('Данные контакта неполны.','Contact details are incomplete.'));return;}
    final approved=await showDialog<int>(context:context,builder:(c)=>AlertDialog(title:Text(t('Добавить контакт?','Add contact?')),content:SingleChildScrollView(child:Text('$label\n$address\n\n${t('Код для сверки с человеком:', 'Compare this code with the person:')} $code\n\n${t('Подписи подтверждают ключи, но не личность. Выбирайте «Сверил», только если сравнили код с человеком.', 'Signatures prove key control, not identity. Select “Compared” only after comparing the code with the person.')}')),actions:[TextButton(onPressed:()=>Navigator.pop(c,0),child:Text(t('Отмена','Cancel'))),TextButton(onPressed:()=>Navigator.pop(c,1),child:Text(t('Добавить без сверки','Add without checking'))),TextButton(onPressed:()=>Navigator.pop(c,2),child:Text(t('Сверил код','Compared code')))]));
    if(approved==null || approved==0 || !mounted) return;
    setState(() {busy=true;error=null;});
    try {await widget.api.catalogueAdd(profile,label,identityChecked:approved==2);if(mounted) Navigator.of(context).pop(address);}
    catch(e){if(mounted)setState(()=>error=e.toString());}
    finally {if(mounted)setState(()=>busy=false);}
  }

  @override
  Widget build(BuildContext context) => AlertDialog(
    title:Text(t('Найти контакт','Find contact')),
    content:SizedBox(width:480,child:SingleChildScrollView(child:Column(mainAxisSize:MainAxisSize.min,crossAxisAlignment:CrossAxisAlignment.stretch,children:[
      TextField(key:const Key('catalogue-query'),controller:name,enabled:!busy,decoration:InputDecoration(labelText:t('Контактная фраза или @имя','Contact phrase or @name'),hintText:'ant-ash-bay-bee-cafe-cold')),
      const SizedBox(height:8),
      FilledButton(onPressed:busy?null:search,child:Text(t('Найти','Search'))),
      Text(t('Фразы и имена могут совпадать. Сверьте код с собеседником; сервер может скрыть результаты.','Phrases and names may collide. Compare the code with your contact; the server may hide results.')),
      Text(t('Поиск и доставка найденным контактам доступны через Nostr. Автоматического переключения каналов пока нет.', 'Search and delivery to directory contacts use Nostr. Automatic channel fallback is not available yet.')),
      if(searched && results.isEmpty) Text(t('Совпадений не найдено.','No matches found.')),
      for(final result in results) ListTile(title:Text('${(result['profile'] as Map?)?['claims']?['name'] ?? '?'}'),subtitle:Text('${(result['profile'] as Map?)?['claims']?['wallet_address'] ?? ''}\n${t('Код','Code')}: ${result['comparison_code'] ?? ''}'),isThreeLine:true,trailing:TextButton(onPressed:busy?null:()=>add(result),child:Text(t('Добавить','Add')))),
      if(ownCode!=null) ...[const SizedBox(height:12), Text('${t('Мой код для сверки:', 'My comparison code:')} $ownCode')],
      ExpansionTile(title:Text(t('Дополнительно','Advanced')),children:[
      Text(t('Публичный профиль','Public profile'),style:Theme.of(context).textTheme.titleMedium),
      Text(t('Профиль действует не более 7 дней. Для продолжения поиска опубликуйте его снова. Сервер может удалить запись раньше.','The profile lasts at most 7 days. Publish it again to remain discoverable; the server may remove it sooner.')),
      CheckboxListTile(value:publicConsent,onChanged:busy?null:(v)=>setState(()=>publicConsent=v==true),title:Text(t('Я согласен опубликовать имя, адрес кошелька и канал. Серверы могут сохранить копии.','I agree to publish my name, wallet and channel addresses; servers may retain copies.'))),
      Wrap(spacing:8,children:[OutlinedButton(onPressed:busy?null:()=>publish(false),child:Text(t('Опубликовать моё имя','Publish my name'))),TextButton(onPressed:busy?null:()=>publish(true),child:Text(t('Отозвать','Revoke')))]),
      ]),
      if(busy) const LinearProgressIndicator(),
      if(error!=null) Text(error!,style:TextStyle(color:Theme.of(context).colorScheme.error)),
      if(notice!=null) Text(notice!),
    ]))),
    actions:[TextButton(onPressed:busy?null:()=>Navigator.pop(context),child:Text(t('Закрыть','Close')))],
  );
}
