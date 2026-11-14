import 'dart:async';
import 'dart:convert';
import 'package:flutter/foundation.dart' show kIsWeb;
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'core.dart';
import 'messenger.dart';
import 'l10n.dart';
import 'theme.dart';
import 'components.dart';

/// Text chat uses messenger keys, never wallet addresses as verified identity.
class ChatSheet extends StatefulWidget {
  const ChatSheet({super.key, required this.core, required this.onClose, this.initialPeer, this.contacts = const [], this.onFindContact});
  final WalletCore core;
  final VoidCallback onClose;
  final String? initialPeer;
  final List<UContact> contacts;
  final VoidCallback? onFindContact;
  @override
  State<ChatSheet> createState() => _ChatSheetState();
}

class _ChatSheetState extends State<ChatSheet> {
  final _peer = TextEditingController();
  final _text = TextEditingController();
  final _search = TextEditingController();
  Timer? _timer;
  String? _address;
  String? _mode;
  String? _error;
  String? _sendError;
  bool _ready = false;
  bool _busy = false;
  bool _loading = false;
  List<Map<String, dynamic>> _messages = [];
  int _cursor = 0;
  String? _epoch;
  bool get _en => AppLocale.of(context).lang == 'en';
  String tr(String ru, String en) => _en ? en : ru;

  @override
  void initState() {
    super.initState();
    _peer.text = widget.initialPeer ?? '';
    _refresh();
    _timer = Timer.periodic(const Duration(seconds: 10), (_) => _refresh());
  }
  @override
  void dispose() { _timer?.cancel(); _peer.dispose(); _text.dispose(); _search.dispose(); super.dispose(); }

  Future<void> _refresh() async {
    if (_loading) return;
    _loading = true;
    try {
      final info = await widget.core.chatInfo();
      final ready = info['ready'] == true;
      var messages = List<Map<String, dynamic>>.of(_messages);
      var cursor = _cursor;
      var epoch = _epoch;
      if (ready) {
        // Advance even across non-text pages; reset after daemon restart.
        for (var i = 0; i < 10; i++) {
          final result = await widget.core.chatMessages(cursor);
          final raw = result['messages'];
          final next = result['next'];
          final currentEpoch = result['epoch'];
          if (raw is! List || next is! int || currentEpoch is! String) throw const FormatException('Invalid messages response');
          if (epoch != null && epoch != currentEpoch) { messages = []; cursor = 0; epoch = currentEpoch; continue; }
          epoch = currentEpoch;
          messages.addAll(raw.whereType<Map>().map((m) => Map<String, dynamic>.from(m)));
          if (messages.length > 1000) messages = messages.sublist(messages.length - 1000);
          if (next <= cursor) break;
          cursor = next;
        }
      }
      if (!mounted) return;
      setState(() { _address = info['address'] as String?; _mode = info['mode'] as String?; _ready = ready; _messages = messages; _cursor = cursor; _epoch = epoch; _error = null; });
    } catch (e) {
      if (mounted) setState(() { _ready = false; _error = widget.core.describeError(e); });
    } finally { _loading = false; }
  }

  Future<void> _send() async {
    if (_busy || !_ready || _peer.text.trim().isEmpty || _text.text.trim().isEmpty) return;
    final to = _peer.text.trim();
    final message = _text.text;
    setState(() { _busy = true; _sendError = null; });
    try {
      await widget.core.chatSend(to, message);
      if (!mounted) return;
      _text.clear();
      await _refresh();
    } catch (e) {
      if (mounted) {
        final detail = widget.core.describeError(e);
        final lower = detail.toLowerCase();
        final onionFailure = lower.contains('failed to obtain hidden service circuit') || lower.contains('onion service not found');
        setState(() => _sendError = onionFailure
          ? tr('Не удалось соединиться с собеседником через Tor. Проверьте адрес мессенджера и что у собеседника открыт кошелёк и запущен Tor. Для переписки можно отдельно настроить I2P или Nostr в настройках каналов. Результат отправки может быть неизвестен — перед повтором уточните у собеседника.', 'Could not connect to the contact over Tor. Check the messenger address and that their wallet and Tor are running. I2P or Nostr messaging can be configured separately in channel settings. The send result may be unknown; check with your contact before retrying.')
          : '$detail\n${tr('Результат отправки может быть неизвестен — перед повтором уточните у собеседника.', 'The send result may be unknown; check with your contact before retrying.')}');
      }
    } finally { if (mounted) setState(() => _busy = false); }
  }

  Future<void> _copyNostrBinding() async {
    try {
      final result = _mode == 'i2p_direct' ? await widget.core.chatI2pBinding() : await widget.core.chatNostrBinding();
      final binding = result['binding'];
      if (binding is! Map) throw const FormatException('Invalid Nostr binding');
      await Clipboard.setData(ClipboardData(text: jsonEncode(binding)));
      if (mounted) showToast(context, tr('Адрес канала скопирован', 'Channel address copied'));
    } catch (e) { if (mounted) setState(() { _sendError = widget.core.describeError(e); }); }
  }

  Future<void> _addNostrContact() async {
    final name = TextEditingController(); final raw = TextEditingController();
    String? error; bool busy = false;
    try {
      await showGeneralDialog<void>(context: context, transitionDuration: Duration.zero, barrierDismissible: false,
        pageBuilder: (dialogContext, _, _) => StatefulBuilder(builder: (ctx, setDialog) => AlertDialog(
          title: Text(_mode == 'i2p_direct' ? tr('Добавить I2P-контакт', 'Add I2P contact') : tr('Добавить Nostr-контакт', 'Add Nostr contact')),
          content: SizedBox(width: 460, child: SingleChildScrollView(child: Column(mainAxisSize: MainAxisSize.min, children: [
            Text(tr('Вставьте подписанный адрес от собеседника. Подпись подтверждает ключ, а не личность — сверьте адрес по доверенному каналу.', 'Paste the signed address from your contact. The signature verifies the key, not the person; compare it over a trusted channel.'), style: uiStyle(11)),
            TextField(key: const Key('nostr-contact-name'), controller: name, decoration: InputDecoration(labelText: tr('Имя', 'Name'))),
            TextField(key: const Key('nostr-contact-binding'), controller: raw, minLines: 2, maxLines: 5, decoration: InputDecoration(labelText: tr('Подписанный адрес', 'Signed address'))),
            if (error != null) Text(error!, style: uiStyle(11, color: UPalette.amber)),
          ]))),
          actions: [TextButton(onPressed: busy ? null : () => Navigator.pop(dialogContext), child: Text(tr('Отмена','Cancel'))),
            TextButton(key: const Key('nostr-contact-save'), onPressed: busy ? null : () async {
              setDialog(() { busy = true; error = null; });
              try {
                if (raw.text.length > 8192) throw const FormatException('Address is too long');
                final decoded = jsonDecode(raw.text);
                if (decoded is! Map) throw const FormatException('Invalid signed address');
                final binding = Map<String, dynamic>.from(decoded);
                if (_mode == 'i2p_direct') { await widget.core.chatI2pAdd(binding, name.text.trim()); }
                else { await widget.core.chatNostrAdd(binding, name.text.trim()); }
                final owner = binding['owner'];
                if (mounted && owner is String) setState(() { _peer.text = owner; });
                if (dialogContext.mounted) Navigator.pop(dialogContext);
              } catch (e) { if (dialogContext.mounted) setDialog(() { busy = false; error = widget.core.describeError(e); }); }
            }, child: Text(tr('Добавить','Add')))],
        )));
    } finally { await WidgetsBinding.instance.endOfFrame; name.dispose(); raw.dispose(); }
  }

  @override
  Widget build(BuildContext context) {
    final peer = _peer.text.trim();
    final matched = widget.contacts.where((c) => c.messenger?.trim() == peer).toList();
    final label = matched.length == 1 ? matched.single.nameFor(AppLocale.of(context).lang) : tr('Контакт', 'Contact');
    final visible = peer.isEmpty ? _messages : _messages.where((m) => m['peer'] == peer).toList();
    return USheetCard(
      title: tr('Переписка', 'Messages'), width: 520, onClose: widget.onClose,
      child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
        MessengerNetworkNotice(core: widget.core),
        if (peer.isEmpty) ...[
          Text(tr('Выберите контакт', 'Choose a contact'), style: uiStyle(13, weight: FontWeight.w600)),
          if (widget.contacts.any((c) => c.messenger?.trim().isNotEmpty == true)) ...[
            TextField(key: const Key('chat-contact-search'), controller: _search,
              onChanged: (_) => setState(() {}),
              decoration: InputDecoration(labelText: tr('Поиск контакта', 'Search contacts'))),
            for (final contact in widget.contacts.where((c) =>
                c.messenger?.trim().isNotEmpty == true &&
                c.nameFor(AppLocale.of(context).lang).toLowerCase().contains(_search.text.trim().toLowerCase())))
              ListTile(key: ValueKey('chat-contact-${contact.fullAddress}'), dense: true,
                title: Text(contact.nameFor(AppLocale.of(context).lang)),
                subtitle: Text(contact.verified ? tr('Код сверён', 'Code compared') : tr('Код не сверён', 'Code not compared')),
                onTap: () => setState(() { _peer.text = contact.messenger!.trim(); })),
          ] else
            Text(tr('Пока нет контактов с перепиской.', 'No messaging contacts yet.'), style: uiStyle(11, color: UPalette.text3)),
          if (widget.onFindContact != null)
            TextButton(key: const Key('chat-find-contact'), onPressed: widget.onFindContact,
              child: Text(tr('Найти контакт', 'Find contact'))),
        ] else ...[
          Row(children: [
            Expanded(child: Text(label, style: uiStyle(13, weight: FontWeight.w600))),
            TextButton(key: const Key('chat-change-contact'), onPressed: () => setState(() { _peer.clear(); _sendError = null; }), child: Text(tr('Выбрать другого', 'Change'))),
          ]),
        ],
        if (_mode == 'nostr_direct' || _mode == 'nostr_i2p') Text(_mode == 'nostr_direct'
            ? tr('Nostr: сервер видит ваш IP. Принятие сервером не подтверждает получение собеседником.', 'The server sees your IP. Server acceptance does not confirm receipt by the contact.')
            : tr('Принятие сервером не подтверждает получение собеседником.', 'Server acceptance does not confirm receipt by the contact.'),
          key: const Key('chat-nostr-server-trust'), style: uiStyle(11, color: UPalette.text3)),
        ExpansionTile(key: const Key('chat-advanced'), title: Text(tr('Дополнительно', 'Advanced'), style: uiStyle(11, color: UPalette.text2)), children: [
          Text(tr('Адрес мессенджера', 'Messenger address'), style: uiStyle(12, color: UPalette.text2)),
          SelectableText(_address ?? tr('Адрес пока недоступен', 'Address is not available yet'), style: monoStyle(11)),
          if (_address != null) TextButton(onPressed: () => Clipboard.setData(ClipboardData(text: _address!)), child: Text(tr('Скопировать адрес', 'Copy address'))),
          Text(tr('Подпись подтверждает ключ, а не личность.', 'A signature verifies the key, not the person.'), style: uiStyle(11, color: UPalette.text3)),
          if (!kIsWeb && (_mode == 'nostr_i2p' || _mode == 'nostr_direct' || _mode == 'i2p_direct'))
            Wrap(children: [TextButton(onPressed: _copyNostrBinding, child: Text(_mode == 'i2p_direct' ? tr('Скопировать I2P-адрес', 'Copy I2P address') : tr('Скопировать Nostr-адрес', 'Copy Nostr address'))),
              TextButton(onPressed: _addNostrContact, child: Text(_mode == 'i2p_direct' ? tr('Добавить I2P-контакт', 'Add I2P contact') : tr('Добавить Nostr-контакт', 'Add Nostr contact')))]),
          TextField(key: const Key('chat-peer-manual'), controller: _peer, onChanged: (_) => setState(() {}), decoration: InputDecoration(labelText: tr('Адрес мессенджера собеседника', 'Contact messenger address')), style: uiStyle(12)),
        ]),
        const SizedBox(height: 8),
        SizedBox(height: 220, child: visible.isEmpty
          ? Center(child: Text(tr('Сообщений пока нет', 'No messages yet'), style: uiStyle(12, color: UPalette.text3)))
          : ListView.builder(itemCount: visible.length, itemBuilder: (context, i) {
              final m = visible[i];
              final outgoing = m['direction'] == 'outgoing';
              final verified = !outgoing && m['verified'] == true;
              final sender = (m['peer'] as String?) ?? '';
              final label = outgoing
                ? tr('Вы · передано в канал, получение не подтверждено', 'You · passed to the channel, receipt unconfirmed')
                : verified ? tr('Подпись ключа проверена', 'Key signature verified') : tr('Подпись не подтверждена', 'Signature not verified');
              return ListTile(dense: true, onTap: sender.isEmpty ? null : () => setState(() { _peer.text = sender; }), title: Text((m['text'] as String?) ?? '', style: uiStyle(13)), subtitle: Text('$label\n$sender', style: uiStyle(10, color: verified ? UPalette.mint : UPalette.text3)));
            })),
        TextField(key: const Key('chat-message'), controller: _text, onChanged: (_) => setState(() {}), minLines: 1, maxLines: 3, decoration: InputDecoration(labelText: tr('Сообщение', 'Message')), style: uiStyle(13)),
        if (_error != null) Text(_error!, style: uiStyle(11, color: UPalette.amber)),
        if (_sendError != null) Text(_sendError!, key: const Key('chat-send-error'), style: uiStyle(11, color: UPalette.amber)),
        const SizedBox(height: 8),
        UButton(label: _busy ? tr('Отправка…', 'Sending…') : tr('Отправить', 'Send'), onTap: _ready && !_busy && peer.isNotEmpty && _text.text.trim().isNotEmpty ? _send : null),
        TextButton(onPressed: _loading ? null : _refresh, child: Text(tr('Обновить', 'Refresh'))),
      ]),
    );
  }
}
