import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter/foundation.dart' show kIsWeb, defaultTargetPlatform, TargetPlatform;

import 'components.dart';
import 'core.dart';
import 'l10n.dart';
import 'messenger.dart';
import 'qr_scanner.dart';
import 'qr_widgets.dart';
import 'theme.dart';
import 'wallet_model.dart';

/// Настройки подключения Tor (мосты obfs4 / Snowflake). Открывается из настроек,
/// из строки статуса Tor и из блока доставки «Tor».
Future<void> showTorBridgeSettings(BuildContext context, WalletCore core) async {
  Map<String, dynamic> saved;
  try {
    saved = await core.torBridgeSettings();
  } catch (e) {
    if (context.mounted) showToast(context, core.describeError(e));
    return;
  }
  if (!context.mounted) return;
  final lang = AppLocale.of(context).lang;
  String tr(String ru, String en) => lang == 'en' ? en : ru;
  String mode = (saved['mode'] ?? 'direct').toString();
  if (!<String>{'direct', 'obfs4', 'snowflake'}.contains(mode)) {
    showToast(context, tr('Неизвестный режим моста Tor', 'Unknown Tor bridge mode'));
    return;
  }
  final line = TextEditingController(text: (saved['line'] ?? '').toString());
  final binary = TextEditingController(text: (saved['binary'] ?? '').toString());
  final bundledSupported = !kIsWeb && (defaultTargetPlatform == TargetPlatform.windows || defaultTargetPlatform == TargetPlatform.android);
  final defaultBridges = <String, String>{'obfs4': "obfs4 37.218.245.14:38224 D9A82D2F9C2F65A18407B1D2B764F130847F8B5D cert=bjRaMrr1BRiAW8IE9U5z27fQaYgOhX1UCmOpg2pFpoMvo6ZgQMzLsaTzzQNTlm7hNcb+Sg iat-mode=0", 'snowflake': "snowflake 192.0.2.3:80 2B280B23E1107BB62ABFC40DDCC8824814F80A72 fingerprint=2B280B23E1107BB62ABFC40DDCC8824814F80A72 url=https://1098762253.rsc.cdn77.org/ fronts=app.datapacket.com,www.datapacket.com ice=stun:stun.epygi.com:3478,stun:stun.uls.co.za:3478,stun:stun.voipgate.com:3478,stun:stun.mixvoip.com:3478,stun:stun.telnyx.com:3478,stun:stun.hot-chilli.net:3478,stun:stun.fitauto.ru:3478,stun:stun.m-online.net:3478 utls-imitate=hellorandomizedalpn"};
  String? error;
  bool busy = false;
  try {
    await showGeneralDialog<void>(context: context, transitionDuration: Duration.zero, barrierDismissible: false, pageBuilder: (dialogContext, _, _) => StatefulBuilder(builder: (ctx, setDialog) => AlertDialog(
      title: Text(tr('Настройки Tor', 'Tor settings')),
      content: SizedBox(width: 480, child: SingleChildScrollView(child: Column(mainAxisSize: MainAxisSize.min, crossAxisAlignment: CrossAxisAlignment.stretch, children: [
        DropdownButtonFormField<String>(key: const Key('tor-bridge-mode'), initialValue: mode,
          decoration: InputDecoration(labelText: tr('Подключение', 'Connection')),
          items: const [DropdownMenuItem(value: 'direct', child: Text('Tor')),
            DropdownMenuItem(value: 'obfs4', child: Text('obfs4')),
            DropdownMenuItem(value: 'snowflake', child: Text('Snowflake'))],
          onChanged: busy ? null : (v) { if (v != null) setDialog(() { mode = v; if (v != 'direct') { if (line.text.trim().isEmpty || !line.text.trim().startsWith('$v ')) line.text = defaultBridges[v]!; if (bundledSupported && binary.text.trim().isEmpty) binary.text = 'bundled'; } error = null; }); }),
        if (mode != 'direct') ...[
          const SizedBox(height: 12),
          TextField(key: const Key('tor-bridge-line'), controller: line, minLines: 1, maxLines: 3,
            decoration: InputDecoration(labelText: tr('Строка моста', 'Bridge line'))),
          const SizedBox(height: 8),
          Text(bundledSupported
            ? tr('Используется встроенный транспорт Tor и стандартный мост. При блокировке моста можно указать другой.', 'The bundled Tor transport and a default bridge are used. If blocked, you can provide another bridge.')
            : tr('Для этой платформы укажите свой транспорт в дополнительных настройках.', 'Provide a transport for this platform in advanced settings.'), style: uiStyle(11)),
          ExpansionTile(key: const Key('tor-bridge-advanced'), tilePadding: EdgeInsets.zero,
            title: Text(tr('Своя программа транспорта', 'Custom transport program'), style: uiStyle(11)),
            children: [TextField(key: const Key('tor-bridge-binary'), controller: binary,
              decoration: InputDecoration(labelText: tr('bundled или полный путь', 'bundled or full path')))]),
        ],
        const SizedBox(height: 8),
        Text(tr('Прежний маршрут Snowflake через Azure недоступен. После сохранения Tor переподключится; состояние соединения показывается отдельно.',
          'The former Snowflake route through Azure is unavailable. Tor reconnects after saving; connection status is shown separately.'), style: uiStyle(11, color: UPalette.text3)),
        if (error != null) ...[const SizedBox(height: 8), Text(error!, style: uiStyle(11, color: UPalette.amber))],
      ]))),
      actions: [
        TextButton(onPressed: busy ? null : () => Navigator.pop(dialogContext), child: Text(tr('Отмена', 'Cancel'))),
        TextButton(key: const Key('tor-bridge-save'), onPressed: busy ? null : () async {
          setDialog(() { busy = true; error = null; });
          try {
            await core.setTorBridgeSettings(mode: mode, line: line.text.trim(), binary: binary.text.trim());
            if (dialogContext.mounted) Navigator.pop(dialogContext);
            if (context.mounted) showToast(context, tr('Настройки применены. Проверьте состояние Tor.', 'Settings applied. Check Tor status.'));
          } catch (e) {
            if (dialogContext.mounted) setDialog(() { busy = false; error = core.describeError(e); });
          }
        }, child: Text(busy ? tr('Применяется…', 'Applying…') : tr('Сохранить', 'Save'))),
      ],
    )));
  } finally {
    await WidgetsBinding.instance.endOfFrame;
    line.dispose(); binary.dispose();
  }
}

Future<void> showMessagingChannelSettings(BuildContext context, WalletCore core, {bool preferDirect = false}) async {
    Map<String, dynamic> saved;
    try { saved = await core.nostrSettings(); } catch (e) { if (context.mounted) showToast(context, core.describeError(e)); return; }
    if (!context.mounted) return;
    final en = AppLocale.of(context).lang == 'en';
    String tr(String ru, String english) => en ? english : ru;
    var mode = (saved['mode'] ?? 'off').toString();
    final proposed = preferDirect && mode == 'off';
    if (proposed) mode = 'direct';
    if (!{'off', 'i2p', 'direct', 'i2p_direct'}.contains(mode)) { showToast(context, tr('Неизвестный режим связи', 'Unknown messaging mode')); return; }
    bool? catalogueAutoPublish = saved['catalogueAutoPublish'] is bool ? saved['catalogueAutoPublish'] as bool : null;
    var expiry = saved['expiry'] == true; var historyDays = saved['historyDays'] == 30 ? 30 : 0; var busy = false; String? error;
    final savedUrl = (saved['url'] ?? '').toString();
    final url = TextEditingController(text: proposed && savedUrl.trim().isEmpty ? 'wss://relay.primal.net' : savedUrl);
    final proxy = TextEditingController(text: (saved['proxy'] ?? '').toString());
    final bool windows = !kIsWeb && defaultTargetPlatform == TargetPlatform.windows;

    // Каналы: подпись кнопки, значок, пояснение и три свойства (IP скрыт, нужен сервер,
    // доставка, если собеседник не в сети). Под полосой кнопок — текст выбранного канала.
    const List<String> modes = <String>['off', 'i2p_direct', 'i2p', 'direct'];
    String label(String m) => switch (m) {
      'off' => 'Tor',
      'i2p_direct' => tr('I2P напрямую', 'Direct I2P'),
      'i2p' => tr('Nostr через I2P', 'Nostr via I2P'),
      _ => tr('Nostr напрямую', 'Direct Nostr'),
    };
    IconData icon(String m) => switch (m) {
      'off' => Icons.vpn_lock_outlined,
      'i2p_direct' => Icons.hub_outlined,
      'i2p' => Icons.cloud_sync_outlined,
      _ => Icons.public_rounded,
    };
    String about(String m) => switch (m) {
      'off' => tr('Сообщения идут напрямую через onion-сервис Tor. Сервер не нужен, ваш IP скрыт. Собеседник должен быть в сети.',
          'Messages go directly through a Tor onion service. No server, your IP is hidden. The contact must be online.'),
      'i2p_direct' => tr('Прямое соединение через сеть I2P. Сервер не нужен, ваш IP скрыт. Собеседник должен быть в сети.',
          'Direct connection over the I2P network. No server, your IP is hidden. The contact must be online.'),
      'i2p' => tr('Через сервер Nostr внутри I2P (.i2p). Сервер хранит сообщение, пока собеседник не в сети, но не видит ваш IP.',
          'Through a Nostr server inside I2P (.i2p). The server holds messages while the contact is offline but does not see your IP.'),
      _ => tr('Через обычный сервер Nostr. Проще всего и доставляет, даже если собеседник не в сети, но сервер видит ваш IP.',
          'Through a regular Nostr server. Simplest, and delivers while the contact is offline, but the server sees your IP.'),
    };
    // (IP скрыт, без сервера, доставка офлайн)
    (bool, bool, bool) props(String m) => switch (m) {
      'off' => (true, true, false),
      'i2p_direct' => (true, true, false),
      'i2p' => (true, false, true),
      _ => (false, false, true),
    };
    Widget fact(bool good, String text) => Container(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
      decoration: BoxDecoration(
        color: good ? UPalette.mintBg : UPalette.amberBg,
        border: Border.all(color: good ? UPalette.mintLine : UPalette.amberLine),
        borderRadius: BorderRadius.circular(999),
      ),
      child: Row(mainAxisSize: MainAxisSize.min, children: [
        Icon(good ? Icons.check_rounded : Icons.remove_rounded, size: 13, color: good ? UPalette.mint : UPalette.amber),
        const SizedBox(width: 4),
        // На узком экране длинная метка переносится, а не вылезает за край.
        Flexible(child: Text(text, softWrap: true, style: uiStyle(11, color: UPalette.text2))),
      ]),
    );

    try {
      await showGeneralDialog<void>(context: context, transitionDuration: Duration.zero, barrierDismissible: false,
        pageBuilder: (dialogContext, _, _) => StatefulBuilder(builder: (ctx, setDialog) {
          void pick(String v) => setDialog(() {
            mode = v;
            if (v == 'direct' && url.text.trim().isEmpty) url.text = 'wss://relay.primal.net';
            if ((v == 'i2p' || v == 'i2p_direct') && windows && proxy.text.trim().isEmpty) proxy.text = 'bundled';
            if (v == 'direct' && proxy.text.trim() == 'bundled') proxy.text = '';
            error = null;
          });
          final (bool ipHidden, bool noServer, bool offline) = props(mode);
          return AlertDialog(
          backgroundColor: UPalette.surface2,
          titlePadding: const EdgeInsets.fromLTRB(22, 18, 22, 0),
          contentPadding: const EdgeInsets.fromLTRB(22, 12, 22, 0),
          title: Text(tr('Каналы переписки', 'Message channels'), style: uiStyle(18, weight: FontWeight.w600)),
          content: SizedBox(width: 520, child: SingleChildScrollView(child: Column(mainAxisSize: MainAxisSize.min, crossAxisAlignment: CrossAxisAlignment.stretch, children: [
            if (proposed) Padding(padding: const EdgeInsets.only(bottom: 8), child: Text(tr('Предлагаемый канал ещё не включён. Для подключения подтвердите настройки.', 'The suggested channel is not active yet. Confirm the settings to connect.'), style: uiStyle(11.5, color: UPalette.text2))),
            // Полоса кнопок всех каналов связи.
            Row(key: const Key('nostr-mode'), children: [
              for (int i = 0; i < modes.length; i++) ...[
                if (i > 0) const SizedBox(width: 6),
                Expanded(child: Semantics(button: true, selected: mode == modes[i], child: Material(
                  color: mode == modes[i] ? UPalette.mintBg : UPalette.surface,
                  borderRadius: BorderRadius.circular(10),
                  child: InkWell(
                    key: Key('channel-${modes[i]}'),
                    borderRadius: BorderRadius.circular(10),
                    onTap: busy ? null : () => pick(modes[i]),
                    child: Container(
                      height: 56,
                      padding: const EdgeInsets.symmetric(horizontal: 4),
                      decoration: BoxDecoration(
                        border: Border.all(color: mode == modes[i] ? UPalette.mintLine : UPalette.line, width: mode == modes[i] ? 1.5 : 1),
                        borderRadius: BorderRadius.circular(10),
                      ),
                      child: Column(mainAxisAlignment: MainAxisAlignment.center, children: [
                        Icon(icon(modes[i]), size: 18, color: mode == modes[i] ? UPalette.mint : UPalette.text2),
                        const SizedBox(height: 3),
                        FittedBox(fit: BoxFit.scaleDown, child: Text(label(modes[i]), maxLines: 1,
                          style: uiStyle(12, weight: FontWeight.w600, color: mode == modes[i] ? UPalette.text : UPalette.text2))),
                      ]),
                    ),
                  ),
                ))),
              ],
            ]),
            const SizedBox(height: 10),
            // Текст и настройки выбранного канала (меняются при выборе кнопки).
            Container(
              key: const Key('channel-details'),
              padding: const EdgeInsets.fromLTRB(12, 10, 12, 10),
              decoration: BoxDecoration(color: UPalette.fieldBg, border: Border.all(color: UPalette.line), borderRadius: BorderRadius.circular(12)),
              child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
                Text(about(mode), style: uiStyle(12, color: UPalette.text2, height: 1.4)),
                const SizedBox(height: 8),
                Wrap(spacing: 6, runSpacing: 6, children: [
                  fact(ipHidden, ipHidden ? tr('IP скрыт', 'IP hidden') : tr('IP виден серверу', 'IP visible to server')),
                  fact(noServer, noServer ? tr('Без сервера', 'No server') : tr('Через сервер', 'Via server')),
                  fact(offline, offline ? tr('Доставка, если собеседник не в сети', 'Delivers while contact is offline') : tr('Собеседник должен быть в сети', 'Contact must be online')),
                ]),
                if (mode == 'i2p_direct') ...[
                  const SizedBox(height: 8),
                  TextField(key: const Key('nostr-proxy'), controller: proxy, decoration: InputDecoration(isDense: true, labelText: tr('Локальный I2P SAM (IP:порт)', 'Local I2P SAM (IP:port)'))),
                  const SizedBox(height: 4),
                  Text(windows
                    ? tr('bundled — встроенный маршрутизатор Windows; можно указать свой локальный SAM.', 'bundled uses the built-in Windows router; a local SAM can also be supplied.')
                    : tr('Нужен запущенный внешний маршрутизатор I2P.', 'A running external I2P router is required.'), style: uiStyle(10.5, color: UPalette.text3)),
                ],
                if (mode == 'i2p' || mode == 'direct') ...[
                  const SizedBox(height: 8),
                  TextField(key: const Key('nostr-url'), controller: url, decoration: InputDecoration(isDense: true, labelText: tr('Адрес сервера', 'Server address'))),
                  if (mode == 'i2p') ...[
                    const SizedBox(height: 6),
                    TextField(key: const Key('nostr-proxy'), controller: proxy, decoration: InputDecoration(isDense: true, labelText: tr('Локальный I2P SOCKS (IP:порт)', 'Local I2P SOCKS (IP:port)'))),
                    const SizedBox(height: 4),
                    Text(windows
                      ? tr('bundled — встроенный I2P Windows. Нужен сервер .i2p.', 'bundled uses built-in I2P on Windows. An .i2p server is required.')
                      : tr('Нужен внешний I2P и сервер .i2p; проверьте, что SOCKS идёт через I2P.', 'An external I2P router and an .i2p server are required; make sure the SOCKS proxy uses I2P.'), style: uiStyle(10.5, color: UPalette.text3)),
                  ],
                  const SizedBox(height: 6),
                  if (mode == 'direct') Text(tr('Сервер видит ваш IP, время подключений и метаданные.', 'The server sees your IP address, connection times, and metadata.'), key: const Key('nostr-ip-notice'), style: uiStyle(11.5, color: UPalette.amber)),
                  Text(tr('Принятие сервером не подтверждает получение собеседником; проверяйте доставку.', 'Server acceptance does not confirm receipt by the contact; check delivery.'), key: const Key('nostr-server-trust'), style: uiStyle(11, color: UPalette.amber)),
                  // Своя прозрачная Material: ListTile внутри цветного контейнера.
                  Material(type: MaterialType.transparency, child: CheckboxListTile(key: const Key('nostr-expiry'), contentPadding: EdgeInsets.zero, dense: true, value: expiry,
                    title: Text(tr('Запрашивать истечение на сервере через 15 минут', 'Request server expiry after 15 minutes'), style: uiStyle(12)),
                    subtitle: Text(tr('Сервер может сохранить копию; время истечения ему видно.', 'The server may retain a copy and can see the expiry time.'), style: uiStyle(10.5, color: UPalette.text3)),
                    onChanged: busy ? null : (v) => setDialog(() { expiry = v == true; }))),
                ],
              ]),
            ),
            const SizedBox(height: 6),
            // Общие настройки — компактно, для всех каналов.
            if (catalogueAutoPublish != null) SwitchListTile(
              key: const Key('catalogue-auto-publish'),
              contentPadding: EdgeInsets.zero,
              dense: true,
              value: catalogueAutoPublish!,
              onChanged: busy ? null : (v) => setDialog(() { catalogueAutoPublish = v; }),
              title: Text(tr('Публиковать контакт для поиска', 'Publish contact for search'), style: uiStyle(12.5)),
              subtitle: Text(tr('Фраза, адрес и канал видны в каталоге. При выключении серверы могут сохранить ранее опубликованное.', 'Phrase, wallet address and channel are visible in the directory. Servers may retain previously published copies after disabling.'), style: uiStyle(10.5, color: UPalette.text3)),
            ) else Text(tr('Настройка публикации недоступна.', 'Publication setting unavailable.'), style: uiStyle(10.5, color: UPalette.amber)),
            // Узкий экран: подпись над выбором; широкий — в одну строку.
            // (Не LayoutBuilder: AlertDialog меряет содержимое через IntrinsicWidth.)
            Builder(builder: (BuildContext lc) {
              final Widget label = Text(tr('Хранить переписку на устройстве', 'Keep conversations on this device'), style: uiStyle(12.5));
              final Widget picker = DropdownButtonFormField<int>(key: const Key('history-retention'), initialValue: historyDays, isExpanded: true, isDense: true,
                decoration: const InputDecoration(isDense: true),
                items: [DropdownMenuItem(value: 0, child: Text(tr('Без срока', 'No expiry'), maxLines: 1, overflow: TextOverflow.ellipsis, style: uiStyle(12.5))), DropdownMenuItem(value: 30, child: Text(tr('Удалять через 30 дней', 'Delete after 30 days'), maxLines: 1, overflow: TextOverflow.ellipsis, style: uiStyle(12.5)))],
                onChanged: busy ? null : (v) { if (v != null) setDialog(() { historyDays = v; }); });
              if (MediaQuery.sizeOf(lc).width < 600) {
                return Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [label, picker]);
              }
              return Row(children: [Expanded(child: label), const SizedBox(width: 8), SizedBox(width: 190, child: picker)]);
            }),
            const SizedBox(height: 4),
            Text(tr('Срок касается только новых текстовых сообщений; платёжные данные сохраняются. Канал переключится после сохранения.', 'Applies to new text messages only; payment data is kept. The channel switches after saving.'), style: uiStyle(10.5, color: UPalette.text3)),
            if (error != null) Padding(padding: const EdgeInsets.only(top: 6), child: Text(error!, style: uiStyle(11, color: UPalette.amber))),
          ]))),
          actions: [TextButton(onPressed: busy ? null : () => Navigator.pop(dialogContext), child: Text(tr('Отмена', 'Cancel'))),
            TextButton(key: const Key('nostr-save'), onPressed: busy ? null : () async {
              setDialog(() { busy = true; error = null; });
              try {
                await core.setNostrSettings(mode: mode, url: url.text.trim(), proxy: proxy.text.trim(), consent: mode == 'direct', expiry: expiry, historyDays: historyDays, catalogueAutoPublish: catalogueAutoPublish);
                if (dialogContext.mounted) Navigator.pop(dialogContext);
                if (context.mounted) showToast(context, tr('Настройки применены. Проверьте состояние канала.', 'Settings applied. Check channel status.'));
              } catch (e) { if (dialogContext.mounted) setDialog(() { busy = false; error = '${tr('Не удалось применить', 'Could not apply')}: ${core.describeError(e)}'; }); }
            }, child: Text(busy ? tr('Применяется…', 'Applying…') : tr('Сохранить', 'Save')))],
        );
        }));
    } finally { await WidgetsBinding.instance.endOfFrame; url.dispose(); proxy.dispose(); }
  }


// ================================ SEND ================================

/// Continue a previously created send; it never creates another payment.
class ResumeSendSheet extends StatefulWidget {
  const ResumeSendSheet({super.key, required this.core, required this.txId, required this.network, required this.onClose, this.retryOnly = false});
  final WalletCore core;
  final String txId;
  final String network;
  final VoidCallback onClose;
  final bool retryOnly;

  @override
  State<ResumeSendSheet> createState() => _ResumeSendSheetState();
}

class _ResumeSendSheetState extends State<ResumeSendSheet> {
  final _answer = TextEditingController();
  bool _busy = false;
  bool _done = false;
  String? _error;
  bool _retryAvailable = false;
  String? _retryMode;
  String? _retryNotice;

  @override
  void initState() {
    super.initState();
    _loadRetry();
  }

  Future<void> _loadRetry() async {
    try {
      final result = await widget.core.backupPaymentRetryInfo(widget.txId);
      if (mounted) setState(() { _retryAvailable = result['available'] == true; _retryMode = result['mode']?.toString(); });
    } catch (e) { if (mounted) setState(() => _error = widget.core.describeError(e)); }
  }

  Future<void> _retry() async {
    if (_busy || !_retryAvailable) return;
    final en = AppLocale.of(context).lang == 'en';
    setState(() { _busy = true; _error = null; _retryNotice = null; });
    try {
      await widget.core.retryBackupPayment(widget.txId);
      if (mounted) setState(() => _retryNotice = en ? 'Retry queued. Delivery and receipt are still unknown.' : 'Повтор поставлен в очередь. Доставка и получение пока неизвестны.');
    } catch (e) { if (mounted) setState(() => _error = widget.core.describeError(e)); }
    finally { if (mounted) setState(() => _busy = false); }
  }

  @override
  void dispose() {
    _answer.dispose();
    super.dispose();
  }

  Future<void> _copySavedSlatepack() async {
    if (_busy) return;
    setState(() { _busy = true; _error = null; });
    try {
      final slatepack = await widget.core.slatepack(widget.txId);
      if (!mounted) return;
      if (slatepack.trim().isEmpty) throw Exception('Saved slatepack is empty');
      await copyText(context, slatepack, AppLocale.of(context).s.copiedSlatepack);
    } catch (e) {
      if (mounted) setState(() => _error = widget.core.describeError(e));
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _finalize() async {
    if (_busy || _done || _answer.text.trim().isEmpty) return;
    setState(() { _busy = true; _error = null; });
    try {
      final job = await widget.core.finalizeJob(txId: widget.txId, answer: _answer.text.trim());
      await job.wait();
      if (mounted) setState(() { _busy = false; _done = true; });
    } catch (e) {
      if (mounted) setState(() { _busy = false; _error = widget.core.describeError(e); });
    }
  }

  @override
  Widget build(BuildContext context) {
    final s = AppLocale.of(context).s;
    return PopScope(
      canPop: !_busy,
      child: USheetCard(
        title: s.resumePayment,
        onClose: _busy ? () {} : widget.onClose,
        child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
          UButton(key: const Key('resume-copy-slatepack'), label: s.copySlatepack,
            onTap: _busy ? null : _copySavedSlatepack),
          const SizedBox(height: 6),
          if (!widget.retryOnly) ...[
            Text(s.torS1Warning, style: uiStyle(11, color: UPalette.text3)),
            const SizedBox(height: 12),
            Text(s.resumePaymentNote, style: uiStyle(12, color: UPalette.text2, height: 1.5)),
          ],
          if (_retryAvailable) ...[
            const SizedBox(height: 8),
            UButton(key: const Key('retry-backup-payment'), label: AppLocale.of(context).lang == 'en' ? 'Retry delivery via $_retryMode' : 'Повторить доставку: $_retryMode', height: 34, onTap: _busy || _done ? null : _retry),
            Text(AppLocale.of(context).lang == 'en' ? 'The same saved payment and route will be used; no new payment is created.' : 'Будет использован сохранённый платёж и прежний маршрут; новый платёж не создаётся.', style: uiStyle(10, color: UPalette.text3)),
            if (_retryNotice != null) Text(_retryNotice!, key: const Key('retry-backup-notice'), style: uiStyle(11, color: UPalette.amber)),
          ],
          const SizedBox(height: 12),
          if (!widget.retryOnly) ...[
            UTextField(label: s.answerLabel, controller: _answer, hint: s.answerLabel,
              fieldKey: const Key('resume-answer'), suffix: qrInputSuffix(context, network: widget.network, controller: _answer)),
            const SizedBox(height: 10),
            UButton(key: const Key('resume-finalize'), label: s.finalizeAction, primary: true,
              onTap: _busy || _done ? null : _finalize),
          ],
          if (_busy) ...[const SizedBox(height: 10), const LinearProgressIndicator()],
          if (_error != null) ...[const SizedBox(height: 10), Text(s.humanError(_error!), style: uiStyle(11, color: UPalette.amber))],
          if (_done) ...[const SizedBox(height: 10), Text(s.jobDone, style: uiStyle(12, color: UPalette.mint))],
        ]),
      ),
    );
  }
}

class SendFlowSheet extends StatefulWidget {
  const SendFlowSheet({
    super.key,
    required this.onClose,
    required this.core,
    this.status,
    this.initialStep = 0,
    this.initialTo,
    this.initialBackupPeer,
    this.delivery = 'tor',
  });

  final VoidCallback onClose;
  final WalletCore core;
  final WalletStatus? status;
  final int initialStep;
  final String? initialTo;
  final String? initialBackupPeer;
  final String delivery;

  @override
  State<SendFlowSheet> createState() => _SendFlowSheetState();
}

class _SendFlowSheetState extends State<SendFlowSheet> {
  S get s => AppLocale.of(context).s;

  late int _step;
  late final TextEditingController _to;
  late final TextEditingController _amount;
  final TextEditingController _answer = TextEditingController();

  bool _busy = false;
  String? _error;
  String _phase = '';
  List<String> _lines = const <String>[];
  WalletJob? _job;
  SendResult? _sent;
  bool _torQueued = false;
  String? _confirmState;
  int? _confirmDepth;
  int? _confirmHeight;
  String? _backupMode;
  String? _backupRoute;
  String? _backupPeer;
  String? _backupError;
  bool _backupLoading = false;
  List<Map<String, dynamic>> _backupContacts = const [];
  bool get _backup => widget.delivery == 'grinmail';
  bool get _en => AppLocale.of(context).lang == 'en';
  String _tr(String ru, String en) => _en ? en : ru;
  String _modeLabel(String? mode) => switch (mode) {
    'i2p_direct' => 'I2P',
    'nostr_i2p' => 'Nostr / I2P',
    'nostr_direct' => _tr('Nostr напрямую', 'Direct Nostr'),
    _ => _tr('не настроен', 'not configured'),
  };
  String _shortPeer(String value) => value.length <= 22 ? value : '${value.substring(0, 11)}…${value.substring(value.length - 7)}';

  Future<void> _loadBackupContacts() async {
    setState(() { _backupLoading = true; _backupError = null; });
    try {
      final result = await widget.core.backupPaymentContacts();
      final mode = result['mode']?.toString();
      final route = result['route']?.toString();
      final entries = result['contacts'];
      if (!{'i2p_direct', 'nostr_i2p', 'nostr_direct'}.contains(mode) || route == null || route.isEmpty || entries is! List) throw StateError('invalid backup channel');
      final contacts = entries.whereType<Map>().map((m) => Map<String, dynamic>.from(m)).where((m) => m['address'] is String && (m['address'] as String).isNotEmpty).toList();
      if (!mounted) return;
      final initialPeer = widget.initialBackupPeer;
      final initialAddress = widget.initialTo?.trim();
      final selectInitial = initialPeer != null && initialPeer.isNotEmpty && initialAddress != null && _to.text.trim() == initialAddress && contacts.any((c) => c['address'] == initialPeer);
      setState(() { _backupMode = mode; _backupRoute = route; _backupContacts = contacts; _backupPeer = selectInitial ? initialPeer : null; _backupLoading = false; });
    } catch (e) {
      if (!mounted) return;
      setState(() { _backupLoading = false; _backupError = widget.core.describeError(e); _backupMode = null; _backupRoute = null; _backupContacts = const []; _backupPeer = null; });
    }
  }

  @override
  void initState() {
    super.initState();
    _step = widget.initialStep.clamp(0, 1);
    _to = TextEditingController(text: widget.initialTo ?? '');
    _to.addListener(_walletAddressChanged);
    _amount = TextEditingController();
    if (_backup) _loadBackupContacts();
  }

  void _walletAddressChanged() {
    if (widget.initialTo != null && _to.text.trim() != widget.initialTo!.trim() && _backupPeer != null) {
      setState(() => _backupPeer = null);
    }
  }

  @override
  void dispose() {
    _to.removeListener(_walletAddressChanged);
    _to.dispose();
    _amount.dispose();
    _answer.dispose();
    super.dispose();
  }

  String get _unit => unitFor(widget.status?.network ?? 'mainnet');
  String get _network => widget.status?.network ?? 'mainnet';
  Widget _scanSuffix(TextEditingController c) => qrInputSuffix(context, network: _network, controller: c);

  String get _title {
    switch (_step) {
      case 1:
        return s.reviewTitle;
      case 2:
        return s.paymentCreated;
      default:
        return s.sendTitle;
    }
  }

  int? _parseAmount() {
    try {
      return grinToNano(_amount.text);
    } on FormatException {
      return null;
    }
  }

  void _continue() {
    if (widget.delivery != 'tor' && widget.delivery != 'manual' && !_backup) {
      showToast(context, s.relayUnavailable);
      return;
    }
    if (_backup && (_backupLoading || _backupMode == null || _backupPeer == null)) {
      showToast(context, _tr('Выберите доступный канал и подписанный адрес собеседника.', 'Choose an available channel and the contact’s signed address.'));
      return;
    }
    final String recipient = _to.text.trim();
    if (recipient.isEmpty) {
      showToast(context, s.recipientRequired);
      return;
    }
    final bool addressShape = recipient.length <= 120 &&
        RegExp(r'^(grin1|tgrin1)[a-z0-9]{20,}$').hasMatch(recipient);
    if (!addressShape) {
      showToast(context, s.recipientInvalid);
      return;
    }
    final String prefix = _network == 'floonet' ? 'tgrin1' : 'grin1';
    if (!recipient.startsWith(prefix)) {
      showToast(context, s.qrWrongNetwork);
      return;
    }
    final int? nano = _parseAmount();
    if (nano == null || nano <= 0) {
      showToast(context, s.amountRequired);
      return;
    }
    final int? available = widget.status?.balance.availableNano;
    // Комиссия добавляется сверх суммы: сумма == доступному уже не пройдёт.
    if (available != null && nano >= available) {
      showToast(context, s.insufficientFunds);
      return;
    }
    setState(() => _step = 1);
  }

  Future<void> _send() async {
    if (_busy || (widget.delivery != 'tor' && widget.delivery != 'manual' && !_backup)) {
      if (!_busy) showToast(context, s.relayUnavailable);
      return;
    }
    final int? nano = _parseAmount();
    if (nano == null) return;
    setState(() {
      _busy = true;
      _error = null;
      _phase = '';
      _lines = const <String>[];
    });
    try {
      if (_backup) {
        final fresh = await widget.core.backupPaymentContacts();
        final list = fresh['contacts'];
        if (fresh['mode'] != _backupMode || fresh['route'] != _backupRoute || list is! List || !list.whereType<Map>().any((v) => v['address'] == _backupPeer)) {
          throw StateError(_tr('Канал или контакт изменился. Вернитесь и выберите контакт заново.', 'The channel or contact changed. Go back and select the contact again.'));
        }
      }
      final intent = _backup ? <String, String>{'peer': _backupPeer!, 'mode': _backupMode!, 'route': _backupRoute!} : null;
      final WalletJob job = await widget.core.sendJob(to: _to.text.trim(), amountNano: nano, backupIntent: intent);
      _job = job;
      final Map<String, dynamic> r = await job.wait(onProgress: (JobProgress p) {
        if (mounted) setState(() { _phase = p.phase; _lines = p.lines; });
      });
      if (!mounted) return;
      setState(() {
        _sent = SendResult(
          txId: (r['tx_id'] ?? '').toString(),
          slatepack: (r['slatepack'] ?? '').toString(),
          feeNano: r['fee'] == null ? null : int.tryParse(r['fee'].toString()),
        );
        _step = 2;
        _job = null;
      });
      if (_backup && r['backup_intent_error'] != null) {
        setState(() { _busy = false; _error = _tr('Платёж создан, но его маршрут не сохранён. Используйте slatepack вручную и не создавайте повторный платёж.', 'Payment was created, but its route was not saved. Use the slatepack manually and do not create another payment.'); });
        return;
      }
      if (widget.delivery == 'manual') {
        setState(() => _busy = false);
        return;
      }
      // Creating S1 already reserves inputs. Preserve that result even if
      // queueing fails: retrying the send could create a second payment.
      try {
        if (_backup) {
          await widget.core.deliverBackup(_sent!.txId, peer: _backupPeer!, mode: _backupMode!, route: _backupRoute!);
        } else {
          await widget.core.deliverTor(_sent!.txId);
        }
        if (!mounted) return;
        setState(() { _torQueued = true; _busy = false; });
      } catch (e) {
        if (!mounted) return;
        setState(() { _busy = false; _error = '${_backup ? _tr('Не удалось поставить платёж в очередь выбранного канала', 'Could not queue the payment on the selected channel') : s.torQueueFailed}: ${widget.core.describeError(e)}'; });
      }
    } catch (e) {
      if (!mounted) return;
      setState(() {
        _busy = false;
        _error = widget.core.describeError(e);
      });
    }
  }

  Future<void> _finalize() async {
    final SendResult? sent = _sent;
    if (sent == null) return;
    if (_answer.text.trim().isEmpty) {
      showToast(context, s.recipientRequired);
      return;
    }
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      final WalletJob job = await widget.core.finalizeJob(txId: sent.txId, answer: _answer.text.trim());
      _job = job;
      await job.wait(onProgress: (JobProgress p) {
        if (mounted) setState(() { _phase = p.phase; _lines = p.lines; });
      });
      if (!mounted) return;
      setState(() {
        _busy = false;
        _step = 2;
        _error = null;
      });
      showToast(context, s.jobDone);
    } catch (e) {
      if (!mounted) return;
      setState(() {
        _busy = false;
        _error = widget.core.describeError(e);
      });
    }
  }

  Future<void> _confirm() async {
    final SendResult? sent = _sent;
    if (sent == null) return;
    setState(() {
      _busy = true;
      _error = null;
      _phase = '';
      _lines = <String>[];
      _confirmState = null;
    });
    try {
      final WalletJob job = await widget.core.confirmJob(sent.txId);
      final Map<String, dynamic> r = await job.wait(onProgress: (JobProgress p) {
        if (mounted) setState(() { _phase = p.phase; _lines = p.lines; });
      });
      if (!mounted) return;
      setState(() {
        _busy = false;
        _confirmState = (r['state'] ?? '').toString();
        _confirmDepth = int.tryParse((r['depth'] ?? '').toString());
        _confirmHeight = int.tryParse((r['height'] ?? '').toString());
      });
    } catch (e) {
      if (!mounted) return;
      setState(() {
        _busy = false;
        _error = widget.core.describeError(e);
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    return PopScope(
      canPop: !_busy,
      child: USheetCard(
      title: _title,
      onClose: _busy ? () {} : widget.onClose,
      child: _step == 0
          ? _form()
          : _step == 1
              ? _review()
              : _sentView(),
      ),
    );
  }

  Widget _jobStatus() {
    if (!_busy && _error == null) return const SizedBox.shrink();
    return Container(
      margin: const EdgeInsets.only(top: 10),
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: UPalette.fieldBg,
        border: Border.all(color: _error == null ? UPalette.line : UPalette.amberLine),
        borderRadius: BorderRadius.circular(12),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          if (_error != null)
            Text(s.humanError(_error!), style: uiStyle(11, color: UPalette.amber, height: 1.5))
          else ...[
            Text(_phase.isEmpty ? s.loadingWallet : _phase, style: uiStyle(11.5, weight: FontWeight.w600)),
            const SizedBox(height: 6),
            const LinearProgressIndicator(minHeight: 3, color: UPalette.mint, backgroundColor: UPalette.line),
            if (_lines.isNotEmpty) ...[
              const SizedBox(height: 6),
              for (final String line in _lines.take(3))
                Text(line, style: uiStyle(10, color: UPalette.text3), maxLines: 1, overflow: TextOverflow.ellipsis),
            ],
            if (_job != null) ...[
              const SizedBox(height: 8),
              UButton(label: s.jobCancel, height: 34, onTap: _busy ? () => _job!.cancel() : null),
            ],
          ],
        ],
      ),
    );
  }

  Widget _form() {
    final int? available = widget.status?.balance.availableNano;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        UTextField(
          label: s.recipient,
          controller: _to,
          hint: s.recipientHint,
          fieldKey: const Key('send-to'),
          suffix: _scanSuffix(_to),
        ),
        if (_backup) ...[
          const SizedBox(height: 12),
          if (_backupLoading) const LinearProgressIndicator(minHeight: 3)
          else if (_backupError != null) ...[
            Text(_tr('Канал переписки недоступен: ', 'Messaging channel unavailable: ') + _backupError!, style: uiStyle(11, color: UPalette.amber)),
            TextButton(onPressed: _loadBackupContacts, child: Text(_tr('Повторить', 'Retry'))),
          ] else ...[
            Text('${_tr('Канал', 'Channel')}: ${_modeLabel(_backupMode)}', style: uiStyle(11, color: UPalette.text2)),
            if (_backupMode == 'nostr_direct') Text(_tr('Сервер видит ваш IP.', 'The server sees your IP.'), style: uiStyle(11, color: UPalette.amber)),
            DropdownButtonFormField<String>(key: const Key('payment-backup-peer'), initialValue: _backupPeer,
              decoration: InputDecoration(labelText: _tr('Подписанный адрес собеседника', 'Contact signed address')),
              items: _backupContacts.map((c) { final address = c['address'].toString(); final name = (c['name'] ?? '').toString(); return DropdownMenuItem(value: address, child: Text('${name.isEmpty ? _shortPeer(address) : name} · ${_shortPeer(address)}', overflow: TextOverflow.ellipsis)); }).toList(),
              onChanged: _busy ? null : (v) => setState(() => _backupPeer = v),
              isExpanded: true),
            if (_backupContacts.isEmpty) Text(_tr('В переписке добавьте подписанный адрес собеседника для выбранного канала.', 'Add the contact’s signed address for this channel in Messages.'), style: uiStyle(11, color: UPalette.amber)),
            Text(_tr('Проверьте, что адрес кошелька и подписанный адрес переписки принадлежат одному человеку.', 'Verify that the wallet address and signed messaging address belong to the same person.'), style: uiStyle(10, color: UPalette.text3)),
          ],
        ],
        const SizedBox(height: 12),
        Row(
          crossAxisAlignment: CrossAxisAlignment.end,
          children: [
            Expanded(
              child: UTextField(
                label: s.amount,
                controller: _amount,
                hint: '0',
                fieldKey: const Key('send-amount'),
                keyboardType: const TextInputType.numberWithOptions(decimal: true),
                onSubmitted: _continue,
              ),
            ),
            const SizedBox(width: 10),
            Padding(
              padding: const EdgeInsets.only(bottom: 14),
              child: Text(_unit, style: uiStyle(13, weight: FontWeight.w600, color: UPalette.text2)),
            ),
          ],
        ),
        const SizedBox(height: 8),
        Row(
          children: [
            Expanded(
              child: Text(
                available == null ? s.feeHint : '${s.availableShort}: ${nanoToGrin(available)} $_unit · ${s.feeHint}',
                style: uiStyle(11, color: UPalette.text3, height: 1.4),
              ),
            ),
            Tooltip(
              message: widget.delivery == 'manual' ? s.deliveryManualHint : s.deliveryAutoHint('Tor'),
              triggerMode: TooltipTriggerMode.tap,
              child: const Padding(
                padding: EdgeInsets.all(4),
                child: Icon(Icons.info_outline_rounded, size: 16, color: UPalette.text3),
              ),
            ),
          ],
        ),
        const SizedBox(height: 14),
        UButton(
          key: const Key('send-continue'),
          label: s.continueLabel,
          primary: true,
          onTap: _continue,
        ),
      ],
    );
  }

  Widget _review() {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        _SumRow(label: s.recipient, value: _to.text.trim(), mono: true),
        _SumRow(label: s.amount, value: '${_amount.text.trim()} $_unit'),
        _SumRow(label: s.delivery, value: _backup ? _modeLabel(_backupMode) : widget.delivery == 'manual' ? s.deliveryManual : s.deliveryTor),
        if (_backup) _SumRow(label: _tr('Подписанный контакт', 'Signed contact'), value: _shortPeer(_backupPeer ?? ''), mono: true),
        _SumRow(label: s.fee, value: '—'),
        const SizedBox(height: 14),
        Text(s.s2Note, style: uiStyle(11.5, color: UPalette.text2, height: 1.6)),
        const SizedBox(height: 16),
        Row(
          children: [
            Expanded(child: UButton(label: s.back, onTap: () => setState(() => _step = 0))),
            const SizedBox(width: 10),
            Expanded(
              flex: 2,
              child: UButton(
                key: const Key('send-submit'),
                label: s.send,
                primary: true,
                onTap: _busy ? null : _send,
              ),
            ),
          ],
        ),
        _jobStatus(),
      ],
    );
  }

  Widget _sentView() {
    final SendResult? sent = _sent;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        const Icon(Icons.check_circle_outline_rounded, size: 26, color: UPalette.mint),
        const SizedBox(height: 8),
        Text(s.paymentCreated, textAlign: TextAlign.center, style: uiStyle(17, weight: FontWeight.w600)),
        const SizedBox(height: 4),
        Text(widget.delivery == 'manual' ? s.torManualFallback : _backup
          ? (_torQueued ? _tr('Платёж в очереди ${_modeLabel(_backupMode)}. Доставка и подтверждение получателем ещё не подтверждены.', 'Payment queued for ${_modeLabel(_backupMode)}. Delivery and receipt are not confirmed.') : _tr('Состояние отправки неизвестно. Проверьте операцию перед повтором.', 'Delivery status is unknown. Check the operation before retrying.'))
          : (_torQueued ? s.torQueued : s.torQueueUnconfirmed), textAlign: TextAlign.center, style: uiStyle(11, color: UPalette.text3, height: 1.5)),
        if (widget.delivery == 'tor') ...[
          const SizedBox(height: 6),
          Text(s.torS1Warning, textAlign: TextAlign.center, style: uiStyle(11, color: UPalette.text3, height: 1.5)),
        ],
        const SizedBox(height: 12),
        if (sent != null) ...[
          if (_backup) ...[
            UButton(key: const Key('send-retry-backup'), label: _tr('Повторить доставку', 'Retry delivery'), height: 34, onTap: _busy ? null : () async {
              setState(() { _busy = true; _error = null; });
              try { await widget.core.retryBackupPayment(sent.txId); if (mounted) setState(() { _torQueued = true; }); }
              catch (e) { if (mounted) setState(() { _error = widget.core.describeError(e); }); }
              finally { if (mounted) setState(() { _busy = false; }); }
            }),
            Text(_tr('Повтор использует тот же платёж и исходный маршрут; получение не подтверждено.', 'Retry uses the same payment and original route; receipt is not confirmed.'), style: uiStyle(10, color: UPalette.text3)),
          ],
          UButton(key: const Key('send-copy-slatepack'), label: s.copySlatepack, height: 34, onTap: () => copyText(context, sent.slatepack, s.copiedSlatepack)),
          if (widget.delivery == 'manual') ...[
            const SizedBox(height: 12),
            Text(s.answerLabel, style: uiStyle(11, weight: FontWeight.w600, color: UPalette.text2)),
            const SizedBox(height: 6),
            UTextField(label: '', controller: _answer, hint: s.answerLabel, fieldKey: const Key('send-answer'), suffix: _scanSuffix(_answer)),
            const SizedBox(height: 10),
            UButton(key: const Key('send-finalize'), label: s.finalizeAction, primary: true, onTap: _busy ? null : _finalize),
          ],
          const SizedBox(height: 8),
          UButton(key: const Key('send-check-confirmation'), label: s.confirmAction, height: 36, onTap: _busy ? null : _confirm),
          _jobStatus(),
          if (_confirmState != null) ...[
            const SizedBox(height: 8),
            Text(
              '${_confirmState!}'
              '${_confirmHeight == null ? '' : ' · ${formatHeight(_confirmHeight!)}'}'
              '${_confirmDepth == null ? '' : ' · depth ${_confirmDepth!}'}',
              style: uiStyle(11, color: UPalette.text2),
            ),
          ],
          if (sent.feeNano != null) ...[
            const SizedBox(height: 8),
            Text('${s.fee}: ${nanoToGrin(sent.feeNano!)} $_unit', style: uiStyle(11, color: UPalette.text3)),
          ],
          const SizedBox(height: 12),
          SlatepackQrView(text: sent.slatepack, network: _network),
        ],
        const SizedBox(height: 10),
        Text(s.paymentProofNote, style: uiStyle(10, color: UPalette.text3, height: 1.5)),
        const SizedBox(height: 12),
        UButton(label: s.done, primary: true, onTap: _busy ? null : widget.onClose),
      ],
    );
  }
}

class _SumRow extends StatelessWidget {
  const _SumRow({required this.label, required this.value, this.mono = false});

  final String label;
  final String value;
  final bool mono;

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(vertical: 10),
      decoration: const BoxDecoration(border: Border(bottom: BorderSide(color: UPalette.line))),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(label, style: uiStyle(12, color: UPalette.text3)),
          const SizedBox(width: 16),
          Expanded(
            child: Text(
              value,
              textAlign: TextAlign.right,
              style: mono
                  ? monoStyle(11.5, weight: FontWeight.w400, color: UPalette.text, height: 1.5)
                  : uiStyle(13, weight: FontWeight.w600),
            ),
          ),
        ],
      ),
    );
  }
}

// =============================== RECEIVE ==============================

class ReceiveSheet extends StatefulWidget {
  const ReceiveSheet({super.key, required this.onClose, required this.core, required this.address, this.network = 'mainnet', this.delivery = 'manual', this.details});

  final VoidCallback onClose;
  final WalletCore core;
  final String address;
  final String network;
  final String delivery;
  /// Контактная фраза и статус публикации (с главного экрана перенесены сюда).
  final Widget? details;

  @override
  State<ReceiveSheet> createState() => _ReceiveSheetState();
}

class _ReceiveSheetState extends State<ReceiveSheet> {
  S get s => AppLocale.of(context).s;
  Widget _scanSuffix(TextEditingController c) => qrInputSuffix(context, network: widget.network, controller: c);

  final TextEditingController _slate = TextEditingController();
  final TextEditingController _invoice = TextEditingController();
  final TextEditingController _invoicePayer = TextEditingController();
  final TextEditingController _pay = TextEditingController();
  String? _invoiceMode;
  String? _invoiceRoute;
  String? _invoicePeer;
  String? _invoiceChannelError;
  String? _invoiceDeliveryNotice;
  bool _invoiceLoading = false;
  List<Map<String, dynamic>> _invoiceContacts = const [];
  bool get _invoiceBackup => widget.delivery == 'grinmail';
  String _invoiceTr(String ru, String en) => AppLocale.of(context).lang == 'en' ? en : ru;
  String _invoiceShort(String text) => text.length <= 22 ? text : '${text.substring(0, 11)}…${text.substring(text.length - 7)}';

  Future<void> _loadInvoiceContacts() async {
    setState(() { _invoiceLoading = true; _invoiceChannelError = null; });
    try {
      final result = await widget.core.backupPaymentContacts();
      final mode = result['mode']?.toString(); final route = result['route']?.toString(); final entries = result['contacts'];
      if (!{'i2p_direct', 'nostr_i2p', 'nostr_direct'}.contains(mode) || route == null || route.isEmpty || entries is! List) throw StateError('invalid backup channel');
      final contacts = entries.whereType<Map>().map((e) => Map<String, dynamic>.from(e)).where((e) => e['address'] is String && (e['address'] as String).isNotEmpty).toList();
      if (mounted) setState(() { _invoiceMode = mode; _invoiceRoute = route; _invoiceContacts = contacts; _invoicePeer = null; _invoiceLoading = false; });
    } catch (e) { if (mounted) setState(() { _invoiceMode = null; _invoiceRoute = null; _invoiceContacts = const []; _invoicePeer = null; _invoiceChannelError = widget.core.describeError(e); _invoiceLoading = false; }); }
  }
  final TextEditingController _invoiceAnswer = TextEditingController();
  ReceiveResult? _received;
  InvoiceResult? _invoiceResult;
  String? _payAnswer;
  bool _busy = false;
  String? _error;
  List<WalletTx> _pendingInvoices = <WalletTx>[];
  List<WalletTx> _finalizedInvoices = <WalletTx>[];
  String? _invoiceToFinalize;
  String _jobPhase = '';

  @override
  void initState() {
    super.initState();
    _loadInvoices();
    if (_invoiceBackup) _loadInvoiceContacts();
  }

  Future<void> _loadInvoices() async {
    try {
      final all = (await widget.core.payments()).where((tx) => tx.kind == 'invoice').toList();
      final invoices = all.where((tx) => tx.stage == TxStage.waitingAnswer).toList();
      final finalized = all.where((tx) => tx.stage == TxStage.finalized).toList();
      if (!mounted) return;
      setState(() {
        _pendingInvoices = invoices;
        _finalizedInvoices = finalized;
        if (!invoices.any((tx) => tx.txId == _invoiceToFinalize)) {
          _invoiceToFinalize = invoices.length == 1 ? invoices.first.txId : null;
        }
      });
    } catch (e) {
      if (mounted) setState(() => _error = widget.core.describeError(e));
    }
  }

  @override
  void dispose() {
    _slate.dispose();
    _invoice.dispose();
    _invoicePayer.dispose();
    _pay.dispose();
    _invoiceAnswer.dispose();
    super.dispose();
  }

  Future<void> _receive() async {
    final String text = _slate.text.trim();
    if (text.isEmpty) return;
    if (looksLikeAddress(text)) {
      setState(() => _error = s.addressNotSlatepack);
      return;
    }
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      final ReceiveResult r = await widget.core.receive(_slate.text.trim());
      if (!mounted) return;
      setState(() {
        _received = r;
        _busy = false;
      });
    } catch (e) {
      if (!mounted) return;
      setState(() {
        _busy = false;
        _error = widget.core.describeError(e);
      });
    }
  }

  Future<void> _createInvoice() async {
    final int? nano = int.tryParse('');
    int amount;
    try {
      amount = grinToNano(_invoice.text);
    } on FormatException {
      setState(() => _error = s.amountRequired);
      return;
    }
    if (nano == null && amount <= 0) return;
    final payer = _invoicePayer.text.trim();
    if (_invoiceBackup) {
      final prefix = widget.network == 'floonet' ? 'tgrin1' : 'grin1';
      if (_invoiceLoading || _invoiceMode == null || _invoiceRoute == null || _invoicePeer == null || !payer.startsWith(prefix) || payer.length > 120 || !RegExp(r'^(grin1|tgrin1)[a-z0-9]{20,}$').hasMatch(payer)) {
        setState(() => _error = _invoiceTr('Укажите адрес кошелька плательщика и выберите его подписанный контакт.', 'Provide the payer wallet address and select the signed contact.'));
        return;
      }
    }
    setState(() { _busy = true; _error = null; _invoiceDeliveryNotice = null; });
    try {
      if (_invoiceBackup) {
        final fresh = await widget.core.backupPaymentContacts(); final list = fresh['contacts'];
        if (fresh['mode'] != _invoiceMode || fresh['route'] != _invoiceRoute || list is! List || !list.whereType<Map>().any((v) => v['address'] == _invoicePeer)) throw StateError(_invoiceTr('Канал или контакт изменился.', 'The channel or contact changed.'));
      }
      final intent = _invoiceBackup ? <String, String>{'peer': _invoicePeer!, 'mode': _invoiceMode!, 'route': _invoiceRoute!} : null;
      final InvoiceResult r = await widget.core.invoice(amountNano: amount, payer: _invoiceBackup ? payer : null, backupIntent: intent);
      if (!mounted) return;
      setState(() { _invoiceResult = r; });
      if (_invoiceBackup) {
        try {
          if (r.backupIntentError != null) throw StateError('invoice route fingerprint was not saved');
          await widget.core.deliverBackup(r.txId, peer: _invoicePeer!, mode: _invoiceMode!, route: _invoiceRoute!);
          if (mounted) setState(() => _invoiceDeliveryNotice = _invoiceTr('Счёт поставлен в очередь исходного канала; получение ещё не подтверждено.', 'Invoice queued on the selected channel; receipt is not confirmed.'));
        } catch (e) {
          if (mounted) setState(() => _invoiceDeliveryNotice = _invoiceTr('Счёт сохранён, но не поставлен в очередь: ', 'Invoice saved, but could not be queued: ') + widget.core.describeError(e));
        }
      }
      if (!mounted) return;
      setState(() { _busy = false; });
      await _loadInvoices();
      if (mounted && _pendingInvoices.any((tx) => tx.txId == r.txId)) {
        setState(() => _invoiceToFinalize = r.txId);
      }
    } catch (e) {
      if (!mounted) return;
      setState(() {
        _busy = false;
        _error = widget.core.describeError(e);
      });
    }
  }

  Future<void> _payInvoice() async {
    if (_pay.text.trim().isEmpty) return;
    setState(() {
      _busy = true;
      _error = null;
      _jobPhase = '';
    });
    try {
      final WalletJob job = await widget.core.payInvoiceJob(_pay.text.trim());
      final Map<String, dynamic> r = await job.wait(onProgress: (p) {
        if (mounted) setState(() => _jobPhase = p.phase);
      });
      if (!mounted) return;
      setState(() {
        _payAnswer = (r['answer'] ?? '').toString();
        _busy = false;
      });
    } catch (e) {
      if (!mounted) return;
      setState(() {
        _busy = false;
        _error = widget.core.describeError(e);
      });
    }
  }

  Future<void> _finalizeInvoice() async {
    final txId = _invoiceToFinalize;
    final answer = _invoiceAnswer.text.trim();
    if (txId == null || answer.isEmpty || _busy) return;
    setState(() { _busy = true; _error = null; _jobPhase = ''; });
    try {
      final job = await widget.core.finalizeJob(txId: txId, answer: answer);
      await job.wait(onProgress: (p) {
        if (mounted) setState(() => _jobPhase = p.phase);
      });
      if (!mounted) return;
      setState(() { _busy = false; _invoiceAnswer.clear(); _invoiceResult = null; });
      showToast(context, s.jobDone);
      await _loadInvoices();
    } catch (e) {
      if (mounted) setState(() { _busy = false; _error = widget.core.describeError(e); });
      // Финализация могла завершиться до сбоя рассылки. Считываем реальную
      // стадию, чтобы не предлагать повторную подпись готовой транзакции.
      await _loadInvoices();
    }
  }

  Future<void> _broadcastInvoice(String txId) async {
    if (_busy) return;
    setState(() { _busy = true; _error = null; _jobPhase = ''; });
    try {
      final job = await widget.core.broadcastJob(txId);
      await job.wait(onProgress: (p) {
        if (mounted) setState(() => _jobPhase = p.phase);
      });
      if (!mounted) return;
      setState(() => _busy = false);
      showToast(context, s.jobDone);
      await _loadInvoices();
    } catch (e) {
      if (mounted) setState(() { _busy = false; _error = widget.core.describeError(e); });
      await _loadInvoices();
    }
  }

  int _tab = 0;

  /// Один результат (slatepack + QR + копирование) под активной вкладкой.
  List<Widget> _result(S s, String text) => [
        const SizedBox(height: 10),
        UButton(label: s.copySlatepack, height: 36, onTap: () => copyText(context, text, s.copiedSlatepack)),
        const SizedBox(height: 6),
        SlatepackQrView(text: text, network: widget.network),
      ];

  Widget _tabBody(S s) {
    switch (_tab) {
      case 1:
        return Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            UTextField(label: s.invoiceAmount, controller: _invoice, hint: '0', fieldKey: const Key('invoice-amount'), onSubmitted: _busy ? null : _createInvoice),
            if (_invoiceBackup) ...[
              UTextField(label: _invoiceTr('Адрес кошелька плательщика', 'Payer wallet address'), controller: _invoicePayer, hint: s.recipientHint, fieldKey: const Key('invoice-payer'), suffix: _scanSuffix(_invoicePayer)),
              if (_invoiceLoading) const LinearProgressIndicator(minHeight: 3)
              else if (_invoiceChannelError != null) ...[
                Text(_invoiceChannelError!, style: uiStyle(11, color: UPalette.amber)),
                TextButton(onPressed: _loadInvoiceContacts, child: Text(_invoiceTr('Повторить', 'Retry'))),
              ] else ...[
                Text('${_invoiceTr('Канал', 'Channel')}: ${_invoiceMode ?? ''}', style: uiStyle(11, color: UPalette.text2)),
                if (_invoiceMode == 'nostr_direct') Text(_invoiceTr('Сервер видит ваш IP.', 'The server sees your IP.'), style: uiStyle(11, color: UPalette.amber)),
                DropdownButtonFormField<String>(key: const Key('invoice-backup-peer'), initialValue: _invoicePeer,
                  decoration: InputDecoration(labelText: _invoiceTr('Подписанный контакт плательщика', 'Payer signed contact')),
                  items: _invoiceContacts.map((c) { final address = c['address'].toString(); final name = (c['name'] ?? '').toString(); return DropdownMenuItem(value: address, child: Text('${name.isEmpty ? _invoiceShort(address) : name} · ${_invoiceShort(address)}', overflow: TextOverflow.ellipsis)); }).toList(),
                  onChanged: _busy ? null : (v) => setState(() => _invoicePeer = v), isExpanded: true),
                if (_invoiceContacts.isEmpty) Text(_invoiceTr('Добавьте подписанный адрес плательщика в переписке.', 'Add the payer’s signed address in Messages.'), style: uiStyle(11, color: UPalette.amber)),
                Text(_invoiceTr('Проверьте, что адрес кошелька и контакт принадлежат одному человеку.', 'Verify that the wallet and messaging addresses belong to the same person.'), style: uiStyle(10, color: UPalette.text3)),
              ],
            ],
            if (_invoiceDeliveryNotice != null) Text(_invoiceDeliveryNotice!, key: const Key('invoice-delivery-notice'), style: uiStyle(11, color: UPalette.amber)),
            const SizedBox(height: 10),
            UButton(label: s.createInvoice, height: 40, primary: true, onTap: _busy ? null : _createInvoice),
            if (_pendingInvoices.isNotEmpty) ...[
              const SizedBox(height: 14),
              Text(s.invoicePendingLabel, style: uiStyle(12, weight: FontWeight.w600)),
              DropdownButton<String>(
                key: const Key('invoice-select'),
                isExpanded: true,
                value: _invoiceToFinalize,
                hint: Text(s.invoiceSelectHint),
                items: _pendingInvoices.map((tx) => DropdownMenuItem<String>(
                  value: tx.txId,
                  child: Text('${nanoToGrin(tx.amountNano)} ${unitFor(widget.network)} · ${tx.txId}', overflow: TextOverflow.ellipsis),
                )).toList(),
                onChanged: _busy ? null : (v) => setState(() => _invoiceToFinalize = v),
              ),
              UTextField(label: s.invoiceAnswerLabel, controller: _invoiceAnswer, hint: s.invoiceAnswerLabel, fieldKey: const Key('invoice-answer'), suffix: _scanSuffix(_invoiceAnswer)),
              const SizedBox(height: 10),
              UButton(key: const Key('invoice-finalize'), label: s.invoiceFinalizeAction, height: 40, primary: true, onTap: _busy || _invoiceToFinalize == null ? null : _finalizeInvoice),
            ],
            for (final tx in _finalizedInvoices) ...[
              const SizedBox(height: 14),
              Text(s.invoiceBroadcastPending, style: uiStyle(12, weight: FontWeight.w600)),
              Text('${nanoToGrin(tx.amountNano)} ${unitFor(widget.network)} · ${tx.txId}', style: uiStyle(11)),
              UButton(key: Key('invoice-broadcast-${tx.txId}'), label: s.invoiceBroadcastRetry, height: 40, primary: true, onTap: _busy ? null : () => _broadcastInvoice(tx.txId)),
            ],
            if (_invoiceResult != null) ..._result(s, _invoiceResult!.slatepack),
          ],
        );
      case 2:
        return Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            UTextField(label: s.invoiceSlatepack, controller: _pay, hint: s.invoiceSlatepack, fieldKey: const Key('pay-invoice'), suffix: _scanSuffix(_pay)),
            const SizedBox(height: 10),
            UButton(label: s.payInvoice, height: 40, primary: true, onTap: _busy ? null : _payInvoice),
            if (_payAnswer != null) ..._result(s, _payAnswer!),
          ],
        );
      default:
        return Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            UTextField(label: s.receiveSlatepackLabel, controller: _slate, hint: s.recipientHint, fieldKey: const Key('receive-slate'), suffix: _scanSuffix(_slate)),
            const SizedBox(height: 10),
            UButton(label: s.receiveAction, height: 40, primary: true, onTap: _busy ? null : _receive),
            if (_received != null) ...[
              const SizedBox(height: 10),
              Text(s.receiveAnswerTitle, style: uiStyle(12, weight: FontWeight.w600, color: UPalette.text2)),
              ..._result(s, _received!.answer),
            ],
          ],
        );
    }
  }

  @override
  Widget build(BuildContext context) {
    final S s = AppLocale.of(context).s;
    final bool has = widget.address.isNotEmpty;
    return USheetCard(
      title: s.receiveTitle,
      onClose: widget.onClose,
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          // Адрес: QR слева, адрес и «Скопировать» справа — всё в одной карточке.
          Container(
            key: const Key('receive-wallet-address'),
            padding: const EdgeInsets.all(12),
            decoration: BoxDecoration(color: UPalette.fieldBg, border: Border.all(color: UPalette.lineStrong), borderRadius: BorderRadius.circular(14)),
            child: Row(
              crossAxisAlignment: CrossAxisAlignment.center,
              children: [
                if (has) ...[
                  AddressQrView(address: widget.address, size: MediaQuery.sizeOf(context).width < 420 ? 96 : 124),
                  const SizedBox(width: 14),
                ],
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.stretch,
                    children: [
                      Tooltip(
                        message: s.receiveCompatibleHint,
                        child: SelectableText(has ? widget.address : '—', style: monoStyle(11.5, weight: FontWeight.w400, height: 1.5), maxLines: 4),
                      ),
                      const SizedBox(height: 10),
                      UButton(
                        label: s.copyAddress,
                        icon: Icons.copy_rounded,
                        primary: true,
                        height: 38,
                        onTap: has ? () => copyText(context, widget.address, s.copiedAddress) : null,
                      ),
                    ],
                  ),
                ),
              ],
            ),
          ),
          if (widget.details != null) ...[
            const SizedBox(height: 10),
            widget.details!,
          ],
          const SizedBox(height: 14),
          USegmented(
            options: <String>[s.tabAccept, s.tabInvoice, s.tabPay],
            selected: _tab,
            expand: true,
            height: 34,
            fontSize: 13,
            onChanged: (int i) => setState(() {
              _tab = i;
              _error = null;
            }),
          ),
          const SizedBox(height: 12),
          if (_busy) ...[
            const SizedBox(height: 8),
            Text(_jobPhase.isEmpty ? s.loadingWallet : _jobPhase, style: uiStyle(11.5)),
            const SizedBox(height: 6),
            const LinearProgressIndicator(minHeight: 3),
          ],
          _tabBody(s),
          if (_error != null) ...[
            const SizedBox(height: 8),
            Text(s.humanError(_error!), style: uiStyle(11.5, color: UPalette.amber, height: 1.5)),
          ],
        ],
      ),
    );
  }
}

/// Прогресс долгой задачи ядра с отменой.
class JobProgressSheet extends StatefulWidget {
  const JobProgressSheet({super.key, required this.core, required this.job, required this.title, required this.onClose});

  final WalletCore core;
  final WalletJob job;
  final String title;
  final VoidCallback onClose;

  @override
  State<JobProgressSheet> createState() => _JobProgressSheetState();
}

class _JobProgressSheetState extends State<JobProgressSheet> {
  JobProgress? _progress;
  String? _error;

  @override
  void initState() {
    super.initState();
    _run();
  }

  Future<void> _run() async {
    try {
      await widget.job.wait(onProgress: (JobProgress p) {
        if (mounted) setState(() => _progress = p);
      });
      if (!mounted) return;
      widget.onClose();
    } catch (e) {
      if (!mounted) return;
      setState(() => _error = widget.core.describeError(e));
    }
  }

  @override
  Widget build(BuildContext context) {
    final S s = AppLocale.of(context).s;
    final JobProgress? p = _progress;
    return USheetCard(
      title: widget.title,
      onClose: widget.onClose,
      width: 460,
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          if (_error == null) ...[
            const LinearProgressIndicator(minHeight: 3, color: UPalette.mint, backgroundColor: UPalette.line),
            const SizedBox(height: 10),
            Text(p?.phase.isNotEmpty == true ? p!.phase : s.loadingWallet, style: uiStyle(12, weight: FontWeight.w600)),
            const SizedBox(height: 8),
            for (final String line in (p?.lines ?? const <String>[]).take(6))
              Padding(
                padding: const EdgeInsets.only(bottom: 4),
                child: Text(line, style: uiStyle(10.5, color: UPalette.text3), maxLines: 1, overflow: TextOverflow.ellipsis),
              ),
            const SizedBox(height: 10),
            UButton(
              label: s.jobCancel,
              height: 36,
              onTap: () async {
                await widget.job.cancel();
                if (mounted) widget.onClose();
              },
            ),
          ] else ...[
            Text(s.humanError(_error!), style: uiStyle(11, color: UPalette.amber, height: 1.5)),
            const SizedBox(height: 10),
            UButton(label: s.done, primary: true, onTap: widget.onClose),
          ],
        ],
      ),
    );
  }
}

// ============================== CHECKPOINT ============================

class VerificationSheet extends StatefulWidget {
  const VerificationSheet({
    super.key,
    required this.onClose,
    required this.status,
    required this.core,
    this.showTechInitially = false,
    this.onRefresh,
    this.future = false,
    this.onFutureChanged,
    this.onPeerSaved,
  });

  final VoidCallback onClose;
  final WalletStatus status;
  final WalletCore core;

  /// Experimental discovery setting; balance still uses the checkpoint.
  final bool future;
  final Future<bool> Function(bool)? onFutureChanged;
  final VoidCallback? onPeerSaved;
  final bool showTechInitially;
  final VoidCallback? onRefresh;

  @override
  State<VerificationSheet> createState() => _VerificationSheetState();
}

class _VerificationSheetState extends State<VerificationSheet> {
  bool _showTech = false;
  late bool _future;
  bool _savingFuture = false;

  @override
  void initState() {
    super.initState();
    _showTech = widget.showTechInitially;
    _future = widget.future;
  }

  Widget _row(String key, String value, {bool ok = false}) {
    return Container(
      padding: const EdgeInsets.symmetric(vertical: 5),
      decoration: const BoxDecoration(border: Border(top: BorderSide(color: UPalette.line))),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Expanded(child: Text(key, style: monoStyle(10.5, weight: FontWeight.w400, color: UPalette.text3, spacing: 0))),
          const SizedBox(width: 12),
          Flexible(
            child: Row(
              mainAxisSize: MainAxisSize.min,
              children: [
                if (ok) ...[
                  const Icon(Icons.check_rounded, size: 12, color: UPalette.mint),
                  const SizedBox(width: 4),
                ],
                Flexible(
                  child: Text(
                    value,
                    textAlign: TextAlign.right,
                    style: uiStyle(11.5, weight: FontWeight.w600, color: ok ? UPalette.mint : UPalette.text2),
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final S s = AppLocale.of(context).s;
    final WalletStatus status = widget.status;
    final WalletProof p = status.proof;
    final WalletBalance b = status.balance;
    final bool verified = p.verified && p.tipHeight != null;
    return USheetCard(
      title: s.verificationTitle,
      width: 460,
      // 0.98 не помещалось в окно диалога вместе с его отступами, и низ («Готово»)
      // обрезался вместо прокрутки. 0.9 — как у остальных листов.
      maxHeightFactor: 0.9,
      onClose: widget.onClose,
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Row(
            children: [
              Icon(verified ? Icons.check_circle_outline_rounded : Icons.sync_problem_rounded, size: 18, color: verified ? UPalette.mint : UPalette.amber),
              const SizedBox(width: 8),
              Expanded(
                child: Text(
                  verified
                      ? s.proofLine(p.tipHeight!, p.independentNets, p.tipAgeSeconds ?? 0)
                      : (p.hasSession ? s.staleProof : s.refreshNeeded),
                  style: uiStyle(12, weight: FontWeight.w600, color: UPalette.text),
                ),
              ),
            ],
          ),
          if (!p.balanceOk) ...[
            const SizedBox(height: 6),
            Text(
              '${s.balanceUnproven}${p.balanceProblem == null ? '' : ': ${p.balanceProblem}'}',
              style: uiStyle(11.5, weight: FontWeight.w600, color: UPalette.amber, height: 1.45),
            ),
          ],
          const SizedBox(height: 6),
          Text(
            '${s.available}: ${nanoToGrin(b.availableNano)} ${unitFor(status.network)} · ${s.totalLabel}: ${nanoToGrin(b.totalNano)} ${unitFor(status.network)}',
            style: uiStyle(11, color: UPalette.text3),
          ),
          const SizedBox(height: 10),
          Text(s.canonicalCaveat, style: uiStyle(11, color: UPalette.text3, height: 1.5)),
          if (!verified && widget.onRefresh != null) ...[
            const SizedBox(height: 12),
            UButton(label: s.refreshAction, primary: true, height: 38, onTap: widget.onRefresh),
          ],
          const SizedBox(height: 14),
          UButton(
            label: _showTech ? s.hideTechnicalDetails : s.showTechnicalDetails,
            dense: true,
            height: 36,
            onTap: () => setState(() => _showTech = !_showTech),
          ),
          if (_showTech) ...[
            const SizedBox(height: 10),
            _row('AVAILABLE', '${b.availableNano} nanogrin', ok: true),
            _row('RESERVED', '${b.reservedNano} nanogrin'),
            _row('INCOMING', '${b.incomingNano} nanogrin'),
            _row('IMMATURE', '${b.immatureNano} nanogrin'),
            _row('TOTAL', '${b.totalNano} nanogrin'),
            _row('TIP_HEIGHT', p.tipHeight == null ? '—' : formatHeight(p.tipHeight!)),
            _row('FRESHNESS', p.freshness),
            _row('CAN_SPEND', p.canSpend ? 'true' : 'false', ok: p.canSpend),
            _row('CURRENT_TIP_STATE', p.currentTipState ?? '—'),
            _row('CANONICAL_TIP', p.canonicalTip ?? '—'),
            _row('PEER_INDEPENDENCE', p.peerIndependence ?? '—'),
            _row('CHAIN_SUPPORT', p.chainSupport ?? '—'),
            _row('SYNC_STATUS', p.syncStatus ?? '—'),
            _row('SESSION', p.hasSession ? 'present' : 'none'),
            if (p.sessionPath != null) _row('SESSION_PATH', p.sessionPath!),
            const SizedBox(height: 6),
            Text(s.verificationNote, style: uiStyle(10.5, color: UPalette.text3, height: 1.5)),
          ],
          const SizedBox(height: 14),
          // Всё про проверку в одном окне: режим, чекпоинт, свой пир.
          if (widget.onFutureChanged != null)
            URowTile(
              title: s.future,
              hint: _future ? s.futureOnHint : s.futureOffHint,
              topBorder: false,
              trailing: USwitch(
                key: const Key('wallet-future-switch'),
                value: _future,
                onChanged: (bool v) async {
                  if (_savingFuture) return;
                  setState(() => _savingFuture = true);
                  final saved = await widget.onFutureChanged!(v);
                  if (!mounted) return;
                  setState(() { if (saved) _future = v; _savingFuture = false; });
                },
              ),
            ),
          const SizedBox(height: 8),
          if (_future) ...[
            Text(s.futureNoCheckpointNote, style: uiStyle(10.5, color: UPalette.violet, height: 1.5)),
            const SizedBox(height: 8),
          ],
          CheckpointSection(core: widget.core),
          const SizedBox(height: 8),
          UExpandSection(
            title: Text(s.peer, style: uiStyle(13, weight: FontWeight.w600)),
            initiallyExpanded: false,
            child: PeerSheet(onClose: () {}, core: widget.core, onSaved: widget.onPeerSaved, embedded: true),
          ),
          const SizedBox(height: 14),
          // Главная кнопка в окне одна — «Обновить», когда доказательство устарело.
          UButton(label: s.done, primary: verified, onTap: widget.onClose),
        ],
      ),
    );
  }
}

class CheckpointSection extends StatefulWidget {
  const CheckpointSection({super.key, required this.core});

  final WalletCore core;

  @override
  State<CheckpointSection> createState() => _CheckpointSectionState();
}

class _CheckpointSectionState extends State<CheckpointSection> {
  CheckpointInfo? _info;
  WalletJob? _job;
  JobProgress? _progress;
  bool _running = false;
  String? _error;

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    try {
      final CheckpointInfo info = await widget.core.checkpointInfo();
      if (!mounted) return;
      setState(() {
        _info = info;
        _error = null;
      });
    } catch (e) {
      if (!mounted) return;
      setState(() => _error = widget.core.describeError(e));
    }
  }

  Future<void> _start() async {
    setState(() {
      _running = true;
      _error = null;
    });
    try {
      final WalletJob job = await widget.core.ownCheckpointJob();
      _job = job;
      await job.wait(onProgress: (JobProgress p) {
        if (mounted) setState(() => _progress = p);
      });
      if (!mounted) return;
      await _load();
    } catch (e) {
      if (!mounted) return;
      setState(() => _error = widget.core.describeError(e));
    } finally {
      if (mounted) setState(() => _running = false);
    }
  }

  Future<void> _pause() async {
    await _job?.cancel();
    if (!mounted) return;
    setState(() {
      _running = false;
      _progress = null;
    });
    await _load();
  }

  Future<void> _setSource(String source) async {
    try {
      await widget.core.setCheckpointSource(source);
      await _load();
    } catch (e) {
      if (!mounted) return;
      setState(() => _error = widget.core.describeError(e));
    }
  }

  String _short(String? h) => h == null || h.length < 16 ? (h ?? '—') : '${h.substring(0, 8)}…${h.substring(h.length - 8)}';

  @override
  Widget build(BuildContext context) {
    final S s = AppLocale.of(context).s;
    final CheckpointInfo? info = _info;
    return Container(
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: UPalette.fieldBg,
        border: Border.all(color: info?.matches == false ? UPalette.red : UPalette.line),
        borderRadius: BorderRadius.circular(12),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Row(
            children: [
              const Icon(Icons.verified_user_outlined, size: 15, color: UPalette.mint),
              const SizedBox(width: 6),
              Expanded(child: Text(s.checkpointSection, style: uiStyle(12, weight: FontWeight.w600))),
              if (info != null)
                Container(
                  padding: const EdgeInsets.symmetric(horizontal: 7, vertical: 2),
                  decoration: BoxDecoration(color: UPalette.line, borderRadius: BorderRadius.circular(999)),
                  child: Text(
                    info.source == 'own' ? s.checkpointOwn : s.checkpointShipped,
                    style: uiStyle(10, color: info.source == 'own' ? UPalette.mint : UPalette.text2),
                  ),
                ),
            ],
          ),
          const SizedBox(height: 6),
          Text(s.checkpointExplain, style: uiStyle(10.5, color: UPalette.text3, height: 1.5)),
          if (info == null)
            const Padding(
              padding: EdgeInsets.symmetric(vertical: 8),
              child: LinearProgressIndicator(minHeight: 2, color: UPalette.mint, backgroundColor: UPalette.line),
            )
          else ...[
            const SizedBox(height: 8),
            _checkpointLine(s.checkpointShipped, info.shippedHeight, info.shippedHash, s),
            _checkpointLine(s.checkpointOwn, info.ownHeight, info.ownHash, s),
            if (info.matches == false) ...[
              const SizedBox(height: 6),
              Text(s.checkpointMismatch, style: uiStyle(11, weight: FontWeight.w600, color: UPalette.red, height: 1.5)),
            ] else if (info.matches == true) ...[
              const SizedBox(height: 6),
              Row(children: [
                const Icon(Icons.check_rounded, size: 13, color: UPalette.mint),
                const SizedBox(width: 4),
                Expanded(child: Text(s.checkpointMatches, style: uiStyle(10.5, color: UPalette.mint))),
              ]),
            ] else if (!info.ownBuilt) ...[
              const SizedBox(height: 4),
              Text(info.ownPaused ? s.checkpointPaused : s.checkpointNotBuilt, style: uiStyle(10.5, color: UPalette.text3)),
            ],
            if (info.ownBuilt) ...[
              const SizedBox(height: 8),
              USegmented(
                options: <String>[s.checkpointShipped, s.checkpointOwn],
                selected: info.source == 'own' ? 1 : 0,
                height: 28,
                fontSize: 12,
                onChanged: (int i) => _setSource(i == 1 ? 'own' : 'release'),
              ),
            ],
          ],
          if (_running) ...[
            const SizedBox(height: 8),
            LinearProgressIndicator(minHeight: 2, color: UPalette.mint, backgroundColor: UPalette.line),
            const SizedBox(height: 4),
            Text(
              _progress?.phase.isNotEmpty == true ? _progress!.phase : s.loadingWallet,
              style: uiStyle(10.5, color: UPalette.text2),
            ),
            const SizedBox(height: 4),
            UButton(label: s.checkpointPause, height: 32, dense: true, onTap: _pause),
          ] else if (info?.ownBuilt != true) ...[
            const SizedBox(height: 8),
            UButton(
              label: info?.ownPaused == true ? s.checkpointContinue : s.checkpointCreate,
              height: 34,
              dense: true,
              onTap: _start,
            ),
          ],
          if (_error != null) ...[
            const SizedBox(height: 6),
            Text(s.humanError(_error!), style: uiStyle(10.5, color: UPalette.amber, height: 1.5)),
          ],
        ],
      ),
    );
  }

  Widget _checkpointLine(String label, int? height, String? hash, S s) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 2),
      child: Row(
        children: [
          Text(label, style: uiStyle(10.5, color: UPalette.text3)),
          const SizedBox(width: 8),
          Expanded(
            child: Text(
              height == null ? '—' : '${s.checkpointHeight} ${formatHeight(height)} · ${_short(hash)}',
              textAlign: TextAlign.right,
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
              style: monoStyle(10, weight: FontWeight.w400, color: UPalette.text2, spacing: 0),
            ),
          ),
        ],
      ),
    );
  }
}

// ============================ CONTACT FEED ============================

class ContactFeedSheet extends StatelessWidget {
  const ContactFeedSheet({super.key, required this.onClose, required this.contact, this.onRename, this.onChat, this.onSend});

  final VoidCallback onClose;
  final UContact contact;
  final VoidCallback? onChat;
  final VoidCallback? onSend;

  /// Сохранить своё имя контакта; null — переименование недоступно.
  final ValueChanged<String>? onRename;

  Future<void> _rename(BuildContext context) async {
    final S s = AppLocale.of(context).s;
    final TextEditingController name = TextEditingController(text: contact.name);
    final String? result = await showDialog<String>(
      context: context,
      barrierColor: const Color(0xA604070B),
      builder: (BuildContext ctx) => AlertDialog(
        backgroundColor: UPalette.surface2,
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(20), side: const BorderSide(color: UPalette.lineStrong)),
        title: Text(s.renameContact, style: uiStyle(16, weight: FontWeight.w600)),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Text(s.renameContactHint, style: uiStyle(12, color: UPalette.text2, height: 1.5)),
            const SizedBox(height: 12),
            UTextField(label: s.renameContact, controller: name, onSubmitted: () => Navigator.of(ctx).pop(name.text)),
          ],
        ),
        actions: [
          TextButton(onPressed: () => Navigator.of(ctx).pop(), child: Text(s.cancel, style: uiStyle(13, color: UPalette.text2))),
          TextButton(onPressed: () => Navigator.of(ctx).pop(name.text), child: Text(s.save, style: uiStyle(13, color: UPalette.mint))),
        ],
      ),
    );
    disposeLater(name);
    if (result != null && result.trim().isNotEmpty) onRename?.call(result.trim());
  }

  @override
  Widget build(BuildContext context) {
    final AppLocale locale = AppLocale.of(context);
    final S s = locale.s;
    return USheetCard(
      title: contact.nameFor(locale.lang),
      width: 460,
      onClose: onClose,
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Row(
            children: [
              Container(
                width: 40,
                height: 40,
                alignment: Alignment.center,
                decoration: BoxDecoration(
                  color: contact.background,
                  border: Border.all(color: contact.border),
                  borderRadius: BorderRadius.circular(12),
                ),
                child: Text(contact.initial, style: uiStyle(15, weight: FontWeight.w700, color: contact.color)),
              ),
              const SizedBox(width: 11),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(contact.shortAddress, style: monoStyle(11.5, weight: FontWeight.w400, color: UPalette.text2, spacing: 0)),
                    const SizedBox(height: 3),
                    Row(
                      children: [
                        Icon(
                          contact.verified ? Icons.verified : Icons.gpp_bad_outlined,
                          size: 13,
                          color: contact.verified ? UPalette.mint : UPalette.amber,
                        ),
                        const SizedBox(width: 4),
                        Text(
                          contact.verified
                              ? (locale.lang == 'en' ? 'Code compared by user' : 'Код сверён пользователем')
                              : (locale.lang == 'en' ? 'Code not compared' : 'Код не сверён'),
                          style: uiStyle(10, color: contact.verified ? UPalette.mint : UPalette.amber),
                        ),
                      ],
                    ),
                  ],
                ),
              ),
              if (onRename != null)
                UIconButton(icon: Icons.edit_outlined, tooltip: s.renameContact, onTap: () => _rename(context)),
            ],
          ),
          const SizedBox(height: 14),
          Row(children: [
            Expanded(child: UButton(key: const Key('contact-chat'), label: locale.lang == 'en' ? 'Message' : 'Написать', icon: Icons.chat_bubble_outline, onTap: onChat)),
            const SizedBox(width: 8),
            Expanded(child: UButton(key: const Key('contact-send'), label: locale.lang == 'en' ? 'Send' : 'Отправить', icon: Icons.north_east, primary: true, onTap: onSend)),
          ]),
          if (onChat == null) Text(locale.lang == 'en' ? 'No messenger address is saved for this contact.' : 'Для контакта не сохранён адрес переписки.', style: uiStyle(10, color: UPalette.text3)),
          const SizedBox(height: 14),
          if (contact.feed.isEmpty)
            Text(s.noFeed, style: uiStyle(11, color: UPalette.text3))
          else
            for (final UFeedItem item in contact.feed)
              Container(
                padding: const EdgeInsets.symmetric(vertical: 9),
                decoration: const BoxDecoration(border: Border(top: BorderSide(color: UPalette.line))),
                child: Row(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Icon(
                      item.amount != null ? Icons.payments_outlined : Icons.chat_bubble_outline_rounded,
                      size: 16,
                      color: item.amount != null ? UPalette.mint : UPalette.text3,
                    ),
                    const SizedBox(width: 9),
                    Expanded(
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text(item.titleFor(locale.lang), style: uiStyle(12, weight: FontWeight.w600)),
                          const SizedBox(height: 1),
                          Text(item.subtitleFor(locale.lang), style: uiStyle(10, color: UPalette.text3)),
                        ],
                      ),
                    ),
                    if (item.amount != null)
                      Text(
                        item.amount!,
                        style: monoStyle(11.5, weight: FontWeight.w600, color: item.outgoing ? UPalette.text : UPalette.mint, spacing: -0.2),
                      ),
                  ],
                ),
              ),
          const SizedBox(height: 12),
          Text(
            s.feedNote,
            style: uiStyle(10, color: UPalette.text3, height: 1.5),
          ),
          const SizedBox(height: 14),
          UButton(label: s.closeAction, primary: true, onTap: onClose),
        ],
      ),
    );
  }
}

// =============================== SETTINGS =============================

class SettingsSheet extends StatefulWidget {
  const SettingsSheet({
    super.key,
    required this.onClose,
    required this.profile,
    required this.networkLabel,
    required this.futureEnabled,
    required this.onVerification,
    required this.onRename,
    required this.core,
  });

  final WalletCore core;
  final VoidCallback onClose;
  final String profile;
  final String networkLabel;
  final bool futureEnabled;

  /// Окно «Проверка»: статус, режим, чекпоинт и свой пир — всё там.
  final VoidCallback onVerification;

  /// Новое название кошелька (папка профиля на устройстве).
  final ValueChanged<String> onRename;

  @override
  State<SettingsSheet> createState() => _SettingsSheetState();
}

class _SettingsSheetState extends State<SettingsSheet> {
  S get s => AppLocale.of(context).s;


  Widget _group(String text) {
    return Padding(
      padding: const EdgeInsets.only(top: 10, bottom: 2),
      child: SectionLabel(text),
    );
  }

  Widget _smallButton(String label, VoidCallback onTap) {
    return UButton(label: label, dense: true, height: 36, expand: false, onTap: onTap);
  }

  Future<void> _renameWallet() async {
    final TextEditingController name = TextEditingController(text: widget.profile);
    final String? result = await showDialog<String>(
      context: context,
      barrierColor: const Color(0xA604070B),
      builder: (BuildContext ctx) => AlertDialog(
        backgroundColor: UPalette.surface2,
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(20), side: const BorderSide(color: UPalette.lineStrong)),
        title: Text(s.renameWalletTitle, style: uiStyle(16, weight: FontWeight.w600)),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            Text(s.renameWalletHint, style: uiStyle(12, color: UPalette.text2, height: 1.5)),
            const SizedBox(height: 12),
            UTextField(label: s.loginLabel, controller: name, onSubmitted: () => Navigator.of(ctx).pop(name.text)),
          ],
        ),
        actions: [
          TextButton(onPressed: () => Navigator.of(ctx).pop(), child: Text(s.cancel, style: uiStyle(13, color: UPalette.text2))),
          TextButton(onPressed: () => Navigator.of(ctx).pop(name.text), child: Text(s.save, style: uiStyle(13, color: UPalette.mint))),
        ],
      ),
    );
    disposeLater(name);
    final String v = (result ?? '').trim();
    if (v.isNotEmpty && v != widget.profile) widget.onRename(v);
  }

  AlertDialog _dialog(String title, List<Widget> content, List<Widget> actions) => AlertDialog(
        backgroundColor: UPalette.surface2,
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(20), side: const BorderSide(color: UPalette.lineStrong)),
        title: Text(title, style: uiStyle(16, weight: FontWeight.w600)),
        content: SizedBox(
          width: 380,
          child: Column(mainAxisSize: MainAxisSize.min, crossAxisAlignment: CrossAxisAlignment.stretch, children: content),
        ),
        actions: actions,
      );

  /// Seed показывается только после верного пароля; окно не хранит фразу после закрытия.
  Future<void> _askPasswordForSeed(BuildContext context) async {
    final TextEditingController pass = TextEditingController();
    String? error;
    String? phrase;
    await showDialog<void>(
      context: context,
      barrierColor: const Color(0xA604070B),
      builder: (BuildContext ctx) => StatefulBuilder(
        builder: (BuildContext ctx, StateSetter set) {
          Future<void> submit() async {
            if (pass.text.isEmpty) {
              set(() => error = s.enterPassword);
              return;
            }
            try {
              final String p = await widget.core.showPhrase(pass.text);
              set(() {
                phrase = p;
                error = null;
              });
            } catch (_) {
              set(() => error = s.wrongPassword);
            }
          }

          if (phrase != null) {
            final List<String> words = phrase!.split(' ');
            return _dialog(
              s.seedShownTitle,
              [
                Text(s.seedShownNote, style: uiStyle(12, color: UPalette.text2, height: 1.5)),
                const SizedBox(height: 12),
                Wrap(
                  spacing: 8,
                  runSpacing: 8,
                  children: [
                    for (int i = 0; i < words.length; i++)
                      Container(
                        padding: const EdgeInsets.symmetric(horizontal: 9, vertical: 5),
                        decoration: BoxDecoration(color: UPalette.fieldBg, border: Border.all(color: UPalette.lineStrong), borderRadius: BorderRadius.circular(9)),
                        child: SelectableText.rich(TextSpan(children: [
                          TextSpan(text: '${i + 1} ', style: monoStyle(11, weight: FontWeight.w400, color: UPalette.text3, spacing: 0)),
                          TextSpan(text: words[i], style: monoStyle(13, weight: FontWeight.w500, spacing: 0)),
                        ])),
                      ),
                  ],
                ),
              ],
              [TextButton(onPressed: () => Navigator.of(ctx).pop(), child: Text(s.close, style: uiStyle(13, color: UPalette.mint)))],
            );
          }
          return _dialog(
            s.confirmPasswordTitle,
            [
              Text(s.confirmPasswordNote, style: uiStyle(12, color: UPalette.text2, height: 1.5)),
              const SizedBox(height: 12),
              UTextField(label: s.password, controller: pass, obscure: true, autocorrect: false, enableSuggestions: false, onSubmitted: submit),
              if (error != null) ...[
                const SizedBox(height: 8),
                Text(error!, style: uiStyle(11.5, color: UPalette.amber)),
              ],
            ],
            [
              TextButton(onPressed: () => Navigator.of(ctx).pop(), child: Text(s.cancel, style: uiStyle(13, color: UPalette.text2))),
              TextButton(onPressed: submit, child: Text(s.show, style: uiStyle(13, color: UPalette.mint))),
            ],
          );
        },
      ),
    );
    disposeLater(pass);
    phrase = null;
  }

  Future<void> _changePassword(BuildContext context) async {
    final TextEditingController old = TextEditingController();
    final TextEditingController next = TextEditingController();
    final TextEditingController again = TextEditingController();
    String? error;
    bool changed = false;
    await showDialog<void>(
      context: context,
      barrierColor: const Color(0xA604070B),
      builder: (BuildContext ctx) => StatefulBuilder(
        builder: (BuildContext ctx, StateSetter set) {
          Future<void> submit() async {
            if (next.text.characters.length < 8) {
              set(() => error = s.passwordTooShort);
              return;
            }
            if (next.text != again.text) {
              set(() => error = s.passwordsDiffer);
              return;
            }
            try {
              await widget.core.changePassword(old.text, next.text);
              changed = true;
              if (ctx.mounted) Navigator.of(ctx).pop();
            } catch (_) {
              set(() => error = s.wrongPassword);
            }
          }

          return _dialog(
            s.password,
            [
              UTextField(label: s.oldPassword, controller: old, obscure: true, autocorrect: false, enableSuggestions: false),
              const SizedBox(height: 10),
              UTextField(label: s.newPassword, controller: next, obscure: true, autocorrect: false, enableSuggestions: false),
              const SizedBox(height: 10),
              UTextField(label: s.repeatPassword, controller: again, obscure: true, autocorrect: false, enableSuggestions: false, onSubmitted: submit),
              if (error != null) ...[
                const SizedBox(height: 8),
                Text(error!, style: uiStyle(11.5, color: UPalette.amber)),
              ],
            ],
            [
              TextButton(onPressed: () => Navigator.of(ctx).pop(), child: Text(s.cancel, style: uiStyle(13, color: UPalette.text2))),
              TextButton(onPressed: submit, child: Text(s.save, style: uiStyle(13, color: UPalette.mint))),
            ],
          );
        },
      ),
    );
    disposeLater(old);
    disposeLater(next);
    disposeLater(again);
    if (changed && mounted) showToast(this.context, s.passwordChanged);
  }

  @override
  Widget build(BuildContext context) {
    return USheetCard(
      title: s.settings,
      width: 540,
      padding: const EdgeInsets.all(18),
      maxHeightFactor: 0.98,
      onClose: widget.onClose,
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          // --- Кошелёк
          _group(s.groupWallet),
          URowTile(
            title: s.loginLabel,
            hint: '${widget.profile} · ${widget.networkLabel} · ${s.profileOnDevice}',
            topBorder: false,
            trailing: _smallButton(s.renameProfile, _renameWallet),
          ),
          // Проверка, Tor и каналы переписки вынесены значками в шапку кошелька:
          // здесь остаются только название, пароль и seed-фраза.
          // --- Безопасность
          ...[
            _group(s.groupSecurity),
            URowTile(
              title: s.password,
              hint: s.passwordHintSettings,
              topBorder: false,
              trailing: _smallButton(s.change, () => _changePassword(context)),
            ),
            URowTile(
              title: s.seedSettings,
              hint: s.seedSettingsHint,
              trailing: _smallButton(s.show, () => _askPasswordForSeed(context)),
            ),
          ],
          // Версия и подпись видны и в релизной сборке (раньше это была пометка «прототип»).
          Container(
              margin: const EdgeInsets.only(top: 8),
              padding: const EdgeInsets.only(top: 8),
              decoration: const BoxDecoration(
                border: Border(top: BorderSide(color: UPalette.line)),
              ),
              child: Text(
                s.prototypeFooter,
                textAlign: TextAlign.center,
                style: uiStyle(12, color: UPalette.text3),
              ),
            ),
        ],
      ),
    );
  }
}

// =============================== FUTURE ===============================

// ================================ PEER ================================

class PeerSheet extends StatefulWidget {
  const PeerSheet({super.key, required this.onClose, required this.core, this.onSaved, this.embedded = false});

  final VoidCallback onClose;

  /// Внутри окна «Проверка»: без своей рамки, окно после сохранения не закрывается.
  final bool embedded;
  final WalletCore core;
  final VoidCallback? onSaved;

  @override
  State<PeerSheet> createState() => _PeerSheetState();
}

class _PeerSheetState extends State<PeerSheet> {
  S get s => AppLocale.of(context).s;

  final TextEditingController _url = TextEditingController();
  bool _busy = false;
  String? _error;

  @override
  void dispose() {
    _url.dispose();
    super.dispose();
  }

  Future<void> _connect() async {
    final String peer = _url.text.trim();
    if (peer.isEmpty) {
      showToast(context, s.peerRequired);
      return;
    }
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      await widget.core.setExtraPeers(<String>[peer]);
      if (!mounted) return;
      widget.onSaved?.call();
      showToast(context, s.peerSaved);
      if (widget.embedded) {
        setState(() => _busy = false);
      } else {
        widget.onClose();
      }
    } catch (e) {
      if (!mounted) return;
      setState(() {
        _busy = false;
        _error = widget.core.describeError(e);
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    final S s = AppLocale.of(context).s;
    final Widget body = Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Text(s.peerNote, style: uiStyle(11.5, color: UPalette.text2, height: 1.6)),
          const SizedBox(height: 14),
          UTextField(
            label: s.peerAddress,
            controller: _url,
            hint: 'host:3414',
            fieldKey: const Key('peer-url'),
          ),
          const SizedBox(height: 12),
          if (_error != null) ...[
            Text(s.humanError(_error!), style: uiStyle(11, color: UPalette.amber, height: 1.5)),
            const SizedBox(height: 10),
          ],
          UButton(label: s.connect, primary: true, onTap: _busy ? null : _connect),
          const SizedBox(height: 10),
          Text(s.peerFootnote, style: uiStyle(10.5, color: UPalette.text3, height: 1.5)),
        ],
      );
    if (widget.embedded) return body;
    return USheetCard(title: s.peerTitle, onClose: widget.onClose, child: body);
  }
}

// ========================== INCOMING PENDING ==========================

/// Итог диалога платежа, ждущего ручного решения.
enum PendingOutcome { accepted, declined, expired }

/// Диалог поверх любого экрана: незнакомый отправитель ждёт «Да».
///
/// Открывается по `tor.pending`, пока `tor.status.pending_count > 0`.
/// Для Foreign API (grin-wallet / Grin++) идёт обратный отсчёт: если он
/// кончился, диалог закрывается ([PendingOutcome.expired]), а платёж
/// остаётся во входящих для ручного приёма.
class PendingPaymentDialog extends StatefulWidget {
  const PendingPaymentDialog({
    super.key,
    required this.core,
    required this.pending,
    this.network = 'mainnet',
  });

  final WalletCore core;
  final PendingPayment pending;
  final String network;

  @override
  State<PendingPaymentDialog> createState() => _PendingPaymentDialogState();
}

class _PendingPaymentDialogState extends State<PendingPaymentDialog> {
  final TextEditingController _name = TextEditingController();
  Timer? _tick;
  late int _left;
  bool _addToBook = false;
  bool _busy = false;
  String? _error;

  S get s => AppLocale.of(context).s;

  @override
  void initState() {
    super.initState();
    final int seconds = widget.pending.expiresInSeconds;
    _left = seconds < 0 ? 0 : seconds;
    // Мессенджер не удерживает соединение — там отсчёта нет.
    _resumeCountdown();
  }

  @override
  void dispose() {
    _tick?.cancel();
    _name.dispose();
    super.dispose();
  }

  Future<void> _decide(bool accept) async {
    if (_busy) return;
    // Пока решение в пути, обратный отсчёт не должен закрыть диалог.
    _tick?.cancel();
    _tick = null;
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      await widget.core.torDecide(
        slateId: widget.pending.slateId,
        accept: accept,
        addContact: accept && _addToBook && (widget.pending.overMessenger ? widget.pending.messengerPeer != null : widget.pending.from != null),
        name: _name.text.trim(),
      );
      if (!mounted) return;
      Navigator.of(context).pop(accept ? PendingOutcome.accepted : PendingOutcome.declined);
    } catch (e) {
      if (!mounted) return;
      setState(() {
        _busy = false;
        _error = widget.core.describeError(e);
      });
      _resumeCountdown();
    }
  }

  /// Возобновляет отсчёт после неудачной попытки (если время ещё есть).
  void _resumeCountdown() {
    if (!widget.pending.overForeignApi || _left <= 0 || _tick != null) return;
    _tick = Timer.periodic(const Duration(seconds: 1), (Timer t) {
      if (!mounted) return;
      if (_left <= 1) {
        t.cancel();
        Navigator.of(context).pop(PendingOutcome.expired);
        return;
      }
      setState(() => _left -= 1);
    });
  }

  @override
  Widget build(BuildContext context) {
    final S s = AppLocale.of(context).s;
    final PendingPayment p = widget.pending;
    final String unit = unitFor(widget.network);
    final String amount = '${formatGrin6(p.amountNano)} $unit';
    final String? from = p.from ?? p.messengerPeer;
    return USheetCard(
      title: s.incomingPaymentTitle(amount),
      width: 460,
      onClose: _busy ? () {} : () => _decide(false),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          if (from != null) ...[
            Text(
              s.incomingPaymentFrom(shortAddress(from)),
              style: monoStyle(12, weight: FontWeight.w400, color: UPalette.text2, height: 1.5),
            ),
            const SizedBox(height: 4),
          ],
          Text(
            p.overMessenger && p.messengerPeer != null ? s.sourceSigned : s.sourceClaimed,
            style: uiStyle(11, color: p.overMessenger && p.messengerPeer != null ? UPalette.mint : UPalette.text3, height: 1.5),
          ),
          if (p.overForeignApi && p.expiresInSeconds > 0) ...[
            const SizedBox(height: 10),
            Row(
              children: [
                Icon(
                  Icons.timer_outlined,
                  size: 15,
                  color: _left <= 10 ? UPalette.amber : UPalette.text3,
                ),
                const SizedBox(width: 6),
                Text(
                  s.secondsLeft(_left),
                  style: uiStyle(11.5, weight: FontWeight.w600, color: _left <= 10 ? UPalette.amber : UPalette.text2),
                ),
              ],
            ),
          ],
          const SizedBox(height: 14),
          if (from == null)
            Text(s.senderUnknown, style: uiStyle(11, color: UPalette.text3, height: 1.5))
          else if (!p.overMessenger || p.messengerPeer != null) ...[
            UTextField(
              label: s.contactNameLabel,
              controller: _name,
              hint: s.contactNameHint,
              fieldKey: const Key('pending-contact-name'),
            ),
            const SizedBox(height: 12),
            UCheckline(
              title: s.addContactAndAuto,
              subtitle: p.overMessenger ? s.addContactAndAutoHint : s.addUnverifiedContactHint,
              value: _addToBook,
              onChanged: (bool v) => setState(() => _addToBook = v),
            ),
          ],
          if (p.feeNano != null) ...[
            const SizedBox(height: 10),
            Text(s.feeLine('${nanoToGrin(p.feeNano!)} $unit'), style: uiStyle(10.5, color: UPalette.text3)),
          ],
          if (_error != null) ...[
            const SizedBox(height: 10),
            Text(s.humanError(_error!), style: uiStyle(11, color: UPalette.amber, height: 1.5)),
          ],
          const SizedBox(height: 16),
          Row(
            children: [
              Expanded(
                child: UButton(
                  key: const Key('pending-decline'),
                  label: s.declineAction,
                  height: 44,
                  onTap: _busy ? null : () => _decide(false),
                ),
              ),
              const SizedBox(width: 10),
              Expanded(
                child: UButton(
                  key: const Key('pending-accept'),
                  label: s.receiveAction,
                  primary: true,
                  height: 44,
                  onTap: _busy ? null : () => _decide(true),
                ),
              ),
            ],
          ),
        ],
      ),
    );
  }
}

// =============================== INBOX ================================

/// Входящие из `tor.inbox`: платежи принимаются вручную (S2 + QR),
/// счета оплачиваются тем же `wallet.pay_invoice`.
class InboxSheet extends StatelessWidget {
  const InboxSheet({super.key, required this.core, required this.onClose, this.network = 'mainnet'});

  final WalletCore core;
  final VoidCallback onClose;
  final String network;

  @override
  Widget build(BuildContext context) {
    return USheetCard(
      title: AppLocale.of(context).s.inboxTitle,
      width: 480,
      onClose: onClose,
      child: InboxPanel(core: core, network: network),
    );
  }
}

/// Блок «Входящие» на экране кошелька: заголовок со счётчиком, раскрывается.
class InboxCard extends StatefulWidget {
  const InboxCard({super.key, required this.core, required this.network, this.initiallyExpanded = false});

  final WalletCore core;
  final String network;
  /// На широком главном экране список открыт сразу (под «Отправить / Получить»).
  final bool initiallyExpanded;

  @override
  State<InboxCard> createState() => _InboxCardState();
}

class _InboxCardState extends State<InboxCard> {
  int _count = 0;

  @override
  Widget build(BuildContext context) {
    final S s = AppLocale.of(context).s;
    return UCard(
      padding: const EdgeInsets.fromLTRB(16, 6, 16, 8),
      child: UExpandSection(
        title: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(Icons.move_to_inbox_rounded, size: 17, color: _count > 0 ? UPalette.mint : UPalette.text3),
            const SizedBox(width: 8),
            Flexible(child: Text(s.inboxCardTitle, maxLines: 1, overflow: TextOverflow.ellipsis, style: uiStyle(14, weight: FontWeight.w600))),
          ],
        ),
        count: _count,
        initiallyExpanded: widget.initiallyExpanded,
        child: InboxPanel(
          core: widget.core,
          network: widget.network,
          onCount: (int n) {
            if (mounted && n != _count) setState(() => _count = n);
          },
        ),
      ),
    );
  }
}

class InboxPanel extends StatefulWidget {
  const InboxPanel({super.key, required this.core, this.network = 'mainnet', this.onCount});

  final WalletCore core;
  final String network;
  final ValueChanged<int>? onCount;

  @override
  State<InboxPanel> createState() => _InboxPanelState();
}

class _InboxPanelState extends State<InboxPanel> {
  Timer? _poll;

  S get s => AppLocale.of(context).s;

  List<InboxItem> _items = const <InboxItem>[];
  bool _loading = true;
  bool _busy = false;
  String? _error;
  ReceiveResult? _received;
  String? _payAnswer;
  String? _deliveryNotice;

  @override
  void initState() {
    super.initState();
    _load();
    // На экране кошелька блок сам подтягивает новые входящие.
    if (widget.onCount != null) {
      _poll = Timer.periodic(const Duration(seconds: 20), (Timer _) {
        if (mounted && !_busy) _load(silent: true);
      });
    }
  }

  @override
  void dispose() {
    _poll?.cancel();
    super.dispose();
  }

  Future<void> _load({bool silent = false}) async {
    if (!silent) {
      setState(() {
        _loading = true;
        _error = null;
      });
    }
    try {
      final List<InboxItem> items = await widget.core.torInbox();
      if (!mounted) return;
      setState(() {
        _items = items;
        _loading = false;
      });
      widget.onCount?.call(items.length);
    } catch (e) {
      if (!mounted || silent) return;
      setState(() {
        _loading = false;
        _error = widget.core.describeError(e);
      });
    }
  }

  Future<void> _accept(InboxItem item) async {
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      final ReceiveResult r = await widget.core.receiveInbox(item.file);
      if (!mounted) return;
      setState(() {
        _received = r;
        _busy = false;
        _deliveryNotice = r.deliveryQueued == null ? null : r.deliveryQueued!
          ? (AppLocale.of(context).lang == 'en' ? 'Response queued on the original messaging route; receipt is not confirmed.' : 'Ответ поставлен в очередь исходного канала; получение ещё не подтверждено.')
          : (AppLocale.of(context).lang == 'en' ? 'Response was saved but could not be queued: ' : 'Ответ сохранён, но не поставлен в очередь: ') + (r.deliveryError ?? '');
      });
      showToast(context, s.inboxAccepted);
      await _load();
    } catch (e) {
      if (!mounted) return;
      setState(() {
        _busy = false;
        _error = widget.core.describeError(e);
      });
    }
  }

  Future<void> _payInvoice(InboxItem item) async {
    final en = AppLocale.of(context).lang == 'en';
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      if (item.viaBackup) await widget.core.validateBackupInboxInvoice(item.file);
      final WalletJob job = await widget.core.payInvoiceInboxJob(item.file);
      final Map<String, dynamic> r = await job.wait();
      String? notice;
      if (item.viaBackup) {
        try {
          if (r['backup_intent_error'] != null) throw StateError('invoice route fingerprint was not saved');
          final id = (r['tx_id'] ?? '').toString();
          if (id.isEmpty) throw StateError('missing payment id');
          await widget.core.deliverBackupInboxInvoice(item.file, id);
          notice = en ? 'Invoice response queued on the original route; receipt is not confirmed.' : 'Ответ на счёт поставлен в очередь исходного канала; получение ещё не подтверждено.';
        } catch (e) {
          notice = (en ? 'Invoice response was saved but could not be queued: ' : 'Ответ на счёт сохранён, но не поставлен в очередь: ') + widget.core.describeError(e);
        }
      }
      if (!mounted) return;
      setState(() {
        _payAnswer = (r['answer'] ?? '').toString();
        _deliveryNotice = notice;
        _busy = false;
      });
      showToast(context, s.inboxInvoicePaid);
      await _load();
    } catch (e) {
      if (!mounted) return;
      setState(() {
        _busy = false;
        _error = widget.core.describeError(e);
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    final S s = AppLocale.of(context).s;
    final String unit = unitFor(widget.network);
    return Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          if (_deliveryNotice != null) ...[
            Text(_deliveryNotice!, key: const Key('inbox-delivery-notice'), style: uiStyle(11, color: UPalette.amber)),
            const SizedBox(height: 8),
          ],
          if (_received != null && _received!.handoverSlatepack.isNotEmpty) ...[
            Text(s.receiveAnswerTitle, style: uiStyle(11, weight: FontWeight.w600, color: UPalette.text2)),
            const SizedBox(height: 6),
            UButton(
              label: s.copySlatepack,
              height: 32,
              onTap: () => copyText(context, _received!.handoverSlatepack, s.copiedSlatepack),
            ),
            const SizedBox(height: 6),
            SlatepackQrView(text: _received!.handoverSlatepack, network: widget.network),
            const SizedBox(height: 6),
            Text(s.inboxS2Hint, style: uiStyle(10.5, color: UPalette.text3, height: 1.5)),
            const Divider(height: 22, color: UPalette.line),
          ],
          if (_payAnswer != null && _payAnswer!.isNotEmpty) ...[
            UButton(
              label: s.copySlatepack,
              height: 32,
              onTap: () => copyText(context, _payAnswer!, s.copiedSlatepack),
            ),
            const SizedBox(height: 6),
            SlatepackQrView(text: _payAnswer!, network: widget.network),
            const Divider(height: 22, color: UPalette.line),
          ],
          if (_loading)
            const Padding(
              padding: EdgeInsets.all(14),
              child: Center(child: CircularProgressIndicator(color: UPalette.mint)),
            )
          else if (_items.isEmpty)
            Padding(
              padding: const EdgeInsets.symmetric(vertical: 14),
              child: Text(s.inboxEmpty, textAlign: TextAlign.center, style: uiStyle(11.5, color: UPalette.text3, height: 1.5)),
            )
          else
            for (final InboxItem item in _items)
              _InboxRow(
                key: ValueKey<String>(item.file),
                item: item,
                unit: unit,
                busy: _busy,
                onAccept: () => _accept(item),
                onPay: () => _payInvoice(item),
              ),
          if (_error != null) ...[
            const SizedBox(height: 10),
            Text(s.humanError(_error!), style: uiStyle(11, color: UPalette.amber, height: 1.5)),
          ],
          const SizedBox(height: 10),
          UButton(label: s.inboxRefresh, height: 36, onTap: _busy ? null : _load),
        ],
    );
  }
}

class _InboxRow extends StatelessWidget {
  const _InboxRow({
    super.key,
    required this.item,
    required this.unit,
    required this.busy,
    required this.onAccept,
    required this.onPay,
  });

  final InboxItem item;
  final String unit;
  final bool busy;
  final VoidCallback onAccept;
  final VoidCallback onPay;

  @override
  Widget build(BuildContext context) {
    final S s = AppLocale.of(context).s;
    final bool invoice = item.isInvoice;
    final String? from = item.from;
    final int? age = item.receivedAt == null ? null : DateTime.now().difference(item.receivedAt!).inSeconds;
    final List<String> bits = <String>[
      if (from != null && from.isNotEmpty) '${s.inboxFromLabel} ${shortAddress(from)}',
      if (age != null) '${s.inboxReceivedLabel}: ${s.formatAge(age)} ${s.ago}',
    ];
    return Container(
      padding: const EdgeInsets.symmetric(vertical: 9),
      decoration: const BoxDecoration(border: Border(top: BorderSide(color: UPalette.line))),
      child: Row(
        children: [
          UIconBadge(
            icon: invoice ? Icons.request_quote_outlined : Icons.south_rounded,
            color: invoice ? UPalette.amber : UPalette.mint,
            background: invoice ? UPalette.amberBg : UPalette.mintBg,
            border: invoice ? UPalette.amberLine : UPalette.mintLine,
            size: 30,
          ),
          const SizedBox(width: 10),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  children: [
                    Text(invoice ? s.inboxInvoice : s.inboxPayment, style: uiStyle(12.5, weight: FontWeight.w600)),
                    if (item.amountNano != null) ...[
                      const SizedBox(width: 8),
                      Flexible(
                        child: Text(
                          '${nanoToGrin(item.amountNano!)} $unit',
                          style: monoStyle(11.5, weight: FontWeight.w600, color: invoice ? UPalette.amber : UPalette.mint, spacing: -0.2),
                          maxLines: 1,
                          overflow: TextOverflow.ellipsis,
                        ),
                      ),
                    ],
                  ],
                ),
                if (bits.isNotEmpty) ...[
                  const SizedBox(height: 1),
                  Text(bits.join(' · '), style: uiStyle(10.5, color: UPalette.text3), maxLines: 2, overflow: TextOverflow.ellipsis),
                ],
              ],
            ),
          ),
          const SizedBox(width: 8),
          if (invoice)
            UButton(
              key: Key('inbox-pay-${item.file}'),
              label: s.payInvoice,
              dense: true,
              height: 30,
              expand: false,
              onTap: busy ? null : onPay,
            )
          else
            UButton(
              key: Key('inbox-accept-${item.file}'),
              label: s.receiveAction,
              dense: true,
              height: 30,
              expand: false,
              onTap: busy ? null : onAccept,
            ),
        ],
      ),
    );
  }
}

// ======================= OWN CHECKPOINT (до входа) =====================

/// Проверка чекпоинта с нуля (от genesis): работает и без кошелька. Пауза
/// сохраняет прогресс в ядре, следующий запуск продолжает с места.
class OwnCheckpointSheet extends StatefulWidget {
  const OwnCheckpointSheet({super.key, required this.core, required this.network, required this.onClose});

  final WalletCore core;
  final String network;
  final VoidCallback onClose;

  @override
  State<OwnCheckpointSheet> createState() => _OwnCheckpointSheetState();
}

class _OwnCheckpointSheetState extends State<OwnCheckpointSheet> {
  S get s => AppLocale.of(context).s;

  CheckpointInfo? _info;
  WalletJob? _job;
  JobProgress? _progress;
  String? _error;

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    try {
      final CheckpointInfo i = await widget.core.checkpointInfo(network: widget.network);
      if (mounted) setState(() => _info = i);
    } catch (e) {
      if (mounted) setState(() => _error = widget.core.describeError(e));
    }
  }

  Future<void> _run() async {
    setState(() {
      _error = null;
      _progress = null;
    });
    try {
      final WalletJob job = await widget.core.ownCheckpointJob(network: widget.network);
      setState(() => _job = job);
      await job.wait(onProgress: (JobProgress p) {
        if (mounted) setState(() => _progress = p);
      });
    } catch (e) {
      if (mounted) setState(() => _error = widget.core.describeError(e));
    }
    if (!mounted) return;
    setState(() => _job = null);
    await _load();
  }

  Future<void> _pause() async {
    await _job?.cancel();
  }

  Widget _status(CheckpointInfo i) {
    if (!i.ownBuilt) {
      return i.ownPaused ? Text(s.ownCpPausedNote, style: uiStyle(12, color: UPalette.amber, height: 1.5)) : const SizedBox.shrink();
    }
    final String h = i.ownHeight == null ? '—' : formatHeight(i.ownHeight!);
    final bool? m = i.matches;
    final Color c = m == false ? UPalette.red : UPalette.mint;
    return Container(
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: m == false ? UPalette.amberBg : UPalette.mintBg,
        border: Border.all(color: m == false ? UPalette.amberLine : UPalette.mintLine),
        borderRadius: BorderRadius.circular(12),
      ),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Icon(m == false ? Icons.gpp_bad_outlined : Icons.verified_outlined, size: 18, color: c),
          const SizedBox(width: 8),
          Expanded(
            child: Text(
              m == true ? s.ownCpMatch(h) : m == false ? s.ownCpMismatch(h) : s.ownCpBuilt(h),
              style: uiStyle(12.5, weight: FontWeight.w600, color: c, height: 1.45),
            ),
          ),
        ],
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final CheckpointInfo? i = _info;
    final bool running = _job != null;
    final String label = i == null
        ? s.ownCpStart
        : i.ownBuilt
            ? s.ownCpAgain
            : i.ownPaused
                ? s.ownCpContinue
                : s.ownCpStart;
    return USheetCard(
      title: s.ownCpTitle,
      width: 480,
      onClose: widget.onClose,
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Text(s.ownCpNote, style: uiStyle(12, color: UPalette.text2, height: 1.55)),
          const SizedBox(height: 10),
          if (i != null)
            Text(
              i.shippedExists && i.shippedHeight != null ? s.ownCpShipped(formatHeight(i.shippedHeight!)) : s.ownCpNoShipped,
              style: uiStyle(12, weight: FontWeight.w600, color: UPalette.text2),
            ),
          const SizedBox(height: 10),
          if (i != null && !running) ...[
            _status(i),
            const SizedBox(height: 10),
          ],
          if (running) ...[
            const LinearProgressIndicator(minHeight: 3, color: UPalette.mint, backgroundColor: UPalette.line),
            const SizedBox(height: 8),
            Text(
              (_progress?.phase.isNotEmpty ?? false) ? _progress!.phase : s.loadingWallet,
              style: uiStyle(12, weight: FontWeight.w600),
            ),
            if ((_progress?.lines ?? const <String>[]).isNotEmpty)
              Text(_progress!.lines.last, style: uiStyle(11, color: UPalette.text3), maxLines: 2, overflow: TextOverflow.ellipsis),
            const SizedBox(height: 10),
            UButton(label: s.ownCpPause, height: 38, onTap: _pause),
          ] else
            UButton(label: label, primary: true, height: 40, onTap: i == null ? null : _run),
          if (_error != null) ...[
            const SizedBox(height: 8),
            Text(s.humanError(_error!), style: uiStyle(11.5, color: UPalette.amber, height: 1.5)),
          ],
        ],
      ),
    );
  }
}
