import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

import 'core.dart';
import 'deferred_events.dart';
import 'quarantine_events.dart';

import 'components.dart';
import 'l10n.dart';
import 'theme.dart';
import 'wallet_model.dart';

/// Сообщение или платёж в ленте контакта.
class UFeedItem {
  const UFeedItem({
    required this.title,
    required this.titleEn,
    required this.subtitle,
    required this.subtitleEn,
    this.amount,
    this.outgoing = false,
    this.confirmed = false,
  });

  final String title;
  final String titleEn;
  final String subtitle;
  final String subtitleEn;
  final String? amount;
  final bool outgoing;
  final bool confirmed;

  String titleFor(String lang) => lang == 'en' ? titleEn : title;
  String subtitleFor(String lang) => lang == 'en' ? subtitleEn : subtitle;
}

class UContact {
  UContact({
    required this.name,
    required this.fullAddress,
    String? nameEn,
    String? shortAddress,
    this.time = '',
    this.timeEn = '',
    String? initial,
    this.color = UPalette.text2,
    this.background = UPalette.surface3,
    this.border = UPalette.line,
    this.verified = false,
    this.messenger,
    this.feed = const <UFeedItem>[],
  })  : nameEn = nameEn ?? name,
        shortAddress = shortAddress ?? fullAddress,
        initial = initial ?? name.substring(0, 1);

  final String name;
  final String nameEn;
  final String shortAddress;
  final String fullAddress;
  final String time;
  final String timeEn;
  final String initial;
  final Color color;
  final Color background;
  final Color border;
  final bool verified;
  final String? messenger;
  final List<UFeedItem> feed;

  String nameFor(String lang) => lang == 'en' ? nameEn : name;
  String timeFor(String lang) => lang == 'en' ? timeEn : time;
  String initialFor(String lang) => lang == 'en' ? nameEn.substring(0, 1) : initial;
}

/// Last daemon error, retained until dismissed even if a later status poll succeeds.
/// Raw errors are never rendered: they can contain addresses or tokens.
class MessengerNetworkNotice extends StatefulWidget {
  const MessengerNetworkNotice({super.key, required this.core, this.silent = false, this.onReport});
  final WalletCore core;
  /// На главном экране сам ничего не рисует: ошибки уходят в журнал через [onReport].
  final bool silent;
  /// Сырой код ошибки (в UI не показывается) — для журнала предупреждений.
  final ValueChanged<String>? onReport;
  @override
  State<MessengerNetworkNotice> createState() => _MessengerNetworkNoticeState();
}

class _MessengerNetworkNoticeState extends State<MessengerNetworkNotice> {
  Timer? _timer;
  String? _visibleError;
  String? _lastObserved;
  bool _polling = false;

  @override
  void initState() {
    super.initState();
    _poll();
    _timer = Timer.periodic(const Duration(seconds: 10), (_) => _poll());
  }

  @override
  void didUpdateWidget(covariant MessengerNetworkNotice oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (oldWidget.core != widget.core) { _visibleError = null; _lastObserved = null; _poll(); }
  }

  @override
  void dispose() { _timer?.cancel(); super.dispose(); }

  Future<void> _poll() async {
    if (_polling) return;
    _polling = true;
    final core = widget.core;
    try {
      final status = await core.chatStatus();
      final value = status['last_error'];
      if (value != null && value is! String) throw const FormatException('invalid status');
      if (!mounted || widget.core != core) return;
      // A cleared daemon status marks a new observation interval; keep any
      // visible notice until the user dismisses it, but allow recurrence.
      if (value == null || value == '') { _lastObserved = null; }
      if (value is String && value.isNotEmpty && value != _lastObserved) {
        setState(() { _lastObserved = value; _visibleError = value; });
        widget.onReport?.call(value);
      }
    } catch (_) {
      if (mounted && widget.core == core && _lastObserved != '__status_unavailable__') {
        setState(() { _lastObserved = '__status_unavailable__'; _visibleError = '__status_unavailable__'; });
        widget.onReport?.call('__status_unavailable__');
      }
    } finally { _polling = false; }
  }

  String _message(String raw, bool en) {
    final text = raw.toLowerCase();
    String tr(String ru, String english) => en ? english : ru;
    if (text == 'message_history_unavailable') return tr('История переписки недоступна или повреждена. Проверьте состояние хранилища.', 'Message history is unavailable or damaged. Check the storage.');
    if (text.contains('nostr receive page is full')) return tr('Список сообщений Nostr переполнен; некоторые входящие могут быть не получены.', 'The Nostr receive page is full; some incoming messages may not be received.');
    if (text.contains('text history full')) return tr('Хранилище переписки заполнено. Новые сообщения могут не приниматься.', 'Conversation storage is full. New messages may not be accepted.');
    if (text.contains('payment message storage full')) return tr('Хранилище входящих платежей заполнено. Новые запросы могут не приниматься.', 'Incoming payment storage is full. New requests may not be accepted.');
    if (text.contains('queue') || text.contains('quota')) return tr('Очередь или хранилище сообщений заполнены. Новые сообщения могут не приниматься.', 'The message queue or storage is full. New messages may not be accepted.');
    if (text.contains('history write') || text.contains('history read') || text.contains('history record')) return tr('Не удалось сохранить или прочитать историю. Проверьте доступное место и права.', 'History could not be saved or read. Check available space and permissions.');
    if (text.startsWith('ack:')) return tr('Не удалось подтвердить обработку входящего сообщения. Возможен повтор.', 'Could not acknowledge an incoming message. It may be retried.');
    if (text.startsWith('fetch:')) return tr('Не удалось получить сообщения по выбранному каналу.', 'Could not receive messages over the selected channel.');
    if (text == '__status_unavailable__') return tr('Не удалось проверить состояние мессенджера.', 'Could not check messenger status.');
    return tr('Не удалось обработать сетевое сообщение. Проверьте подключение и состояние операций.', 'A network message could not be processed. Check the connection and operation status.');
  }

  @override
  Widget build(BuildContext context) {
    final error = _visibleError;
    if (error == null || widget.silent) return const SizedBox.shrink();
    final en = AppLocale.of(context).lang == 'en';
    // Та же плашка, что у остальных уведомлений главного экрана.
    return Container(key: const Key('messenger-last-error'), margin: const EdgeInsets.only(bottom: 10),
      padding: const EdgeInsets.fromLTRB(12, 4, 4, 4),
      decoration: BoxDecoration(color: UPalette.amberBg, border: Border.all(color: UPalette.amberLine), borderRadius: BorderRadius.circular(12)),
      child: Row(crossAxisAlignment: CrossAxisAlignment.center, children: [
        const Icon(Icons.error_outline_rounded, size: 16, color: UPalette.amber),
        const SizedBox(width: 8),
        Expanded(child: Text('${en ? 'Last error' : 'Последняя ошибка'}: ${_message(error, en)}', style: uiStyle(12, color: UPalette.text2))),
        IconButton(key: const Key('messenger-error-dismiss'), tooltip: en ? 'Dismiss' : 'Скрыть',
          onPressed: () => setState(() => _visibleError = null), icon: const Icon(Icons.close, size: 18)),
      ]));
  }
}

/// Содержимое мессенджера: статус Tor, доставка платежей, автоприём, адресная книга.
class MessengerContent extends StatelessWidget {
  const MessengerContent({
    super.key,
    required this.delivery,
    required this.autoAccept,
    required this.onDelivery,
    required this.onAutoAccept,
    required this.onContact,
    required this.contacts,
    this.contactsUnavailable = false,
    this.torRunning = false,
    this.torPhase,
    this.onTorStart,
    this.onTorStop,
    this.onTorBridges,
    this.onOpenChat,
    this.onSettings,
    this.onAddContact,
    this.onOpenCatalogue,
    this.showHeader = true,
    this.core,
    this.collapsibleSettings = false,
    this.showNetworkNotice = true,
    this.showRecentMessages = true,
    this.lastTx,
    this.messengerOn = true,
    this.onMessengerToggle,
  });

  final String delivery;
  final String autoAccept;
  final ValueChanged<String> onDelivery;
  final ValueChanged<String> onAutoAccept;
  final ValueChanged<UContact> onContact;
  final List<UContact> contacts;
  final bool contactsUnavailable;
  final bool torRunning;
  /// Фаза Tor от службы: «процесс запущен» ещё не значит «подключён к сети».
  final TorPhase? torPhase;
  final VoidCallback? onTorStart;
  final VoidCallback? onTorStop;
  final VoidCallback? onTorBridges;
  final VoidCallback? onOpenChat;
  /// Канал сообщений (I2P / Nostr) для GlauxMail.
  final VoidCallback? onSettings;
  final VoidCallback? onAddContact;
  final VoidCallback? onOpenCatalogue;
  final bool showHeader;
  final WalletCore? core;
  /// На главном экране доставка и автоприём свёрнуты в одну строку
  /// «Доставка: Вручную · Настроить»: ежедневно они не нужны.
  final bool collapsibleSettings;
  /// На главном экране ошибки сети показываются в общей области уведомлений.
  final bool showNetworkNotice;
  /// На главном экране сообщения — отдельным списком под балансом.
  final bool showRecentMessages;
  /// Последний платёж: при ручной доставке показываем его slatepack.
  final WalletTx? lastTx;
  /// Мессенджер выключен: контакты и переписка скрыты, Tor управляется отдельно.
  final bool messengerOn;
  final ValueChanged<bool>? onMessengerToggle;

  @override
  Widget build(BuildContext context) {
    final S s = AppLocale.of(context).s;
    final bool en = AppLocale.of(context).lang == 'en';
    final String deliveryName = delivery == 'grinmail' ? s.deliveryMail : (delivery == 'tor' ? 'Tor' : s.deliveryManual);
    final Widget torLine = TorStatusLine(
      running: torRunning,
      phase: torPhase,
      onStart: onTorStart,
      onStop: onTorStop,
      onBridges: onTorBridges,
      dense: !showHeader,
    );
    final Widget? power = onMessengerToggle == null
        ? null
        : UIconButton(
            key: Key(messengerOn ? 'messenger-power' : 'messenger-power-on'),
            icon: Icons.power_settings_new_rounded,
            size: 34,
            iconSize: 17,
            tooltip: messengerOn ? s.messengerOff : s.messengerOn,
            onTap: () => onMessengerToggle!(!messengerOn),
          );
    final Widget title = Row(
      children: [
        Expanded(
          child: Text(s.messenger, maxLines: 1, softWrap: false, overflow: TextOverflow.ellipsis,
              style: uiStyle(15, weight: FontWeight.w600)),
        ),
        if (messengerOn && core != null) _MessengerTools(core: core!),
        ?power,
      ],
    );
    if (!messengerOn) {
      // Выключенный мессенджер: только статус Tor (он нужен и для платежей) и кнопка включения.
      return Column(
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          if (showHeader) ...[title, const SizedBox(height: 6)],
          Text(s.messengerIsOff, key: const Key('messenger-off'), style: uiStyle(13, weight: FontWeight.w600, color: UPalette.text2)),
          const SizedBox(height: 4),
          Text(s.messengerOffHint, style: uiStyle(11, color: UPalette.text3, height: 1.4)),
          const SizedBox(height: 10),
          torLine,
          if (onMessengerToggle != null) ...[
            const SizedBox(height: 10),
            UButton(key: const Key('messenger-turn-on'), label: s.messengerOn, height: 36, onTap: () => onMessengerToggle!(true)),
          ],
        ],
      );
    }
    final Widget settings = Column(
      mainAxisSize: MainAxisSize.min,
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Text(en ? 'Payment delivery' : 'Доставка платежей', style: uiStyle(11.5, color: UPalette.text2)),
        const SizedBox(height: 6),
        // Три явные кнопки вместо переключателя-сегмента: выбранная подсвечена.
        Row(children: [
          Expanded(child: _DeliveryButton(key: const Key('delivery-tor'), icon: Icons.vpn_lock_outlined, label: 'Tor',
            selected: delivery == 'tor', onTap: () => onDelivery('tor'))),
          const SizedBox(width: 6),
          Expanded(child: _DeliveryButton(key: const Key('delivery-manual'), icon: Icons.content_paste_rounded, label: s.deliveryManual,
            selected: delivery == 'manual', onTap: () => onDelivery('manual'))),
          const SizedBox(width: 6),
          Expanded(child: _DeliveryButton(key: const Key('delivery-grinmail'), icon: Icons.mail_outline_rounded, label: s.deliveryMail,
            selected: delivery == 'grinmail', onTap: () => onDelivery('grinmail'))),
        ]),
        if (delivery == 'grinmail') ...[
          const SizedBox(height: 4),
          Text(en
            ? 'Payments use the selected I2P or Nostr messaging channel. Add the recipient’s signed messaging address first.'
            : 'Платежи используют выбранный канал переписки I2P или Nostr. Сначала добавьте подписанный адрес собеседника.',
            key: const Key('glauxmail-payment-hint'), style: uiStyle(10.5, color: UPalette.text3)),
          // Выбор канала сообщений — прямо под GlauxMail: он нужен только ей.
          if (onSettings != null)
            Align(
              alignment: Alignment.centerLeft,
              child: TextButton.icon(
                key: const Key('open-messaging-settings'),
                onPressed: onSettings,
                style: TextButton.styleFrom(padding: const EdgeInsets.symmetric(horizontal: 6), minimumSize: const Size(0, 32), tapTargetSize: MaterialTapTargetSize.shrinkWrap),
                icon: const Icon(Icons.forum_outlined, size: 16),
                label: Text('${s.messageChannel}: I2P / Nostr ▾', style: uiStyle(11.5)),
              ),
            ),
        ],
        // При доставке через Tor мосты — внизу блока доставки.
        if (delivery == 'tor' && onTorBridges != null) ...[
          const SizedBox(height: 8),
          UButton(key: const Key('tor-bridges-delivery'), label: s.torBridgesDelivery, icon: Icons.alt_route_rounded, dense: true, height: 34, onTap: onTorBridges),
        ],
      ],
    );
    final Widget autoAcceptRow = _ControlRow(
      label: s.autoAccept,
      child: UAutoAcceptPicker(mode: autoAccept, onChanged: onAutoAccept),
    );
    return Column(
      mainAxisSize: MainAxisSize.min,
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        if (showHeader) ...[
          title,
          const SizedBox(height: 3),
          torLine,
          const SizedBox(height: 10),
        ],
        if (!showHeader) ...[
          Row(children: [Expanded(child: torLine), if (core != null) _MessengerTools(core: core!), ?power]),
          const SizedBox(height: 8),
        ],
        if (core != null && showNetworkNotice) MessengerNetworkNotice(core: core!),
        if (onOpenChat != null) ...[
          UButton(label: en ? 'Messages' : 'Переписка', height: 36, onTap: onOpenChat),
          const SizedBox(height: 10),
        ],
        // Кнопки доставки видны всегда; на главном экране свёрнут только автоприём.
        settings,
        const SizedBox(height: 6),
        if (collapsibleSettings)
          _DeliverySettings(deliveryName: deliveryName, child: autoAcceptRow)
        else
          autoAcceptRow,
        // Ручная доставка: все slatepack последнего платежа, с «Скопировать» и «Показать».
        if (delivery == 'manual' && core != null) ...[
          const SizedBox(height: 10),
          LastSlatepacks(core: core!, tx: lastTx),
        ],
        const SizedBox(height: 18),
        if (contactsUnavailable) ...[
          Text(en
            ? 'Could not load the address book. Any displayed contacts may be out of date; refresh to retry.'
            : 'Не удалось загрузить адресную книгу. Показанные контакты могут быть устаревшими; повторите обновление.',
            key: const Key('contacts-load-error'), style: uiStyle(11, color: UPalette.amber)),
          const SizedBox(height: 6),
        ],
        _AddressBook(contacts: contacts, onContact: onContact, onAddContact: onAddContact, onOpenCatalogue: onOpenCatalogue, unavailable: contactsUnavailable),
        if (showRecentMessages && _recentMessages(contacts).isNotEmpty) ...[
          const SizedBox(height: 18),
          SectionLabel(s.recentMessages),
          const SizedBox(height: 4),
          for (final (UContact, UFeedItem) recent in _recentMessages(contacts))
            _RecentRow(contact: recent.$1, item: recent.$2),
        ],
      ],
    );
  }
}

/// Строка статуса Tor. «Процесс запущен» и «подключён к сети» разведены:
/// зелёный — только когда служба сообщила, что onion-сервис поднят (сеть достигнута).
/// Пока не подключён — рядом «Настройки мостов». Переключатель включает/выключает
/// Tor независимо от мессенджера.
class TorStatusLine extends StatelessWidget {
  const TorStatusLine({super.key, required this.running, this.phase, this.onStart, this.onStop, this.onBridges, this.dense = false});

  final bool running;
  final TorPhase? phase;
  final VoidCallback? onStart;
  final VoidCallback? onStop;
  final VoidCallback? onBridges;
  final bool dense;

  @override
  Widget build(BuildContext context) {
    final S s = AppLocale.of(context).s;
    final TorPhase p = phase ?? (running ? TorPhase.unknown : TorPhase.stopped);
    final (String label, Color color) = switch (p) {
      TorPhase.onionStarted => (s.torStatusOnionStarted, UPalette.mint),
      TorPhase.starting => (s.torStatusStarting, UPalette.amber),
      TorPhase.failed => (s.torStatusFailed, UPalette.red),
      TorPhase.stopped => (s.torOffline, UPalette.amber),
      TorPhase.unknown => (running ? s.torProcessUnconfirmed : s.torOffline, UPalette.amber),
    };
    final bool on = running || p == TorPhase.starting || p == TorPhase.onionStarted;
    final bool connected = p == TorPhase.onionStarted;
    final bool canToggle = on ? onStop != null : onStart != null;
    return Tooltip(
      message: s.torStatusDetail,
      child: Column(
        key: const Key('tor-status-line'),
        crossAxisAlignment: CrossAxisAlignment.start,
        mainAxisSize: MainAxisSize.min,
        children: [
          Row(children: [
            Container(
              width: 7, height: 7,
              decoration: BoxDecoration(color: color, borderRadius: BorderRadius.circular(999),
                boxShadow: [BoxShadow(color: color.withValues(alpha: 0.14), blurRadius: 6, spreadRadius: 2)]),
            ),
            const SizedBox(width: 6),
            Expanded(child: Text(label, maxLines: 2, overflow: TextOverflow.ellipsis,
              style: uiStyle(dense ? 11 : 12, color: connected ? UPalette.text2 : color))),
            if (canToggle)
              USwitch(key: const Key('tor-switch'), value: on, onChanged: (bool v) => v ? onStart!() : onStop!()),
          ]),
          if (!connected && onBridges != null)
            TextButton.icon(
              key: const Key('tor-bridges-status'),
              onPressed: onBridges,
              style: TextButton.styleFrom(padding: const EdgeInsets.symmetric(horizontal: 6), minimumSize: const Size(0, 30), tapTargetSize: MaterialTapTargetSize.shrinkWrap),
              icon: const Icon(Icons.alt_route_rounded, size: 16),
              label: Text(s.torBridges, style: uiStyle(11.5)),
            ),
        ],
      ),
    );
  }
}

/// Все slatepack последнего платежа (S1, S2, I1, I2…) с «Скопировать» и «Показать».
/// Это публичные сообщения обмена: ключей в них нет.
class LastSlatepacks extends StatefulWidget {
  const LastSlatepacks({super.key, required this.core, this.tx});
  final WalletCore core;
  final WalletTx? tx;

  @override
  State<LastSlatepacks> createState() => _LastSlatepacksState();
}

class _LastSlatepacksState extends State<LastSlatepacks> {
  List<SlatepackFile> _items = const <SlatepackFile>[];
  bool _loading = false;
  String? _error;
  String? _loadedFor;

  @override
  void initState() {
    super.initState();
    _load();
  }

  @override
  void didUpdateWidget(LastSlatepacks old) {
    super.didUpdateWidget(old);
    if (old.tx?.txId != widget.tx?.txId || old.tx?.stage != widget.tx?.stage || old.core != widget.core) _load();
  }

  Future<void> _load() async {
    final String? id = widget.tx?.txId;
    _loadedFor = id;
    _error = null;
    if (id == null) {
      _items = const <SlatepackFile>[];
      _loading = false;
      return;
    }
    _loading = true;
    final WalletCore core = widget.core;
    List<SlatepackFile> items = const <SlatepackFile>[];
    String? error;
    try {
      if (core is SlatepackHistoryApi) {
        try {
          items = await (core as SlatepackHistoryApi).slatepacks(id);
        } catch (_) {
          // Старая служба без wallet.slatepacks: хотя бы текущий slatepack.
          items = <SlatepackFile>[SlatepackFile('', await core.slatepack(id))];
        }
      } else {
        items = <SlatepackFile>[SlatepackFile('', await core.slatepack(id))];
      }
    } catch (e) {
      final String raw = core.describeError(e);
      if (!raw.contains('no slatepack')) error = raw;
    }
    if (!mounted || _loadedFor != id) return;
    setState(() { _items = items; _error = error; _loading = false; });
  }

  String _label(String file, bool en) {
    String t(String ru, String e) => en ? e : ru;
    return switch (file) {
      'slatepack-s1.txt' => t('S1 · отправьте получателю', 'S1 · send to the recipient'),
      'slatepack-answer-in.txt' => t('Ответ второй стороны (получен)', 'Answer from the other side (received)'),
      'slatepack-in.txt' => t('S1 · от отправителя (получен)', 'S1 · from the sender (received)'),
      'slatepack-answer.txt' => t('S2 · ваш ответ, верните отправителю', 'S2 · your answer, return to the sender'),
      'backup-s2.txt' => t('S2 · ответ (резервная доставка)', 'S2 · answer (backup delivery)'),
      'invoice-i1.txt' => t('I1 · ваш счёт, отправьте плательщику', 'I1 · your invoice, send to the payer'),
      'invoice-in.txt' => t('I1 · счёт (получен)', 'I1 · invoice (received)'),
      'invoice-i2.txt' => t('I2 · оплата счёта, верните выставившему', 'I2 · invoice payment, return to the issuer'),
      _ => 'Slatepack',
    };
  }

  Future<void> _copy(String text) async {
    await Clipboard.setData(ClipboardData(text: text));
    if (mounted) showToast(context, AppLocale.of(context).lang == 'en' ? 'Copied' : 'Скопировано');
  }

  void _show(String label, String text) {
    final S s = AppLocale.of(context).s;
    showDialog<void>(
      context: context,
      builder: (BuildContext ctx) => AlertDialog(
        backgroundColor: UPalette.surface2,
        title: Text(label, style: uiStyle(14, weight: FontWeight.w600)),
        content: SizedBox(
          width: 520,
          child: SingleChildScrollView(child: SelectableText(text, key: const Key('slatepack-text'), style: monoStyle(11, weight: FontWeight.w400, height: 1.5))),
        ),
        actions: [
          TextButton(onPressed: () => _copy(text), child: Text(s.copy)),
          TextButton(onPressed: () => Navigator.of(ctx).pop(), child: Text(s.close)),
        ],
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final S s = AppLocale.of(context).s;
    final bool en = AppLocale.of(context).lang == 'en';
    final WalletTx? tx = widget.tx;
    return Container(
      key: const Key('last-slatepacks'),
      padding: const EdgeInsets.fromLTRB(12, 10, 12, 8),
      decoration: BoxDecoration(color: UPalette.fieldBg, border: Border.all(color: UPalette.line), borderRadius: BorderRadius.circular(12)),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          SectionLabel(s.lastSlatepacks),
          if (tx != null) ...[
            const SizedBox(height: 2),
            Text('${s.txDirectionLabel(tx.direction)} · ${tx.amountNano % 10000000 == 0 ? shortGrin(tx.amountNano) : nanoToGrin(tx.amountNano)} GRIN', style: uiStyle(11, color: UPalette.text3)),
          ],
          const SizedBox(height: 6),
          if (tx == null)
            Text(s.noPaymentsYet, style: uiStyle(11.5, color: UPalette.text3))
          else if (_loading)
            const LinearProgressIndicator(minHeight: 2, color: UPalette.mint, backgroundColor: UPalette.line)
          else if (_error != null)
            Text(s.humanError(_error!), style: uiStyle(11.5, color: UPalette.amber))
          else if (_items.isEmpty)
            Text(s.noSlatepacks, style: uiStyle(11.5, color: UPalette.text3))
          else
            for (int i = 0; i < _items.length; i++)
              Padding(
                padding: const EdgeInsets.only(top: 2),
                child: Row(children: [
                  // Подпись целиком (без «…»), кнопки — компактными значками с подсказками.
                  Expanded(child: Text(_label(_items[i].file, en), style: uiStyle(12, weight: FontWeight.w600))),
                  const SizedBox(width: 4),
                  UIconButton(key: Key('slatepack-copy-$i'), icon: Icons.copy_rounded, size: 34, iconSize: 16, tooltip: s.copy, onTap: () => _copy(_items[i].text)),
                  UIconButton(key: Key('slatepack-show-$i'), icon: Icons.visibility_outlined, size: 34, iconSize: 16, tooltip: s.show, onTap: () => _show(_label(_items[i].file, en), _items[i].text)),
                ]),
              ),
        ],
      ),
    );
  }
}

/// Последние сообщения отдельным списком (на главном экране — под балансом).
class RecentMessagesCard extends StatelessWidget {
  const RecentMessagesCard({super.key, required this.contacts, this.onOpenChat});
  final List<UContact> contacts;
  final VoidCallback? onOpenChat;

  @override
  Widget build(BuildContext context) {
    final S s = AppLocale.of(context).s;
    final List<(UContact, UFeedItem)> recent = _recentMessages(contacts);
    return UCard(
      key: const Key('recent-messages'),
      padding: const EdgeInsets.fromLTRB(16, 6, 16, 8),
      child: UExpandSection(
        title: Row(mainAxisSize: MainAxisSize.min, children: [
          Icon(Icons.chat_bubble_outline_rounded, size: 17, color: recent.isNotEmpty ? UPalette.mint : UPalette.text3),
          const SizedBox(width: 8),
          Flexible(child: Text(s.messagesTitle, maxLines: 1, overflow: TextOverflow.ellipsis, style: uiStyle(14, weight: FontWeight.w600))),
        ]),
        count: recent.length,
        child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
          if (recent.isEmpty)
            Padding(padding: const EdgeInsets.symmetric(vertical: 6), child: Text(s.messagesEmpty, style: uiStyle(11.5, color: UPalette.text3)))
          else
            for (final (UContact, UFeedItem) r in recent) _RecentRow(contact: r.$1, item: r.$2),
          if (onOpenChat != null)
            Align(alignment: Alignment.centerRight, child: TextButton(key: const Key('recent-messages-open'), onPressed: onOpenChat,
              child: Text(AppLocale.of(context).lang == 'en' ? 'Open conversations' : 'Открыть переписку', style: uiStyle(12, weight: FontWeight.w600, color: UPalette.mint)))),
        ]),
      ),
    );
  }
}

/// Явная кнопка способа доставки (Tor / Вручную / GlauxMail).
class _DeliveryButton extends StatelessWidget {
  const _DeliveryButton({super.key, required this.icon, required this.label, required this.selected, required this.onTap});
  final IconData icon;
  final String label;
  final bool selected;
  final VoidCallback onTap;

  @override
  Widget build(BuildContext context) {
    return Semantics(
      button: true,
      selected: selected,
      child: Material(
        color: selected ? UPalette.mintBg : UPalette.surface2,
        borderRadius: BorderRadius.circular(10),
        child: InkWell(
          onTap: onTap,
          borderRadius: BorderRadius.circular(10),
          child: Container(
            height: 40,
            padding: const EdgeInsets.symmetric(horizontal: 6),
            decoration: BoxDecoration(
              border: Border.all(color: selected ? UPalette.mintLine : UPalette.line, width: selected ? 1.5 : 1),
              borderRadius: BorderRadius.circular(10),
            ),
            child: Center(
              child: FittedBox(
                fit: BoxFit.scaleDown,
                child: Row(mainAxisSize: MainAxisSize.min, children: [
                  Icon(icon, size: 16, color: selected ? UPalette.mint : UPalette.text2),
                  const SizedBox(width: 6),
                  Text(label, style: uiStyle(12.5, weight: FontWeight.w600, color: selected ? UPalette.text : UPalette.text2)),
                ]),
              ),
            ),
          ),
        ),
      ),
    );
  }
}

/// Свёрнутая строка «Доставка: Tor · Настроить ▾»; по нажатию раскрывает
/// выбор канала и автоприём. Содержимое остаётся в дереве (Offstage).
class _DeliverySettings extends StatefulWidget {
  const _DeliverySettings({required this.deliveryName, required this.child});
  final String deliveryName;
  final Widget child;

  @override
  State<_DeliverySettings> createState() => _DeliverySettingsState();
}

class _DeliverySettingsState extends State<_DeliverySettings> {
  bool _open = false;

  @override
  Widget build(BuildContext context) {
    final bool en = AppLocale.of(context).lang == 'en';
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        InkWell(
          key: const Key('messenger-delivery-toggle'),
          borderRadius: BorderRadius.circular(10),
          onTap: () => setState(() => _open = !_open),
          child: Padding(
            padding: const EdgeInsets.symmetric(vertical: 8, horizontal: 2),
            child: Row(children: [
              const Icon(Icons.tune_rounded, size: 16, color: UPalette.text3),
              const SizedBox(width: 8),
              Expanded(child: Text(en ? 'Auto-accept' : 'Автоприём',
                maxLines: 1, overflow: TextOverflow.ellipsis, style: uiStyle(12.5, color: UPalette.text2))),
              Text(en ? 'Configure' : 'Настроить', style: uiStyle(12, weight: FontWeight.w600, color: UPalette.text2)),
              AnimatedRotation(
                turns: _open ? 0.5 : 0,
                duration: const Duration(milliseconds: 160),
                child: const Icon(Icons.keyboard_arrow_down_rounded, size: 18, color: UPalette.text3),
              ),
            ]),
          ),
        ),
        Offstage(offstage: !_open, child: Padding(padding: const EdgeInsets.only(top: 4), child: widget.child)),
      ],
    );
  }
}

/// Less common recovery actions remain available without crowding the dashboard.
class _MessengerTools extends StatelessWidget {
  const _MessengerTools({required this.core});
  final WalletCore core;

  @override
  Widget build(BuildContext context) {
    final en = AppLocale.of(context).lang == 'en';
    return PopupMenuButton<String>(
      key: const Key('messenger-tools'),
      tooltip: en ? 'Message recovery' : 'Восстановление сообщений',
      icon: const Icon(Icons.more_horiz, size: 20, color: UPalette.text2),
      padding: EdgeInsets.zero,
      constraints: const BoxConstraints(minWidth: 220),
      onSelected: (value) {
        if (value == 'deferred') {
          showDialog<void>(context: context, builder: (_) => DeferredEventsDialog(core: core, english: en));
        } else if (value == 'quarantine') {
          showDialog<void>(context: context, builder: (_) => QuarantineEventsDialog(core: core, english: en));
        }
      },
      itemBuilder: (_) => [
        PopupMenuItem(value: 'deferred', key: const Key('deferred-open'), child: Text(en ? 'Unprocessed messages' : 'Необработанные сообщения')),
        PopupMenuItem(value: 'quarantine', key: const Key('quarantine-open'), child: Text(en ? 'Message quarantine' : 'Карантин сообщений')),
      ],
    );
  }
}

class _AddressBook extends StatefulWidget {
  const _AddressBook({required this.contacts, required this.onContact, this.onAddContact, this.onOpenCatalogue, this.unavailable = false});

  final List<UContact> contacts;
  final ValueChanged<UContact> onContact;
  final VoidCallback? onAddContact;
  final VoidCallback? onOpenCatalogue;
  final bool unavailable;

  @override
  State<_AddressBook> createState() => _AddressBookState();
}

class _AddressBookState extends State<_AddressBook> {
  final TextEditingController _q = TextEditingController();

  @override
  void dispose() {
    _q.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final AppLocale locale = AppLocale.of(context);
    final S s = locale.s;
    final String q = _q.text.trim().toLowerCase();
    final List<UContact> shown = q.isEmpty
        ? widget.contacts
        : widget.contacts
            .where((UContact c) => c.nameFor(locale.lang).toLowerCase().contains(q) || c.fullAddress.toLowerCase().contains(q))
            .toList();
    return UExpandSection(
      title: SectionLabel(s.addressBook),
      count: widget.unavailable && widget.contacts.isEmpty ? null : widget.contacts.length,
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Wrap(spacing: 8, runSpacing: 4, children: [
            if (widget.onOpenCatalogue != null) TextButton.icon(
              key: const Key('open-contact-catalogue'),
              onPressed: widget.onOpenCatalogue,
              style: TextButton.styleFrom(padding: const EdgeInsets.symmetric(horizontal: 6), minimumSize: const Size(0, 36)),
              icon: const Icon(Icons.manage_search_rounded, size: 17),
              label: Text(locale.lang == 'en' ? 'Find / my profile' : 'Поиск / мой профиль', style: uiStyle(11.5)),
            ),
            if (widget.onAddContact != null) TextButton.icon(
              key: const Key('add-wallet-contact'),
              onPressed: widget.onAddContact,
              style: TextButton.styleFrom(padding: const EdgeInsets.symmetric(horizontal: 6), minimumSize: const Size(0, 36)),
              icon: const Icon(Icons.person_add_alt_1_rounded, size: 17),
              label: Text(locale.lang == 'en' ? 'Add' : 'Добавить', style: uiStyle(11.5)),
            ),
          ]),
          if (widget.contacts.isNotEmpty) ...[
            const SizedBox(height: 4),
            TextField(
              controller: _q,
              onChanged: (_) => setState(() {}),
              cursorColor: UPalette.mint,
              style: uiStyle(13, color: UPalette.text),
              decoration: InputDecoration(
                hintText: s.searchContacts,
                hintStyle: uiStyle(12.5, color: UPalette.text3),
                prefixIcon: const Icon(Icons.search_rounded, size: 18, color: UPalette.text3),
                suffixIcon: q.isEmpty
                    ? null
                    : IconButton(
                        icon: const Icon(Icons.close_rounded, size: 16, color: UPalette.text3),
                        onPressed: () => setState(_q.clear),
                      ),
                filled: true,
                fillColor: UPalette.fieldBg,
                isDense: true,
                contentPadding: const EdgeInsets.symmetric(vertical: 10),
                border: OutlineInputBorder(borderRadius: BorderRadius.circular(12), borderSide: const BorderSide(color: UPalette.lineStrong)),
                enabledBorder: OutlineInputBorder(borderRadius: BorderRadius.circular(12), borderSide: const BorderSide(color: UPalette.lineStrong)),
                focusedBorder: OutlineInputBorder(borderRadius: BorderRadius.circular(12), borderSide: const BorderSide(color: UPalette.mintLine)),
              ),
            ),
            const SizedBox(height: 4),
          ],
          if (widget.contacts.isEmpty && !widget.unavailable)
            Padding(
              padding: const EdgeInsets.symmetric(vertical: 12),
              child: Text(s.noContacts, textAlign: TextAlign.center, style: uiStyle(12, color: UPalette.text3)),
            )
          else if (widget.contacts.isNotEmpty && shown.isEmpty)
            Padding(
              padding: const EdgeInsets.symmetric(vertical: 12),
              child: Text(s.noMatches, textAlign: TextAlign.center, style: uiStyle(12, color: UPalette.text3)),
            )
          else
            for (final UContact c in shown) _ContactRow(contact: c, onTap: () => widget.onContact(c)),
        ],
      ),
    );
  }
}

class _ControlRow extends StatelessWidget {
  const _ControlRow({required this.label, required this.child});

  final String label;
  final Widget child;

  @override
  Widget build(BuildContext context) {
    return LayoutBuilder(builder: (context, constraints) {
      if (constraints.maxWidth < 315) {
        return Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Text(label, style: uiStyle(12.5, color: UPalette.text2)),
          const SizedBox(height: 4),
          child,
        ]);
      }
      return Row(children: [
        Expanded(child: Text(label, style: uiStyle(12.5, color: UPalette.text2), maxLines: 1, overflow: TextOverflow.ellipsis)),
        const SizedBox(width: 8),
        child,
      ]);
    });
  }
}

/// Автоприём: компактный выпадающий выбор (ask / contacts / all / off).
class UAutoAcceptPicker extends StatelessWidget {
  const UAutoAcceptPicker({super.key, required this.mode, required this.onChanged});

  final String mode;
  final ValueChanged<String> onChanged;

  static const List<String> _modes = <String>['ask_all', 'off'];

  @override
  Widget build(BuildContext context) {
    final s = AppLocale.of(context).s;
    final List<String> options = <String>[s.autoEnable, s.autoDisable];
    final int index = _modes.indexOf(mode);
    return PopupMenuButton<int>(
      tooltip: '',
      color: UPalette.surface2,
      surfaceTintColor: Colors.transparent,
      initialValue: index < 0 ? null : index,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(14),
        side: const BorderSide(color: UPalette.lineStrong),
      ),
      onSelected: (int i) => onChanged(_modes[i]),
      itemBuilder: (BuildContext context) => <PopupMenuEntry<int>>[
        for (int i = 0; i < options.length; i++)
          PopupMenuItem<int>(value: i, height: 44, child: Text(options[i], style: uiStyle(14))),
      ],
      child: Container(
        height: 30,
        padding: const EdgeInsets.symmetric(horizontal: 10),
        decoration: BoxDecoration(
          color: UPalette.surface,
          border: Border.all(color: UPalette.lineStrong),
          borderRadius: BorderRadius.circular(12),
        ),
        child: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            Text(index < 0 ? (mode == 'unknown' ? s.autoAcceptUnknown : s.autoAcceptValue(mode)) : options[index], style: uiStyle(12.5, weight: FontWeight.w600, color: UPalette.text2)),
            const SizedBox(width: 2),
            const Icon(Icons.keyboard_arrow_down_rounded, size: 18, color: UPalette.text3),
          ],
        ),
      ),
    );
  }
}

List<(UContact, UFeedItem)> _recentMessages(List<UContact> contacts) {
  final List<(UContact, UFeedItem)> result = <(UContact, UFeedItem)>[];
  for (final UContact contact in contacts) {
    for (final UFeedItem item in contact.feed) {
      if (item.titleEn == 'Message') {
        result.add((contact, item));
        break;
      }
    }
    if (result.length == 3) break;
  }
  return result;
}

class _RecentRow extends StatelessWidget {
  const _RecentRow({required this.contact, required this.item});

  final UContact contact;
  final UFeedItem item;

  @override
  Widget build(BuildContext context) {
    final AppLocale locale = AppLocale.of(context);
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 5, horizontal: 4),
      child: Row(
        children: [
          Container(
            width: 22,
            height: 22,
            alignment: Alignment.center,
            decoration: BoxDecoration(
              color: contact.background,
              border: Border.all(color: contact.border),
              borderRadius: BorderRadius.circular(7),
            ),
            child: Text(contact.initialFor(locale.lang), style: uiStyle(10, weight: FontWeight.w700, color: contact.color)),
          ),
          const SizedBox(width: 8),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(contact.nameFor(locale.lang), style: uiStyle(11, weight: FontWeight.w600)),
                Text(
                  item.subtitleFor(locale.lang),
                  style: uiStyle(10.5, color: UPalette.text3),
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                ),
              ],
            ),
          ),
          const SizedBox(width: 6),
          Text(contact.timeFor(locale.lang), style: uiStyle(10, color: UPalette.text3)),
        ],
      ),
    );
  }
}

class _ContactRow extends StatelessWidget {
  const _ContactRow({required this.contact, required this.onTap});

  final UContact contact;
  final VoidCallback onTap;

  @override
  Widget build(BuildContext context) {
    final AppLocale locale = AppLocale.of(context);
    final S s = locale.s;
    return Material(
      color: Colors.transparent,
      child: InkWell(
        borderRadius: BorderRadius.circular(10),
        onTap: onTap,
        child: Padding(
          padding: const EdgeInsets.symmetric(vertical: 8, horizontal: 6),
          child: Row(
            children: [
              Container(
                width: 34,
                height: 34,
                alignment: Alignment.center,
                decoration: BoxDecoration(
                  color: contact.background,
                  border: Border.all(color: contact.border),
                  borderRadius: BorderRadius.circular(11),
                ),
                child: Text(
                  contact.initialFor(locale.lang),
                  style: uiStyle(13, weight: FontWeight.w700, color: contact.color),
                ),
              ),
              const SizedBox(width: 10),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Row(
                      children: [
                        Flexible(
                          child: Text(
                            contact.nameFor(locale.lang),
                            style: uiStyle(12.5, weight: FontWeight.w600),
                            overflow: TextOverflow.ellipsis,
                          ),
                        ),
                        if (contact.verified) ...[
                          const SizedBox(width: 4),
                          const Icon(Icons.verified, size: 12, color: UPalette.mint),
                        ],
                      ],
                    ),
                    const SizedBox(height: 1),
                    Text(
                      contact.shortAddress,
                      style: monoStyle(10.5, weight: FontWeight.w400, color: UPalette.text3, spacing: 0),
                      maxLines: 1,
                      overflow: TextOverflow.ellipsis,
                    ),
                  ],
                ),
              ),
              const SizedBox(width: 8),
              Column(
                crossAxisAlignment: CrossAxisAlignment.end,
                children: [
                  Text(contact.timeFor(locale.lang), style: uiStyle(10, color: UPalette.text3)),
                  if (contact.verified)
                    Text(s.signature, style: uiStyle(9.5, color: UPalette.mint)),
                ],
              ),
            ],
          ),
        ),
      ),
    );
  }
}
