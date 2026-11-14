import 'package:flutter/foundation.dart' show kIsWeb;
import 'package:flutter/material.dart';
import 'package:flutter/rendering.dart';
import 'package:flutter/services.dart';

import '../components.dart';
import '../core.dart';
import '../event_log.dart';
import '../l10n.dart';
import '../messenger.dart';
import '../sheets.dart';
import '../theme.dart';
import '../wallet_model.dart';

class WalletScreen extends StatelessWidget {
  const WalletScreen({
    super.key,
    required this.core,
    required this.wide,
    required this.status,
    this.contactPhrase,
    this.contactPublication,
    this.contactChannel,
    required this.transactions,
    required this.contacts,
    this.contactsUnavailable = false,
    required this.delivery,
    required this.autoAccept,
    required this.loading,
    required this.torRunning,
    this.torInfo,
    required this.onTorStart,
    required this.showCheckpointOffer,
    required this.onCheckpointOffer,
    required this.onDismissCheckpointOffer,
    required this.onSettings,
    required this.showHistory,
    required this.onHistory,
    required this.onOpenOwnCheckpoint,
    required this.onLogout,
    required this.onSend,
    required this.onReceive,
    required this.onOpenMessenger,
    required this.onContact,
    this.onAddContact,
    this.onOpenCatalogue,
    required this.onDeliveryChanged,
    required this.onAutoAcceptChanged,
    required this.onVerification,
    required this.onRefresh,
    this.messengerOn = true,
    this.onMessengerToggle,
    this.onTorStop,
    this.future = false,
    this.onFutureToggle,
    this.mono = false,
    this.onMonoToggle,
  });

  /// Монохромная тема (переключатель в шапке).
  final bool mono;
  final VoidCallback? onMonoToggle;

  /// «Пощупать будущее» (проверка по header-proof) — переключатель в шапке.
  final bool future;
  final ValueChanged<bool>? onFutureToggle;

  /// Мессенджер можно выключить целиком; Tor при этом управляется отдельно.
  final bool messengerOn;
  final ValueChanged<bool>? onMessengerToggle;
  final VoidCallback? onTorStop;

  final WalletCore core;
  final bool wide;
  final WalletStatus status;
  final String? contactPhrase;
  final String? contactPublication;
  final String? contactChannel;
  final List<WalletTx> transactions;
  final List<UContact> contacts;
  final bool contactsUnavailable;
  final String delivery;
  final String autoAccept;
  final bool loading;
  final bool torRunning;
  final TorStatusInfo? torInfo;
  final VoidCallback onTorStart;
  final bool showCheckpointOffer;
  final VoidCallback onCheckpointOffer;
  final VoidCallback onDismissCheckpointOffer;
  final VoidCallback onSettings;
  final bool showHistory;
  final VoidCallback onHistory;
  final VoidCallback onOpenOwnCheckpoint;
  final VoidCallback onLogout;
  final VoidCallback onSend;
  final VoidCallback onReceive;
  final VoidCallback onOpenMessenger;
  final ValueChanged<UContact> onContact;
  final VoidCallback? onAddContact;
  final VoidCallback? onOpenCatalogue;
  final ValueChanged<String> onDeliveryChanged;
  final ValueChanged<String> onAutoAcceptChanged;
  final VoidCallback onVerification;
  final VoidCallback onRefresh;

  @override
  Widget build(BuildContext context) {
    if (kIsWeb && !wide) {
      return _WebConceptShell(
        status: status,
        transactions: transactions,
        onSettings: onSettings,
        onSend: onSend,
        onReceive: onReceive,
        onOpenMessenger: onOpenMessenger,
        onVerification: onVerification,
        onRefresh: onRefresh,
      );
    }
    return Column(
      children: [
        _WalletHeader(
          status: status,
          wide: wide,
          onSettings: onSettings,
          onHistory: onHistory,
          onOpenOwnCheckpoint: onOpenOwnCheckpoint,
          onLogout: onLogout,
          onVerification: onVerification,
          onTorSettings: () => showTorBridgeSettings(context, core),
          future: future,
          onFuture: onFutureToggle == null ? null : () => onFutureToggle!(!future),
          mono: mono,
          onMono: onMonoToggle,
        ),
        Expanded(
          child: showHistory
              ? _HistoryPage(transactions: transactions, network: status.network, onBack: onHistory)
              : wide
              ? _WideBody(
                  core: core,
                  status: status,
                  contactPhrase: contactPhrase,
                  contactPublication: contactPublication,
                  contactChannel: contactChannel,
                  transactions: transactions,
                  contacts: contacts,
                  contactsUnavailable: contactsUnavailable,
                  delivery: delivery,
                  autoAccept: autoAccept,
                  torRunning: torRunning,
                  onTorStart: onTorStart,
                  onOpenChat: onOpenMessenger,
                  onSettings: onSettings,
                  onHistory: onHistory,
                  showCheckpointOffer: showCheckpointOffer,
                  onCheckpointOffer: onCheckpointOffer,
                  onDismissCheckpointOffer: onDismissCheckpointOffer,
                  onDeliveryChanged: onDeliveryChanged,
                  onAutoAcceptChanged: onAutoAcceptChanged,
                  onContact: onContact,
                  onAddContact: onAddContact,
                  onOpenCatalogue: onOpenCatalogue,
                  onSend: onSend,
                  onReceive: onReceive,
                  onVerification: onVerification,
                  onRefresh: onRefresh,
                  torInfo: torInfo,
                  messengerOn: messengerOn,
                  onMessengerToggle: onMessengerToggle,
                  onTorStop: onTorStop,
                )
              : _NarrowBody(
                  core: core,
                  status: status,
                  contactPhrase: contactPhrase,
                  contactPublication: contactPublication,
                  contactChannel: contactChannel,
                  transactions: transactions,
                  delivery: delivery,
                  autoAccept: autoAccept,
                  onOpenMessenger: onOpenMessenger,
                  torInfo: torInfo,
                  showCheckpointOffer: showCheckpointOffer,
                  onCheckpointOffer: onCheckpointOffer,
                  onDismissCheckpointOffer: onDismissCheckpointOffer,
                  onHistory: onHistory,
                  onSend: onSend,
                  onReceive: onReceive,
                  onVerification: onVerification,
                  onRefresh: onRefresh,
                  messengerOn: messengerOn,
                ),
        ),
      ],
    );
  }
}

class _WalletHeader extends StatelessWidget {
  const _WalletHeader({
    required this.status,
    required this.wide,
    required this.onSettings,
    required this.onHistory,
    required this.onOpenOwnCheckpoint,
    required this.onLogout,
    required this.onVerification,
    required this.onTorSettings,
    this.future = false,
    this.onFuture,
    this.mono = false,
    this.onMono,
  });

  final bool mono;
  final VoidCallback? onMono;
  final WalletStatus status;
  final bool wide;
  final VoidCallback onSettings;
  final VoidCallback onHistory;
  final VoidCallback onOpenOwnCheckpoint;
  final VoidCallback onLogout;
  final VoidCallback onVerification;
  final VoidCallback onTorSettings;
  final bool future;
  final VoidCallback? onFuture;

  @override
  Widget build(BuildContext context) {
    final S s = AppLocale.of(context).s;
    final bool en = AppLocale.of(context).lang == 'en';
    final double b = wide ? 44 : 40;
    Widget divider() => Container(width: 1, height: 20, margin: const EdgeInsets.symmetric(horizontal: 4), color: UPalette.line);
    // Все действия шапки — значками в одну линию, ничего не прячется в «⋯».
    final Widget toolbar = Container(
      decoration: BoxDecoration(
        color: UPalette.surface,
        border: Border.all(color: UPalette.line),
        borderRadius: BorderRadius.circular(14),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          UIconButton(key: const Key('wallet-proof'), icon: Icons.verified_outlined, size: b, onTap: onVerification, tooltip: s.verificationTitle),
          UIconButton(key: const Key('wallet-own-checkpoint'), icon: Icons.shield_outlined, size: b, onTap: onOpenOwnCheckpoint,
            tooltip: en ? 'Verify from genesis' : 'Проверить с нуля'),
          UIconButton(key: const Key('wallet-tor'), icon: Icons.vpn_lock_outlined, size: b, onTap: onTorSettings,
            tooltip: en ? 'Tor: connection and bridges' : 'Tor: подключение и мосты'),
          if (onFuture != null) _FutureToggle(on: future, onTap: onFuture!, compact: !wide),
          divider(),
          UIconButton(key: const Key('wallet-history'), icon: Icons.history, size: b, onTap: onHistory, tooltip: s.historyTitle),
          UIconButton(icon: Icons.settings_outlined, size: b, onTap: onSettings, tooltip: s.settings),
          if (onMono != null)
            UIconButton(key: const Key('wallet-theme'), icon: mono ? Icons.palette_outlined : Icons.contrast_rounded, size: b, onTap: onMono,
              tooltip: mono ? (en ? 'Colour theme' : 'Цветная тема') : (en ? 'Monochrome theme' : 'Монохромная тема')),
          const ULanguageChip(),
          divider(),
          // «Выйти» отделён, чтобы не нажать его вместо настроек.
          UIconButton(key: const Key('wallet-logout'), icon: Icons.logout_rounded, size: b, onTap: onLogout, tooltip: s.logout),
        ],
      ),
    );
    final Widget title = wide
        ? Row(
            mainAxisSize: MainAxisSize.min,
            children: [
              const _Wordmark(size: 18),
              if (status.profile.isNotEmpty) ...[
                Container(width: 1, height: 20, margin: const EdgeInsets.symmetric(horizontal: 12), color: UPalette.lineStrong),
                // Имя кошелька целиком: раньше мелкая серая строка рядом с названием читалась как обрывок («N»).
                Text(status.profile, key: const Key('wallet-profile-name'), maxLines: 1, style: uiStyle(14, weight: FontWeight.w600, color: UPalette.text2)),
              ],
              const SizedBox(width: 10),
              // Сеть видна всегда: mainnet тоже помечен, чтобы её нельзя было спутать с тестовой.
              _NetworkPill(network: status.network),
            ],
          )
        : Row(
            mainAxisSize: MainAxisSize.min,
            children: [
              const _Wordmark(size: 16),
              if (status.profile.isNotEmpty) ...[
                const SizedBox(width: 8),
                Text(status.profile, key: const Key('wallet-profile-name'), maxLines: 1, style: uiStyle(13, weight: FontWeight.w600, color: UPalette.text2)),
              ],
              const SizedBox(width: 8),
              _NetworkPill(network: status.network, small: true),
            ],
          );
    return Center(
      child: ConstrainedBox(
        constraints: BoxConstraints(minWidth: wide ? 1040 : 0, maxWidth: wide ? 1040 : double.infinity),
        child: Padding(
          padding: EdgeInsets.fromLTRB(wide ? 32 : 18, 10, wide ? 32 : 18, 6),
          child: wide
              ? Row(
                  children: [
                    const ULogo(size: 32),
                    const SizedBox(width: 11),
                    Expanded(child: FittedBox(fit: BoxFit.scaleDown, alignment: Alignment.centerLeft, child: title)),
                    const SizedBox(width: 8),
                    Expanded(flex: 4, child: FittedBox(fit: BoxFit.scaleDown, alignment: Alignment.centerRight, child: toolbar)),
                  ],
                )
              // Телефон: название сверху, под ним вся линия значков на всю ширину.
              : Column(
                  crossAxisAlignment: CrossAxisAlignment.stretch,
                  children: [
                    Row(children: [
                      const ULogo(size: 28),
                      const SizedBox(width: 10),
                      Expanded(child: FittedBox(fit: BoxFit.scaleDown, alignment: Alignment.centerLeft, child: title)),
                    ]),
                    const SizedBox(height: 8),
                    FittedBox(fit: BoxFit.scaleDown, alignment: Alignment.center, child: toolbar),
                  ],
                ),
        ),
      ),
    );
  }
}

/// «Пощупать будущее» в шапке: значок-колба + подпись «вкл/выкл». Включено — фиолетовый.
class _FutureToggle extends StatelessWidget {
  const _FutureToggle({required this.on, required this.onTap, this.compact = false});
  final bool on;
  final VoidCallback onTap;
  /// На телефоне — только значок-колба (подпись в подсказке), чтобы линия влезла.
  final bool compact;

  @override
  Widget build(BuildContext context) {
    final S s = AppLocale.of(context).s;
    return Tooltip(
      message: '${s.future}\n${on ? s.futureOnHint : s.futureOffHint}',
      child: Semantics(
        button: true,
        toggled: on,
        label: s.future,
        child: InkWell(
          key: const Key('wallet-future'),
          borderRadius: BorderRadius.circular(999),
          onTap: onTap,
          child: Container(
            height: 30,
            margin: const EdgeInsets.symmetric(horizontal: 4),
            padding: const EdgeInsets.symmetric(horizontal: 9),
            decoration: BoxDecoration(
              color: on ? UPalette.violetBg : Colors.transparent,
              border: Border.all(color: on ? const Color(0x57A78BFA) : UPalette.line),
              borderRadius: BorderRadius.circular(999),
            ),
            child: Row(mainAxisSize: MainAxisSize.min, children: [
              Icon(Icons.science_outlined, size: 16, color: on ? UPalette.violet : UPalette.text2),
              if (!compact) const SizedBox(width: 5),
              if (!compact) Text(on ? (AppLocale.of(context).lang == 'en' ? 'Future: on' : 'Будущее: вкл') : (AppLocale.of(context).lang == 'en' ? 'Future: off' : 'Будущее: выкл'),
                style: uiStyle(12, weight: FontWeight.w600, color: on ? UPalette.violet : UPalette.text2)),
            ]),
          ),
        ),
      ),
    );
  }
}

class _WideBody extends StatelessWidget {
  const _WideBody({
    required this.core,
    required this.status,
    this.contactPhrase,
    this.contactPublication,
    this.contactChannel,
    required this.transactions,
    required this.contacts,
    this.contactsUnavailable = false,
    required this.delivery,
    required this.autoAccept,
    required this.torRunning,
    required this.onTorStart,
    required this.onOpenChat,
    required this.onSettings,
    required this.onHistory,
    required this.showCheckpointOffer,
    required this.onCheckpointOffer,
    required this.onDismissCheckpointOffer,
    required this.onDeliveryChanged,
    required this.onAutoAcceptChanged,
    required this.onContact,
    this.onAddContact,
    this.onOpenCatalogue,
    required this.onSend,
    required this.onReceive,
    required this.onVerification,
    required this.onRefresh,
    this.torInfo,
    this.messengerOn = true,
    this.onMessengerToggle,
    this.onTorStop,
  });

  final TorStatusInfo? torInfo;
  final bool messengerOn;
  final ValueChanged<bool>? onMessengerToggle;
  final VoidCallback? onTorStop;
  final WalletCore core;
  final WalletStatus status;
  final String? contactPhrase;
  final String? contactPublication;
  final String? contactChannel;
  final List<WalletTx> transactions;
  final List<UContact> contacts;
  final bool contactsUnavailable;
  final String delivery;
  final String autoAccept;
  final bool torRunning;
  final VoidCallback onTorStart;
  final VoidCallback onOpenChat;
  final VoidCallback onSettings;
  final VoidCallback onHistory;
  final bool showCheckpointOffer;
  final VoidCallback onCheckpointOffer;
  final VoidCallback onDismissCheckpointOffer;
  final ValueChanged<String> onDeliveryChanged;
  final ValueChanged<String> onAutoAcceptChanged;
  final ValueChanged<UContact> onContact;
  final VoidCallback? onAddContact;
  final VoidCallback? onOpenCatalogue;
  final VoidCallback onSend;
  final VoidCallback onReceive;
  final VoidCallback onVerification;
  final VoidCallback onRefresh;

  @override
  Widget build(BuildContext context) {
    return Align(
      alignment: Alignment.topCenter,
      child: ConstrainedBox(
        constraints: const BoxConstraints(maxWidth: 1040),
        child: Padding(
          padding: const EdgeInsets.fromLTRB(32, 12, 32, 8),
          // Слева — деньги: баланс, реквизиты, журнал и два списка рядом
          // (входящие slatepack и сообщения). Справа — мессенджер и операции.
          // Низ колонок и пары карточек выровнен.
          child: _BalancedColumns(
            left: [
              _BalanceCard(
                status: status,
                actions: _Actions(onSend: onSend, onReceive: onReceive),
                footer: _VerificationStrip(status: status, onTap: onVerification, onRefresh: onRefresh),
              ),
              if (status.headerProof) ...[
                const SizedBox(height: 8),
                const _FutureStrip(),
              ],
              const SizedBox(height: 10),
              _MyDetailsCard(status: status, contactPhrase: contactPhrase, contactPublication: contactPublication),
              _Notices(core: core, contactChannel: messengerOn ? contactChannel : null, networkNotice: messengerOn, torPhase: torInfo?.phase),
              if (messengerOn)
                _EqualPair(
                  left: InboxCard(core: core, network: status.network, initiallyExpanded: true),
                  right: RecentMessagesCard(contacts: contacts, onOpenChat: onOpenChat),
                )
              else
                InboxCard(core: core, network: status.network, initiallyExpanded: true),
            ],
            rightTop: [
              UCard(
                padding: const EdgeInsets.all(18),
                child: MessengerContent(
                  core: core,
                  delivery: delivery,
                  autoAccept: autoAccept,
                  contacts: contacts,
                  contactsUnavailable: contactsUnavailable,
                  torRunning: torRunning,
                  torPhase: torInfo?.phase,
                  onTorStart: onTorStart,
                  onTorStop: onTorStop,
                  onTorBridges: () => showTorBridgeSettings(context, core),
                  onOpenChat: onOpenChat,
                  onSettings: () => showMessagingChannelSettings(context, core, preferDirect: true),
                  onDelivery: onDeliveryChanged,
                  onAutoAccept: onAutoAcceptChanged,
                  onContact: onContact,
                  onAddContact: onAddContact,
                  onOpenCatalogue: onOpenCatalogue,
                  collapsibleSettings: true,
                  showNetworkNotice: false,
                  showRecentMessages: false,
                  lastTx: latestPayment(transactions),
                  messengerOn: messengerOn,
                  onMessengerToggle: onMessengerToggle,
                ),
              ),
            ],
            rightBottom: _RecentOperations(transactions: transactions, network: status.network, onHistory: onHistory),
          ),
        ),
      ),
    );
  }
}

/// Растягивает ребёнка (карточку) до [minHeight] и сообщает его естественную высоту.
/// Нужен, чтобы выровнять низ соседних карточек и колонок без IntrinsicHeight
/// (внутри есть LayoutBuilder, а он не умеет отдавать «естественные» размеры).
class _FillTo extends SingleChildRenderObjectWidget {
  const _FillTo({required this.minHeight, required this.onNatural, super.child});
  final double minHeight;
  final ValueChanged<double> onNatural;

  @override
  RenderObject createRenderObject(BuildContext context) => _RenderFillTo(minHeight, onNatural);

  @override
  void updateRenderObject(BuildContext context, _RenderFillTo renderObject) {
    renderObject
      ..minHeight = minHeight
      ..onNatural = onNatural;
  }
}

class _RenderFillTo extends RenderProxyBox {
  _RenderFillTo(this._minHeight, this.onNatural);

  double _minHeight;
  ValueChanged<double> onNatural;
  double? _reported;

  set minHeight(double value) {
    if (value == _minHeight) return;
    _minHeight = value;
    markNeedsLayout();
  }

  @override
  void performLayout() {
    final RenderBox? c = child;
    if (c == null) {
      size = constraints.smallest;
      return;
    }
    // Сначала — естественная высота, затем (если нужно) — растянуть до minHeight.
    c.layout(constraints.copyWith(minHeight: 0), parentUsesSize: true);
    final double natural = c.size.height;
    if (_minHeight > natural + 0.5 && constraints.maxHeight >= _minHeight) {
      c.layout(constraints.copyWith(minHeight: _minHeight), parentUsesSize: true);
    }
    size = constraints.constrain(c.size);
    if (_reported == null || (_reported! - natural).abs() > 0.5) {
      _reported = natural;
      final ValueChanged<double> cb = onNatural;
      WidgetsBinding.instance.addPostFrameCallback((_) => cb(natural));
    }
  }
}

/// Две карточки рядом одинаковой высоты (низ ровный).
class _EqualPair extends StatefulWidget {
  const _EqualPair({required this.left, required this.right});
  final Widget left;
  final Widget right;

  @override
  State<_EqualPair> createState() => _EqualPairState();
}

class _EqualPairState extends State<_EqualPair> {
  double _l = 0;
  double _r = 0;

  void _set(bool left, double h) {
    if (!mounted) return;
    setState(() { if (left) { _l = h; } else { _r = h; } });
  }

  @override
  Widget build(BuildContext context) {
    final double target = _l > _r ? _l : _r;
    return Row(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Expanded(child: _FillTo(minHeight: target, onNatural: (double h) => _set(true, h), child: widget.left)),
        const SizedBox(width: 10),
        Expanded(child: _FillTo(minHeight: target, onNatural: (double h) => _set(false, h), child: widget.right)),
      ],
    );
  }
}

/// Две колонки главного экрана с ровным низом: последняя карточка справа
/// дотягивается до низа левой колонки (если правая короче).
class _BalancedColumns extends StatefulWidget {
  const _BalancedColumns({required this.left, required this.rightTop, required this.rightBottom});
  final List<Widget> left;
  final List<Widget> rightTop;
  final Widget rightBottom;

  @override
  State<_BalancedColumns> createState() => _BalancedColumnsState();
}

class _BalancedColumnsState extends State<_BalancedColumns> {
  double _left = 0;
  double _top = 0;
  static const double _gap = 10;

  @override
  Widget build(BuildContext context) {
    final double fill = _left - _top - _gap;
    return Row(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Expanded(
          flex: 3,
          child: SingleChildScrollView(
            child: _FillTo(
              minHeight: 0,
              onNatural: (double h) { if (mounted) setState(() => _left = h); },
              child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: widget.left),
            ),
          ),
        ),
        const SizedBox(width: 20),
        Expanded(
          flex: 2,
          child: SingleChildScrollView(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                _FillTo(
                  minHeight: 0,
                  onNatural: (double h) { if (mounted) setState(() => _top = h); },
                  child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: widget.rightTop),
                ),
                const SizedBox(height: _gap),
                _FillTo(minHeight: fill > 0 ? fill : 0, onNatural: (_) {}, child: widget.rightBottom),
              ],
            ),
          ),
        ),
      ],
    );
  }
}

class _NarrowBody extends StatelessWidget {
  const _NarrowBody({
    required this.core,
    required this.status,
    this.contactPhrase,
    this.contactPublication,
    this.contactChannel,
    required this.transactions,
    required this.delivery,
    required this.autoAccept,
    required this.onOpenMessenger,
    required this.torInfo,
    required this.showCheckpointOffer,
    required this.onCheckpointOffer,
    required this.onDismissCheckpointOffer,
    required this.onHistory,
    required this.onSend,
    required this.onReceive,
    required this.onVerification,
    required this.onRefresh,
    this.messengerOn = true,
  });

  final bool messengerOn;
  final VoidCallback onHistory;
  final WalletCore core;
  final WalletStatus status;
  final String? contactPhrase;
  final String? contactPublication;
  final String? contactChannel;
  final List<WalletTx> transactions;
  final String delivery;
  final String autoAccept;
  final VoidCallback onOpenMessenger;
  final TorStatusInfo? torInfo;
  final bool showCheckpointOffer;
  final VoidCallback onCheckpointOffer;
  final VoidCallback onDismissCheckpointOffer;
  final VoidCallback onSend;
  final VoidCallback onReceive;
  final VoidCallback onVerification;
  final VoidCallback onRefresh;

  @override
  Widget build(BuildContext context) {
    final S s = AppLocale.of(context).s;
    return ListView(
      padding: const EdgeInsets.fromLTRB(18, 2, 18, 20),
      // Блоков стало больше: строим весь список сразу, чтобы нижние не пропадали.
      // Замена (scrollCacheExtent / ScrollCacheExtent) в этой версии Flutter не экспортируется.
      // ignore: deprecated_member_use
      cacheExtent: 4000,
      children: [
        _BalanceCard(
          status: status,
          compact: true,
          actions: _Actions(onSend: onSend, onReceive: onReceive),
          footer: _VerificationStrip(status: status, onTap: onVerification, onRefresh: onRefresh),
        ),
        if (status.headerProof) ...[
          const SizedBox(height: 8),
          const _FutureStrip(),
        ],
        const SizedBox(height: 10),
        // Связь — сразу под балансом: статус Tor и вход в мессенджер видны без прокрутки.
        _TorIndicator(info: torInfo, onTap: onOpenMessenger),
        const SizedBox(height: 10),
        UButton(key: const Key('mobile-messenger'), label: s.messenger, onTap: onOpenMessenger),
        const SizedBox(height: 10),
        _MyDetailsCard(status: status, contactPhrase: contactPhrase, contactPublication: contactPublication),
        _Notices(core: core, contactChannel: messengerOn ? contactChannel : null, networkNotice: messengerOn, torPhase: torInfo?.phase),
        _RecentOperations(transactions: transactions, network: status.network, onHistory: onHistory),
        const SizedBox(height: 10),
        InboxCard(core: core, network: status.network),
        const SizedBox(height: 20),
        Text(s.keysStayOnDevice, textAlign: TextAlign.center, style: uiStyle(11, color: UPalette.text3)),
      ],
    );
  }
}

class _TorIndicator extends StatelessWidget {
  const _TorIndicator({required this.info, required this.onTap});
  final TorStatusInfo? info;
  final VoidCallback onTap;

  @override
  Widget build(BuildContext context) {
    final s = AppLocale.of(context).s;
    final phase = info?.phase ?? TorPhase.unknown;
    final String label = switch (phase) {
      TorPhase.stopped => s.torStatusStopped,
      TorPhase.starting => s.torStatusStarting,
      TorPhase.onionStarted => s.torStatusOnionStarted,
      TorPhase.failed => s.torStatusFailed,
      TorPhase.unknown => s.torStatusUnknown,
    };
    final Color color = switch (phase) {
      TorPhase.onionStarted => UPalette.mint,
      TorPhase.starting || TorPhase.failed => UPalette.amber,
      _ => UPalette.text3,
    };
    return Tooltip(
      message: s.torStatusDetail,
      child: Material(
        color: UPalette.surface,
        borderRadius: BorderRadius.circular(14),
        child: InkWell(
          key: const Key('mobile-tor-status'),
          borderRadius: BorderRadius.circular(14),
          onTap: onTap,
          child: Container(
            padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 12),
            decoration: BoxDecoration(border: Border.all(color: UPalette.line), borderRadius: BorderRadius.circular(14)),
            child: Row(children: [
              Icon(Icons.shield_outlined, size: 18, color: color),
              const SizedBox(width: 8),
              Expanded(child: Text(label, style: uiStyle(12, color: UPalette.text2))),
              const Icon(Icons.chevron_right_rounded, size: 18, color: UPalette.text3),
            ]),
          ),
        ),
      ),
    );
  }
}

/// Public values only. Tapping copies the complete value, never a seed phrase.
class _IdentityLine extends StatelessWidget {
  const _IdentityLine({super.key, required this.label, required this.value});
  final String label;
  final String value;

  @override
  Widget build(BuildContext context) {
    final en = AppLocale.of(context).lang == 'en';
    return Tooltip(
      message: en ? 'Copy $label' : 'Скопировать: $label',
      child: InkWell(
        onTap: () async {
          await Clipboard.setData(ClipboardData(text: value));
          if (context.mounted) showToast(context, en ? 'Copied' : 'Скопировано');
        },
        child: Padding(
          padding: const EdgeInsets.symmetric(vertical: 5),
          child: Row(children: [
            Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
              Text(label, style: uiStyle(10, color: UPalette.text3)),
              // Сокращаем середину: сверяют обычно начало и конец адреса.
              LayoutBuilder(builder: (context, c) => Text(_middleEllipsis(value, c.maxWidth),
                maxLines: 1, overflow: TextOverflow.ellipsis, style: monoStyle(12))),
            ])),
            const SizedBox(width: 8),
            const Icon(Icons.copy_rounded, size: 16, color: UPalette.text2),
          ]),
        ),
      ),
    );
  }
}

/// Помещает [value] в [width] моноширинным шрифтом 12px, вырезая середину.
String _middleEllipsis(String value, double width) {
  if (!width.isFinite) return value;
  final int fit = (width / 7.0).floor();
  if (value.length <= fit || fit < 9) return value;
  final int head = (fit - 1) ~/ 2;
  final int tail = fit - 1 - head;
  return '${value.substring(0, head)}…${value.substring(value.length - tail)}';
}

class _BalanceCard extends StatelessWidget {
  const _BalanceCard({required this.status, this.compact = false, this.actions, this.footer});

  final WalletStatus status;
  final bool compact;
  /// «Отправить / Получить» — сразу под суммой, без прокрутки.
  final Widget? actions;
  /// Единственная строка статуса проверки (бейдж + пояснение + «Обновить»).
  final Widget? footer;

  @override
  Widget build(BuildContext context) {
    final S s = AppLocale.of(context).s;
    final WalletBalance b = status.balance;
    final String unit = unitFor(status.network);
    // «Входит» показывается отдельной плашкой; здесь — только
    // «зарезервировано / созревает», если там не ноль.
    // Разбивка баланса — строкой «чипов» сразу под суммой, «всего» — рядом с подписью.
    final bool hasDetails = b.reservedNano != 0 || b.immatureNano != 0 || b.incomingNano != 0;
    return UCard(
      padding: EdgeInsets.fromLTRB(compact ? 16 : 20, compact ? 14 : 18, compact ? 16 : 20, compact ? 14 : 18),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          SectionLabel(s.available),
          const SizedBox(height: 8),
          Tooltip(
            message: '${nanoToGrin(b.availableNano)} $unit',
            child: Row(
              crossAxisAlignment: CrossAxisAlignment.end,
              children: [
                Flexible(
                  child: FittedBox(
                    fit: BoxFit.scaleDown,
                    alignment: Alignment.centerLeft,
                    // Единица вдвое меньше и светлее: глаз сразу находит цифру.
                    child: Text.rich(
                      TextSpan(children: [
                        TextSpan(text: shortGrin(b.availableNano)),
                        TextSpan(text: ' $unit', style: monoStyle(compact ? 17 : 21, weight: FontWeight.w500, color: UPalette.text2, spacing: 0)),
                      ]),
                      style: monoStyle(compact ? 36 : 46, weight: FontWeight.w600, spacing: -1.0),
                    ),
                  ),
                ),
              ],
            ),
          ),
          const SizedBox(height: 4),
          Text(
            hasDetails ? '${s.spendableHint} · ${s.totalLabel.toLowerCase()} ${shortGrin(b.totalNano)} $unit' : s.spendableHint,
            style: uiStyle(13, color: UPalette.text2),
          ),
          if (hasDetails) ...[
            const SizedBox(height: 12),
            Wrap(
              spacing: 8,
              runSpacing: 8,
              children: [
                if (b.incomingNano != 0)
                  _BalanceChip(
                    key: const Key('balance-incoming'),
                    icon: Icons.hourglass_bottom_rounded,
                    accent: true,
                    text: '${s.incomingLabel} ${shortGrin(b.incomingNano)} $unit · ${s.incomingHint}',
                    tooltip: '${nanoToGrin(b.incomingNano)} $unit',
                  ),
                if (b.reservedNano != 0)
                  _BalanceChip(text: '${s.reservedLabel} ${shortGrin(b.reservedNano)} $unit', tooltip: s.reservedHint),
                if (b.immatureNano != 0)
                  _BalanceChip(text: '${s.immatureLabel} ${shortGrin(b.immatureNano)} $unit', tooltip: s.immatureHint),
              ],
            ),
          ],
          if (actions != null) ...[
            const SizedBox(height: 16),
            actions!,
          ],
          ?footer,
        ],
      ),
    );
  }
}

/// Часть баланса (входит / зарезервировано / созревает) — компактный «чип».
/// Неподтверждённые входящие выделены янтарным: это главная новость на экране.
class _BalanceChip extends StatelessWidget {
  const _BalanceChip({super.key, required this.text, required this.tooltip, this.icon, this.accent = false});
  final String text;
  final String tooltip;
  final IconData? icon;
  final bool accent;

  @override
  Widget build(BuildContext context) {
    final Color fg = accent ? UPalette.amber : UPalette.text2;
    return Tooltip(
      message: tooltip,
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 11, vertical: 7),
        decoration: BoxDecoration(
          color: accent ? UPalette.amberBg : UPalette.surface2,
          border: Border.all(color: accent ? UPalette.amberLine : UPalette.line),
          borderRadius: BorderRadius.circular(999),
        ),
        child: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            if (icon != null) ...[
              Icon(icon, size: 15, color: fg),
              const SizedBox(width: 6),
            ],
            Flexible(
              child: Text(text, maxLines: 1, overflow: TextOverflow.ellipsis,
                  style: uiStyle(13, weight: accent ? FontWeight.w600 : FontWeight.w400, color: fg)),
            ),
          ],
        ),
      ),
    );
  }
}

/// Название приложения в шапке: «Grin» светлым, «Sight» фирменным золотом.
class _Wordmark extends StatelessWidget {
  const _Wordmark({this.size = 17});
  final double size;

  @override
  Widget build(BuildContext context) {
    return Text.rich(
      TextSpan(children: [
        TextSpan(text: 'Grin', style: uiStyle(size, weight: FontWeight.w800)),
        TextSpan(text: 'Sight', style: uiStyle(size, weight: FontWeight.w800, color: UPalette.gold)),
      ]),
      maxLines: 1,
      semanticsLabel: 'GrinSight',
    );
  }
}

/// Метка сети: TESTNET янтарная, MAINNET нейтральная, но видна всегда.
class _NetworkPill extends StatelessWidget {
  const _NetworkPill({required this.network, this.small = false});
  final String network;
  final bool small;

  @override
  Widget build(BuildContext context) {
    final bool test = network == 'floonet';
    return Container(
      key: const Key('wallet-network'),
      padding: EdgeInsets.symmetric(horizontal: small ? 7 : 9, vertical: small ? 1 : 2),
      decoration: BoxDecoration(
        color: test ? UPalette.amberBg : UPalette.surface2,
        border: Border.all(color: test ? UPalette.amberLine : UPalette.lineStrong),
        borderRadius: BorderRadius.circular(999),
      ),
      child: Text(
        test ? 'TESTNET' : 'MAINNET',
        style: uiStyle(12, weight: FontWeight.w600, color: test ? UPalette.amber : UPalette.text2).copyWith(letterSpacing: 0.4),
      ),
    );
  }
}

/// Контактная фраза и статус её публикации — в окне «Получить», рядом с адресом
/// и QR. На главном экране их больше нет: нужны только когда получаешь деньги.
class ReceivingDetails extends StatelessWidget {
  const ReceivingDetails({super.key, this.contactPhrase, this.contactPublication});

  final String? contactPhrase;
  final String? contactPublication;

  @override
  Widget build(BuildContext context) {
    final bool en = AppLocale.of(context).lang == 'en';
    if (contactPhrase == null && contactPublication == null) return const SizedBox.shrink();
    return Container(
      key: const Key('receive-details'),
      padding: const EdgeInsets.fromLTRB(12, 6, 12, 8),
      decoration: BoxDecoration(color: UPalette.fieldBg, border: Border.all(color: UPalette.line), borderRadius: BorderRadius.circular(14)),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          if (contactPhrase != null) _IdentityLine(
            label: en ? 'Contact phrase (for search in the directory)' : 'Контактная фраза (для поиска в каталоге)',
            value: contactPhrase!, key: const Key('receive-contact-phrase'),
          ),
          if (contactPublication == 'published')
            Text(en ? 'Phrase and address sent to public directory' : 'Фраза и адрес переданы в публичный каталог',
              key: const Key('receive-contact-published'), style: uiStyle(10.5, color: UPalette.text3)),
          if (contactPublication != null && contactPublication != 'published')
            Text(
              en
                ? (contactPublication == 'pending' ? 'Contact publication pending' : contactPublication == 'disabled' ? 'Contact publication disabled' : 'Contact publication unavailable')
                : (contactPublication == 'pending' ? 'Публикация контакта ожидается' : contactPublication == 'disabled' ? 'Публикация контакта выключена' : 'Публикация контакта недоступна'),
              key: const Key('receive-contact-status'),
              style: uiStyle(10.5, color: UPalette.amber),
            ),
        ],
      ),
    );
  }
}

/// «Мои реквизиты» прямо на главном: адрес кошелька и фраза для поиска в Nostr.
/// Нажатие на строку копирует полное значение (сокращена только середина).
/// Только публичные данные — никогда не seed.
class _MyDetailsCard extends StatelessWidget {
  const _MyDetailsCard({required this.status, this.contactPhrase, this.contactPublication});

  final WalletStatus status;
  final String? contactPhrase;
  final String? contactPublication;

  @override
  Widget build(BuildContext context) {
    final bool en = AppLocale.of(context).lang == 'en';
    final String address = status.address ?? '';
    if (address.isEmpty && contactPhrase == null && contactPublication == null) return const SizedBox.shrink();
    return Padding(
      padding: const EdgeInsets.only(bottom: 10),
      child: UCard(
        key: const Key('dashboard-identity'),
        padding: const EdgeInsets.fromLTRB(16, 10, 12, 8),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            // Wrap, а не Row: на узком телефоне подсказка уходит на вторую строку,
            // а не вылезает за край.
            Wrap(
              alignment: WrapAlignment.spaceBetween,
              crossAxisAlignment: WrapCrossAlignment.center,
              spacing: 8,
              runSpacing: 2,
              children: [
                SectionLabel(en ? 'My details' : 'Мои реквизиты'),
                Text(en ? 'tap to copy' : 'нажмите, чтобы скопировать', style: uiStyle(10.5, color: UPalette.text3)),
              ],
            ),
            const SizedBox(height: 2),
            if (address.isNotEmpty)
              _IdentityLine(label: en ? 'Wallet address' : 'Адрес кошелька', value: address, key: const Key('dashboard-wallet-address')),
            if (contactPhrase != null)
              _IdentityLine(label: en ? 'Phrase for Nostr search' : 'Фраза для поиска в Nostr', value: contactPhrase!, key: const Key('dashboard-contact-phrase')),
            if (contactPublication == 'published')
              Text(en ? 'Phrase and address sent to public directory' : 'Фраза и адрес переданы в публичный каталог',
                key: const Key('dashboard-contact-published'), style: uiStyle(10.5, color: UPalette.text3)),
            if (contactPublication != null && contactPublication != 'published')
              Text(
                en
                  ? (contactPublication == 'pending' ? 'Contact publication pending' : contactPublication == 'disabled' ? 'Contact publication disabled' : 'Contact publication unavailable')
                  : (contactPublication == 'pending' ? 'Публикация контакта ожидается' : contactPublication == 'disabled' ? 'Публикация контакта выключена' : 'Публикация контакта недоступна'),
                key: const Key('dashboard-contact-status'),
                style: uiStyle(10.5, color: UPalette.amber),
              ),
          ],
        ),
      ),
    );
  }
}

/// Журнал предупреждений и ошибок главного экрана. Свёрнут в одну строку
/// (самое важное сейчас + счётчик); раскрывается списком. У каждой записи «?» —
/// что это значит и что сделать. Пусто — блок не занимает места.
class _Notices extends StatefulWidget {
  const _Notices({required this.core, this.contactChannel, this.networkNotice = true, this.torPhase});

  final WalletCore core;
  final String? contactChannel;
  /// Ошибки мессенджера не опрашиваются, когда он выключен.
  final bool networkNotice;
  final TorPhase? torPhase;

  @override
  State<_Notices> createState() => _NoticesState();
}

class _NoticesState extends State<_Notices> {
  bool _open = false;

  void _help(BuildContext context, String kind) {
    final bool en = AppLocale.of(context).lang == 'en';
    final h = logHelp(kind, en);
    showDialog<void>(
      context: context,
      builder: (BuildContext ctx) => AlertDialog(
        backgroundColor: UPalette.surface2,
        title: Text(h.title, style: uiStyle(15, weight: FontWeight.w600)),
        content: SizedBox(
          width: 440,
          child: Column(mainAxisSize: MainAxisSize.min, crossAxisAlignment: CrossAxisAlignment.start, children: [
            Text(en ? 'What it means' : 'Что это значит', style: uiStyle(11.5, weight: FontWeight.w700, color: UPalette.text3)),
            const SizedBox(height: 3),
            Text(h.meaning, style: uiStyle(12.5, color: UPalette.text2, height: 1.45)),
            const SizedBox(height: 12),
            Text(en ? 'What to do' : 'Что сделать', style: uiStyle(11.5, weight: FontWeight.w700, color: UPalette.text3)),
            const SizedBox(height: 3),
            Text(h.fix, style: uiStyle(12.5, color: UPalette.text, height: 1.45)),
          ]),
        ),
        actions: [TextButton(onPressed: () => Navigator.of(ctx).pop(), child: Text(AppLocale.of(context).s.close))],
      ),
    );
  }

  Widget _helpButton(BuildContext context, String kind, {Key? key}) => Tooltip(
    message: AppLocale.of(context).lang == 'en' ? 'What it means and how to fix' : 'Что это значит и как решить',
    child: InkWell(
      key: key,
      borderRadius: BorderRadius.circular(999),
      onTap: () => _help(context, kind),
      child: Container(
        width: 26, height: 26,
        alignment: Alignment.center,
        decoration: BoxDecoration(border: Border.all(color: UPalette.lineStrong), borderRadius: BorderRadius.circular(999)),
        child: Text('?', style: uiStyle(12.5, weight: FontWeight.w700, color: UPalette.text2)),
      ),
    ),
  );

  @override
  Widget build(BuildContext context) {
    final bool en = AppLocale.of(context).lang == 'en';
    return Column(
      key: const Key('wallet-notices'),
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        // Опрос ошибок мессенджера: сам ничего не рисует, пишет в журнал.
        if (widget.networkNotice)
          MessengerNetworkNotice(
            core: widget.core,
            silent: true,
            onReport: (String raw) {
              final String kind = classifyError(raw);
              EventLog.instance.add(kind, logHelp(kind, en).title, level: LogLevel.warning);
            },
          ),
        ListenableBuilder(
          listenable: EventLog.instance,
          builder: (BuildContext context, _) {
            // Действующие состояния (пока условие есть) + события сеанса.
            final List<String> active = <String>[
              if (widget.contactChannel == 'direct') 'nostr_ip',
              if (widget.torPhase == TorPhase.failed) 'tor_failed',
            ];
            final List<LogEntry> events = EventLog.instance.items;
            final int total = active.length + events.length;
            if (total == 0) return const SizedBox.shrink();
            final bool hasError = events.any((LogEntry e) => e.level == LogLevel.error);
            final String headKind = active.isNotEmpty ? active.first : events.first.kind;
            // В заголовке — короткое название вида проблемы; подробный текст — в списке.
            final String headText = logHelp(headKind, en).title;
            final Color tone = hasError && active.isEmpty ? UPalette.red : UPalette.amber;
            String time(DateTime t) => '${t.hour.toString().padLeft(2, '0')}:${t.minute.toString().padLeft(2, '0')}';
            return Padding(
              padding: const EdgeInsets.only(bottom: 10),
              child: Container(
                decoration: BoxDecoration(color: UPalette.amberBg, border: Border.all(color: UPalette.amberLine), borderRadius: BorderRadius.circular(12)),
                child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
                  Material(
                    color: Colors.transparent,
                    child: InkWell(
                      key: active.contains('nostr_ip') ? const Key('dashboard-ip-notice') : const Key('notices-toggle'),
                      borderRadius: BorderRadius.circular(12),
                      onTap: () => setState(() => _open = !_open),
                      child: Padding(
                        padding: const EdgeInsets.fromLTRB(12, 8, 8, 8),
                        child: Row(children: [
                          Icon(Icons.warning_amber_rounded, size: 16, color: tone),
                          const SizedBox(width: 8),
                          Expanded(child: Text(headText, maxLines: 1, overflow: TextOverflow.ellipsis, style: uiStyle(12.5, color: UPalette.text2))),
                          const SizedBox(width: 6),
                          _helpButton(context, headKind),
                          const SizedBox(width: 6),
                          Container(
                            padding: const EdgeInsets.symmetric(horizontal: 7, vertical: 1),
                            decoration: BoxDecoration(color: UPalette.line, borderRadius: BorderRadius.circular(999)),
                            child: Text('$total', style: monoStyle(12, weight: FontWeight.w500, color: UPalette.text2, spacing: 0)),
                          ),
                          AnimatedRotation(
                            turns: _open ? 0.5 : 0,
                            duration: const Duration(milliseconds: 160),
                            child: const Icon(Icons.keyboard_arrow_down_rounded, size: 20, color: UPalette.text3),
                          ),
                        ]),
                      ),
                    ),
                  ),
                  if (_open) ...[
                    Container(height: 1, color: UPalette.amberLine),
                    for (final String kind in active)
                      Padding(
                        padding: const EdgeInsets.fromLTRB(12, 6, 8, 6),
                        child: Row(children: [
                          Text(en ? 'now' : 'сейчас', style: monoStyle(11, weight: FontWeight.w500, color: UPalette.amber, spacing: 0)),
                          const SizedBox(width: 10),
                          Expanded(child: Text(logHelp(kind, en).title, style: uiStyle(12, color: UPalette.text2))),
                          _helpButton(context, kind, key: Key('notice-help-$kind')),
                        ]),
                      ),
                    for (final LogEntry e in events)
                      Padding(
                        padding: const EdgeInsets.fromLTRB(12, 6, 8, 6),
                        child: Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
                          Text(time(e.time), style: monoStyle(11, weight: FontWeight.w500, color: e.level == LogLevel.error ? UPalette.red : UPalette.amber, spacing: 0)),
                          const SizedBox(width: 10),
                          Expanded(child: Text(e.count > 1 ? '${e.text}  ×${e.count}' : e.text, maxLines: 3, overflow: TextOverflow.ellipsis, style: uiStyle(12, color: UPalette.text2))),
                          _helpButton(context, e.kind),
                        ]),
                      ),
                    if (events.isNotEmpty)
                      Align(
                        alignment: Alignment.centerRight,
                        child: TextButton(
                          key: const Key('notices-clear'),
                          onPressed: EventLog.instance.clear,
                          child: Text(en ? 'Clear log' : 'Очистить журнал', style: uiStyle(11.5, color: UPalette.text2)),
                        ),
                      ),
                  ],
                ]),
              ),
            );
          },
        ),
      ],
    );
  }
}


/// Единственный индикатор проверки на кошельке: доказан / не проверен /
/// режим «Будущее» (эксперимент).
class _StatusBadge extends StatelessWidget {
  const _StatusBadge({required this.status});

  final WalletStatus status;

  @override
  Widget build(BuildContext context) {
    final S s = AppLocale.of(context).s;
    // Бейдж показывает фактическую проверку; режим «будущее» её не меняет.
    final bool verified = status.proof.verified;
    final Color c = verified ? UPalette.mint : UPalette.amber;
    final Color bg = verified ? UPalette.mintBg : UPalette.amberBg;
    final Color line = verified ? UPalette.mintLine : UPalette.amberLine;
    final IconData icon = verified ? Icons.verified : Icons.help_outline;
    final String label = verified ? s.proven : s.notVerified;
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 9, vertical: 4),
      decoration: BoxDecoration(color: bg, border: Border.all(color: line), borderRadius: BorderRadius.circular(999)),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(icon, size: 13, color: c),
          const SizedBox(width: 4),
          Text(label.toUpperCase(), style: uiStyle(12, weight: FontWeight.w700, color: c).copyWith(letterSpacing: 0.5)),
        ],
      ),
    );
  }
}

class _FutureStrip extends StatelessWidget {
  const _FutureStrip();

  @override
  Widget build(BuildContext context) {
    final S s = AppLocale.of(context).s;
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
      decoration: BoxDecoration(
        color: UPalette.violetBg,
        border: Border.all(color: const Color(0x57A78BFA)),
        borderRadius: BorderRadius.circular(14),
      ),
      child: Row(
        children: [
          const Icon(Icons.science_outlined, size: 18, color: UPalette.violet),
          const SizedBox(width: 9),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(s.futureNoCheckpoint, style: uiStyle(11.5, weight: FontWeight.w700, color: UPalette.violet)),
                const SizedBox(height: 2),
                Text(s.futureNoCheckpointNote, style: uiStyle(10.5, color: UPalette.text2, height: 1.4)),
              ],
            ),
          ),
        ],
      ),
    );
  }
}

/// Единственная строка статуса проверки — внизу карточки баланса:
/// бейдж (ДОКАЗАН / НЕ ПРОВЕРЕНО) + пояснение + «Обновить» + настройки проверки.
class _VerificationStrip extends StatelessWidget {
  const _VerificationStrip({required this.status, required this.onTap, required this.onRefresh});

  final WalletStatus status;
  final VoidCallback onTap;
  final VoidCallback onRefresh;

  static const BoxDecoration _divider = BoxDecoration(border: Border(top: BorderSide(color: UPalette.line)));

  @override
  Widget build(BuildContext context) {
    final S s = AppLocale.of(context).s;
    final WalletProof p = status.proof;
    // Единый критерий с бейджем и окном «Проверка»: WalletProof.verified
    // (сессия свежая, можно тратить И файл баланса привязан к ней).
    final bool ok = p.verified && p.tipHeight != null;
    final String text = ok
        ? s.proofLine(p.tipHeight!, p.independentNets, p.tipAgeSeconds ?? 0)
        : !p.balanceOk && p.hasSession
            ? s.balanceUnproven
            : p.hasSession
                ? s.staleProof
                : s.refreshNeeded;
    final RefreshScope? refresh = RefreshScope.maybeOf(context);
    if (refresh != null && refresh.active) {
      // Идёт обновление: прогресс-полоса, этап и «Отмена» вместо кнопки.
      return Container(
        margin: const EdgeInsets.only(top: 14),
        padding: const EdgeInsets.only(top: 12),
        decoration: _divider,
        child: Row(
          children: [
            const Icon(Icons.sync_rounded, size: 18, color: UPalette.mint),
            const SizedBox(width: 9),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                mainAxisSize: MainAxisSize.min,
                children: [
                  Text(
                    refresh.phase.isNotEmpty ? refresh.phase : s.refreshing,
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                    style: uiStyle(12, weight: FontWeight.w600, color: UPalette.text2),
                  ),
                  const SizedBox(height: 6),
                  ClipRRect(
                    borderRadius: BorderRadius.circular(3),
                    child: const LinearProgressIndicator(
                      key: Key('refresh-progress'),
                      minHeight: 4,
                      color: UPalette.mint,
                      backgroundColor: UPalette.line,
                    ),
                  ),
                ],
              ),
            ),
            const SizedBox(width: 8),
            UButton(key: const Key('refresh-cancel'), label: s.jobCancel, dense: true, height: 36, expand: false, onTap: refresh.onCancel),
          ],
        ),
      );
    }
    final Widget badge = Align(
      alignment: Alignment.centerLeft,
      child: FittedBox(fit: BoxFit.scaleDown, alignment: Alignment.centerLeft, child: _StatusBadge(status: status)),
    );
    final Widget label = Text(
      text,
      maxLines: 2,
      softWrap: true,
      overflow: TextOverflow.ellipsis,
      style: uiStyle(12, color: ok ? UPalette.text2 : UPalette.text),
    );
    // Кнопка доступна и для свежего доказательства: можно проверить новые блоки.
    final Widget refreshButton = UButton(key: const Key('refresh-start'), label: s.refreshAction, dense: true, height: 36, expand: false, onTap: onRefresh);
    final Widget options = UIconButton(key: const Key('wallet-verification-options'), icon: Icons.tune_rounded, size: 36, iconSize: 17, onTap: onTap, tooltip: s.verifyRowHint);
    return Container(
      margin: const EdgeInsets.only(top: 14),
      padding: const EdgeInsets.only(top: 10),
      decoration: _divider,
      child: Material(
        color: Colors.transparent,
        child: InkWell(
          borderRadius: BorderRadius.circular(10),
          onTap: ok ? onTap : onRefresh,
          child: LayoutBuilder(builder: (BuildContext context, BoxConstraints box) {
            // Узко: бейдж и кнопки сверху, пояснение — на всю ширину под ними
            // (иначе текст сжимается в колонку из букв).
            if (box.maxWidth < 520) {
              return Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  Row(children: [Expanded(child: badge), options, const SizedBox(width: 4), refreshButton]),
                  const SizedBox(height: 6),
                  label,
                ],
              );
            }
            return Row(
              children: [
                _StatusBadge(status: status),
                const SizedBox(width: 10),
                Expanded(child: label),
                const SizedBox(width: 8),
                options,
                const SizedBox(width: 4),
                refreshButton,
              ],
            );
          }),
        ),
      ),
    );
  }
}

class _Actions extends StatelessWidget {
  const _Actions({required this.onSend, required this.onReceive});

  final VoidCallback onSend;
  final VoidCallback onReceive;

  @override
  Widget build(BuildContext context) {
    final S s = AppLocale.of(context).s;
    return Row(
      children: [
        Expanded(
          child: UButton(key: const Key('wallet-send'), label: s.send, icon: Icons.north_east_rounded, primary: true, height: 56, onTap: onSend),
        ),
        const SizedBox(width: 12),
        Expanded(
          child: UButton(key: const Key('wallet-receive'), label: s.receive, icon: Icons.south_rounded, height: 56, onTap: onReceive),
        ),
      ],
    );
  }
}

class _HistoryPage extends StatelessWidget {
  const _HistoryPage({required this.transactions, required this.network, required this.onBack});
  final List<WalletTx> transactions;
  final String network;
  final VoidCallback onBack;
  @override
  Widget build(BuildContext context) => Center(child: ConstrainedBox(
    constraints: const BoxConstraints(maxWidth: 1040),
    child: ListView(padding: const EdgeInsets.all(18), children: [
      Align(alignment: Alignment.centerLeft, child: TextButton.icon(key: const Key('history-back'), onPressed: onBack, icon: const Icon(Icons.arrow_back), label: Text(AppLocale.of(context).lang == 'en' ? 'Back' : 'Назад'))),
      _HistoryCard(transactions: transactions, network: network),
    ]),
  ));
}

/// Последний платёж (по времени создания, отменённые пропускаются) —
/// его slatepack показываются при ручной доставке.
WalletTx? latestPayment(List<WalletTx> transactions) {
  WalletTx? best;
  for (final WalletTx tx in transactions) {
    if (tx.stage == TxStage.cancelled) continue;
    if (best == null) { best = tx; continue; }
    final int? a = tx.created?.millisecondsSinceEpoch;
    final int? b = best.created?.millisecondsSinceEpoch;
    if (a != null && (b == null || a > b)) best = tx;
  }
  return best;
}

class _RecentOperations extends StatelessWidget {
  const _RecentOperations({required this.transactions, required this.network, required this.onHistory});
  final List<WalletTx> transactions;
  final String network;
  final VoidCallback onHistory;
  @override
  Widget build(BuildContext context) {
    final en = AppLocale.of(context).lang == 'en';
    final ordered = transactions.asMap().entries.toList()..sort((a, b) {
      final at = a.value.created?.millisecondsSinceEpoch;
      final bt = b.value.created?.millisecondsSinceEpoch;
      if (at == null && bt == null) return a.key.compareTo(b.key);
      if (at == null) return 1;
      if (bt == null) return -1;
      final byTime = bt.compareTo(at);
      return byTime == 0 ? a.key.compareTo(b.key) : byTime;
    });
    return UCard(key: const Key('recent-operations'), padding: const EdgeInsets.all(14), child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
      Text(en ? 'Recent operations' : 'Последние операции', style: uiStyle(13, weight: FontWeight.w600)),
      if (transactions.isEmpty) Padding(padding: const EdgeInsets.symmetric(vertical: 12), child: Text(AppLocale.of(context).s.noTransactions, style: uiStyle(12, color: UPalette.text3)))
      else for (final entry in ordered.take(3)) _TxRow(tx: entry.value, unit: unitFor(network)),
      TextButton(key: const Key('recent-all-operations'), onPressed: onHistory, child: Text(en ? 'All operations' : 'Все операции')),
    ]));
  }
}

class _HistoryCard extends StatelessWidget {
  const _HistoryCard({required this.transactions, required this.network});

  final List<WalletTx> transactions;
  final String network;

  @override
  Widget build(BuildContext context) {
    final S s = AppLocale.of(context).s;
    return UCard(
      padding: const EdgeInsets.fromLTRB(16, 6, 16, 4),
      child: UExpandSection(
        title: Text(s.historyTitle, style: uiStyle(14, weight: FontWeight.w600)),
        count: transactions.length,
        child: transactions.isEmpty
            ? Padding(
                padding: const EdgeInsets.symmetric(vertical: 14),
                child: Tooltip(
                  message: s.noTransactionsRestoredNote,
                  child: Text(s.noTransactions, textAlign: TextAlign.center, style: uiStyle(12, color: UPalette.text3)),
                ),
              )
            : LayoutBuilder(builder: (context, constraints) {
                final columns = constraints.maxWidth >= 510;
                final groups = <Widget>[
                  _group(context, 'cancelled', transactions.where((tx) => tx.stage == TxStage.cancelled).toList(), initiallyExpanded: false, compact: columns),
                  _group(context, 'incoming', transactions.where((tx) => tx.stage != TxStage.cancelled && tx.incoming).toList(), compact: columns),
                  _group(context, 'outgoing', transactions.where((tx) => tx.stage != TxStage.cancelled && !tx.incoming).toList(), compact: columns),
                ];
                if (!columns) return Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: groups);
                return Row(key: const Key('history-columns'), crossAxisAlignment: CrossAxisAlignment.start,
                  children: [for (var i = 0; i < groups.length; i++) ...[
                    if (i > 0) const SizedBox(width: 12),
                    Expanded(child: groups[i]),
                  ]]);
              }),
      ),
    );
  }

  Widget _group(BuildContext context, String group, List<WalletTx> items, {bool initiallyExpanded = true, bool compact = false}) {
    final en = AppLocale.of(context).lang == 'en';
    final label = switch (group) {
      'cancelled' => en ? 'Cancelled' : 'Отменённые',
      'incoming' => en ? 'Incoming' : 'Входящие',
      _ => en ? 'Outgoing' : 'Исходящие',
    };
    return UExpandSection(
      key: ValueKey('history-group-$group'),
      title: Text(label, style: uiStyle(12.5, weight: FontWeight.w600, color: UPalette.text2)),
      count: items.length,
      initiallyExpanded: initiallyExpanded,
      child: Column(crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          if (group == 'cancelled' && items.isNotEmpty && PaymentActions.maybeOf(context)?.onHideAllCancelled != null)
            TextButton(key: const Key('hide-all-cancelled'), onPressed: PaymentActions.maybeOf(context)!.onHideAllCancelled,
              child: Text(en ? 'Remove all' : 'Удалить все', textAlign: TextAlign.center)),
          for (final tx in items)
            if (compact) _CompactTxCard(tx: tx, unit: unitFor(network)) else _TxRow(tx: tx, unit: unitFor(network)),
        ]),
    );
  }
}

/// Compact symbols always have a full, localized status for assistive tech.
class _TxStatus extends StatelessWidget {
  const _TxStatus({required this.tx});
  final WalletTx tx;

  @override
  Widget build(BuildContext context) {
    final s = AppLocale.of(context).s;
    final label = s.txStatusLabel(tx.stage, tx.direction, block: tx.height, confirmations: tx.confirmations);
    final symbol = switch (tx.stage) {
      TxStage.waitingAnswer => '⏳',
      TxStage.finalized => '📝',
      TxStage.broadcast => '📡',
      TxStage.inBlock => '📦',
      TxStage.confirmed => '✅',
      TxStage.reorged => '⚠️',
      TxStage.cancelled => '🚫',
      TxStage.unknown => '❔',
    };
    final depth = tx.stage == TxStage.confirmed
        ? ' ${tx.confirmations}' : tx.stage == TxStage.inBlock && tx.height != null ? ' ${tx.height}' : '';
    return Tooltip(message: label, child: Semantics(label: label, excludeSemantics: true,
      child: Text('$symbol$depth', key: Key('tx-status-${tx.txId}'), style: uiStyle(13))));
  }
}

/// A narrow operation card for the three-column desktop history.
class _CompactTxCard extends StatelessWidget {
  const _CompactTxCard({required this.tx, required this.unit});
  final WalletTx tx;
  final String unit;

  @override
  Widget build(BuildContext context) {
    final locale = AppLocale.of(context);
    final s = locale.s;
    final actions = PaymentActions.maybeOf(context);
    final peer = tx.counterparty;
    final short = peer.length > 18 ? '${peer.substring(0, 8)}…${peer.substring(peer.length - 6)}' : peer;
    final canConfirm = tx.kind == 'send' && !tx.incoming &&
      (tx.stage == TxStage.broadcast || tx.stage == TxStage.inBlock || tx.stage == TxStage.confirmed || tx.stage == TxStage.unknown || tx.stage == TxStage.reorged);
    final canResume = tx.backupRetry || (tx.kind == 'send' && !tx.incoming && tx.stage == TxStage.waitingAnswer);
    final canCancel = !tx.incoming && tx.stage == TxStage.waitingAnswer;
    final en = locale.lang == 'en';
    Widget action({required String keyName, required String tip, required IconData icon, required VoidCallback? tap}) =>
      Tooltip(message: tip, child: TextButton(key: Key(keyName), onPressed: tap,
        style: TextButton.styleFrom(padding: EdgeInsets.zero, minimumSize: const Size(36, 36),
          tapTargetSize: MaterialTapTargetSize.shrinkWrap, foregroundColor: UPalette.text2),
        child: Icon(icon, size: 17)));
    return Container(
      padding: const EdgeInsets.symmetric(vertical: 8),
      decoration: const BoxDecoration(border: Border(top: BorderSide(color: UPalette.line))),
      child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
        Row(children: [
          _TxStatus(tx: tx),
          const SizedBox(width: 5),
          Expanded(child: Text(_txAmount(tx, unit),
            textAlign: TextAlign.right, maxLines: 1, overflow: TextOverflow.ellipsis,
            style: monoStyle(11.5, weight: FontWeight.w600, color: _txAmountColor(tx)))),
        ]),
        if (short.isNotEmpty) ...[
          const SizedBox(height: 4),
          Tooltip(message: peer, child: Text(short, maxLines: 1, overflow: TextOverflow.ellipsis, style: uiStyle(11, color: UPalette.text3))),
        ],
        if (tx.feeNano != null) Text(s.feeLine('${nanoToGrin(tx.feeNano!)} $unit'), maxLines: 1,
          overflow: TextOverflow.ellipsis, style: uiStyle(10, color: UPalette.text3)),
        // Доказательство платежа действительно, только когда платёж в блоке: до этого — серым, без «галочки».
        if (tx.proof) Tooltip(message: s.paymentProof, child: Align(alignment: Alignment.centerLeft,
          child: Icon(_proofFinal(tx) ? Icons.verified : Icons.receipt_long_outlined, size: 14,
            color: _proofFinal(tx) ? UPalette.mint : UPalette.text3))),
        if (tx.stage != TxStage.cancelled && tx.torStatus?.startsWith('FAILED') == true)
          Tooltip(message: s.torHistoryFailed, child: Text(s.torHistoryFailed, maxLines: 4,
            overflow: TextOverflow.ellipsis, style: uiStyle(10, color: UPalette.amber))),
        if (actions != null && (canConfirm || canResume || canCancel || tx.stage == TxStage.cancelled))
          Wrap(alignment: WrapAlignment.end, spacing: 0, children: [
            if (canConfirm) action(keyName: 'confirm-${tx.txId}', tip: s.confirmAction, icon: Icons.manage_search_rounded,
              tap: actions.onConfirm == null ? null : () => actions.onConfirm!(tx.txId)),
            if (canResume) action(keyName: 'resume-${tx.txId}', tip: s.resumePayment, icon: Icons.content_paste_go_rounded,
              tap: () => actions.onResume(tx.txId)),
            if (canCancel) action(keyName: 'cancel-${tx.txId}', tip: s.cancelPayment, icon: Icons.cancel_outlined,
              tap: () => actions.onCancel(tx.txId)),
            if (tx.stage == TxStage.cancelled && actions.onHideCancelled != null)
              action(keyName: 'hide-cancelled-${tx.txId}', tip: en ? 'Remove from list' : 'Удалить из списка', icon: Icons.delete_outline_rounded,
                tap: () => actions.onHideCancelled!(tx.txId)),
          ]),
      ]),
    );
  }
}

class _TxRow extends StatelessWidget {
  const _TxRow({required this.tx, required this.unit});

  final WalletTx tx;
  final String unit;

  ({Color color, Color bg, Color border, IconData icon}) get _style {
    switch (tx.stage) {
      case TxStage.confirmed:
        return (color: UPalette.mint, bg: UPalette.mintBg, border: UPalette.mintLine, icon: tx.incoming ? Icons.south_rounded : Icons.north_east_rounded);
      case TxStage.inBlock:
        return (color: UPalette.blue, bg: UPalette.blueBg, border: UPalette.blueLine, icon: tx.incoming ? Icons.south_rounded : Icons.north_east_rounded);
      case TxStage.broadcast:
        return (color: UPalette.blue, bg: UPalette.blueBg, border: UPalette.blueLine, icon: tx.incoming ? Icons.south_rounded : Icons.north_east_rounded);
      case TxStage.finalized:
      case TxStage.waitingAnswer:
        return (color: UPalette.amber, bg: UPalette.amberBg, border: UPalette.amberLine, icon: tx.incoming ? Icons.south_rounded : Icons.north_east_rounded);
      case TxStage.reorged:
        return (color: UPalette.red, bg: UPalette.amberBg, border: UPalette.amberLine, icon: Icons.sync_problem_rounded);
      case TxStage.cancelled:
        return (color: UPalette.text3, bg: UPalette.surface3, border: UPalette.line, icon: Icons.block_rounded);
      case TxStage.unknown:
        return (color: UPalette.amber, bg: UPalette.amberBg, border: UPalette.amberLine, icon: Icons.help_outline);
    }
  }

  @override
  Widget build(BuildContext context) {
    final AppLocale locale = AppLocale.of(context);
    final S s = locale.s;
    final style = _style;
    return Container(
      padding: const EdgeInsets.symmetric(vertical: 5),
      decoration: const BoxDecoration(border: Border(top: BorderSide(color: UPalette.line))),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Container(
            width: 30,
            height: 30,
            margin: const EdgeInsets.only(top: 1),
            decoration: BoxDecoration(color: style.bg, border: Border.all(color: style.border), borderRadius: BorderRadius.circular(8)),
            child: Icon(style.icon, size: 15, color: style.color),
          ),
          const SizedBox(width: 10),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  s.txDirectionLabel(tx.direction),
                  style: uiStyle(12.5, weight: FontWeight.w600, color: tx.stage == TxStage.cancelled ? UPalette.text3 : UPalette.text),
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                ),
                const SizedBox(height: 1),
                // «подтверждён» уже есть в бейдже справа: не повторять.
                if (_subtitle(s).isNotEmpty)
                  Text(
                    _subtitle(s),
                    style: uiStyle(12, color: UPalette.text3),
                    maxLines: 2,
                    overflow: TextOverflow.ellipsis,
                  ),
                if (tx.proof) ...[
                  const SizedBox(height: 1),
                  Row(
                    children: [
                      Icon(_proofFinal(tx) ? Icons.verified : Icons.receipt_long_outlined, size: 12,
                          color: _proofFinal(tx) ? UPalette.mint : UPalette.text3),
                      const SizedBox(width: 3),
                      Flexible(
                        child: Text(
                          s.paymentProof,
                          style: uiStyle(12, color: _proofFinal(tx) ? UPalette.mint : UPalette.text3),
                          maxLines: 1,
                          overflow: TextOverflow.ellipsis,
                        ),
                      ),
                    ],
                  ),
                ],
              ],
            ),
          ),
          const SizedBox(width: 8),
          // Ширина по содержимому (до 150): в узкой колонке остаётся место
          // под адрес и статус, без обрезки «доказательс…».
          ConstrainedBox(
            constraints: const BoxConstraints(maxWidth: 150),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.end,
              children: [
                Text(
                  _txAmount(tx, unit),
                  textAlign: TextAlign.right,
                  style: monoStyle(11.5, weight: FontWeight.w600, color: _txAmountColor(tx), spacing: -0.2),
                ),
                const SizedBox(height: 2),
                _TxStatus(tx: tx),
                if (tx.feeNano != null) ...[
                  const SizedBox(height: 2),
                  Text(s.feeLine('${nanoToGrin(tx.feeNano!)} $unit'), style: uiStyle(10.5, color: UPalette.text3)),
                ],
                if (tx.stage == TxStage.cancelled && PaymentActions.maybeOf(context)?.onHideCancelled != null)
                  TextButton(
                    key: Key('hide-cancelled-${tx.txId}'),
                    onPressed: () => PaymentActions.maybeOf(context)!.onHideCancelled!(tx.txId),
                    child: Text(locale.lang == 'en' ? 'Remove from list' : 'Удалить из списка', style: uiStyle(11)),
                  ),
                if (tx.stage != TxStage.cancelled && tx.torStatus?.startsWith('FAILED') == true) ...[
                  const SizedBox(height: 2),
                  Text(s.torHistoryFailed, style: uiStyle(10.5, color: UPalette.amber)),
                ],
                if (tx.kind == 'send' && !tx.incoming &&
                    (tx.stage == TxStage.broadcast || tx.stage == TxStage.inBlock ||
                     tx.stage == TxStage.confirmed || tx.stage == TxStage.unknown || tx.stage == TxStage.reorged) &&
                    PaymentActions.maybeOf(context) != null)
                  TextButton(
                    key: Key('confirm-${tx.txId}'),
                    style: TextButton.styleFrom(padding: const EdgeInsets.symmetric(horizontal: 6), minimumSize: const Size(0, 30), tapTargetSize: MaterialTapTargetSize.shrinkWrap),
                    onPressed: PaymentActions.maybeOf(context)!.onConfirm == null
                        ? null : () => PaymentActions.maybeOf(context)!.onConfirm!(tx.txId),
                    child: Text(s.confirmAction, textAlign: TextAlign.right, style: uiStyle(11.5, weight: FontWeight.w600, color: UPalette.blue)),
                  ),
                // После финализации или рассылки отмена уже невозможна.
                if ((tx.backupRetry || (tx.kind == 'send' && !tx.incoming && tx.stage == TxStage.waitingAnswer)) && PaymentActions.maybeOf(context) != null)
                  TextButton(
                    key: Key('resume-${tx.txId}'),
                    style: TextButton.styleFrom(padding: const EdgeInsets.symmetric(horizontal: 6), minimumSize: const Size(0, 30), tapTargetSize: MaterialTapTargetSize.shrinkWrap),
                    onPressed: () => PaymentActions.maybeOf(context)!.onResume(tx.txId),
                    child: Text(s.resumePayment, textAlign: TextAlign.right, style: uiStyle(11.5, weight: FontWeight.w600, color: UPalette.blue)),
                  ),
                if (!tx.incoming && tx.stage == TxStage.waitingAnswer && PaymentActions.maybeOf(context) != null)
                  TextButton(
                    key: Key('cancel-${tx.txId}'),
                    style: TextButton.styleFrom(padding: const EdgeInsets.symmetric(horizontal: 6), minimumSize: const Size(0, 30), tapTargetSize: MaterialTapTargetSize.shrinkWrap),
                    onPressed: () => PaymentActions.maybeOf(context)!.onCancel(tx.txId),
                    child: Text(s.cancelPayment, style: uiStyle(11.5, weight: FontWeight.w600, color: UPalette.amber)),
                  ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  String _subtitle(S s) {
    final String note = tx.stage == TxStage.confirmed ? '' : s.txNote(tx);
    final String who = tx.counterparty.isEmpty ? '' : _shortAddress(tx.counterparty);
    if (who.isEmpty) return note;
    return note.isEmpty ? who : '$who · $note';
  }

  static String _shortAddress(String value) {
    if (value.length <= 18) return value;
    return '${value.substring(0, 8)}…${value.substring(value.length - 6)}';
  }
}




/// Web-only iPhone/PWA shell: the minimal concept hierarchy from the design
/// mock, without desktop cards or native navigation.
class _WebConceptShell extends StatefulWidget {
  const _WebConceptShell({
    required this.status,
    required this.transactions,
    required this.onSettings,
    required this.onSend,
    required this.onReceive,
    required this.onOpenMessenger,
    required this.onVerification,
    required this.onRefresh,
  });

  final WalletStatus status;
  final List<WalletTx> transactions;
  final VoidCallback onSettings;
  final VoidCallback onSend;
  final VoidCallback onReceive;
  final VoidCallback onOpenMessenger;
  final VoidCallback onVerification;
  final VoidCallback onRefresh;

  @override
  State<_WebConceptShell> createState() => _WebConceptShellState();
}

class _WebConceptShellState extends State<_WebConceptShell> {
  bool _history = false;

  @override
  Widget build(BuildContext context) {
    final S s = AppLocale.of(context).s;
    return SafeArea(
      bottom: true,
      child: Column(
        children: [
          Padding(
            padding: const EdgeInsets.fromLTRB(20, 10, 14, 4),
            child: Row(
              children: [
                const ULogo(size: 30),
                const SizedBox(width: 9),
                Text('GrinSight', style: uiStyle(16, weight: FontWeight.w800).copyWith(letterSpacing: -0.3)),
                if (widget.status.network == 'floonet') ...[
                  const SizedBox(width: 8),
                  Container(
                    padding: const EdgeInsets.symmetric(horizontal: 7, vertical: 2),
                    decoration: BoxDecoration(color: UPalette.amberBg, border: Border.all(color: UPalette.amberLine), borderRadius: BorderRadius.circular(99)),
                    child: Text('TESTNET', style: uiStyle(8.5, weight: FontWeight.w700, color: UPalette.amber)),
                  ),
                ],
                const Spacer(),
                UIconButton(icon: Icons.settings_outlined, onTap: widget.onSettings, tooltip: s.settings, size: 34, iconSize: 18),
              ],
            ),
          ),
          Expanded(
            child: AnimatedSwitcher(
              duration: const Duration(milliseconds: 180),
              child: _history
                  ? _WebHistoryPage(
                      key: const ValueKey('history'),
                      status: widget.status,
                      transactions: widget.transactions,
                      onBack: () => setState(() => _history = false),
                      onRefresh: widget.onRefresh,
                    )
                  : _WebConceptHome(
                      key: const ValueKey('home'),
                      status: widget.status,
                      transactions: widget.transactions,
                      onSend: widget.onSend,
                      onReceive: widget.onReceive,
                      onOpenMessenger: widget.onOpenMessenger,
                      onVerification: widget.onVerification,
                      onAll: () => setState(() => _history = true),
                    ),
            ),
          ),
        ],
      ),
    );
  }
}

class _WebConceptHome extends StatelessWidget {
  const _WebConceptHome({
    super.key,
    required this.status,
    required this.transactions,
    required this.onSend,
    required this.onReceive,
    required this.onOpenMessenger,
    required this.onVerification,
    required this.onAll,
  });

  final WalletStatus status;
  final List<WalletTx> transactions;
  final VoidCallback onSend;
  final VoidCallback onReceive;
  final VoidCallback onOpenMessenger;
  final VoidCallback onVerification;
  final VoidCallback onAll;

  @override
  Widget build(BuildContext context) {
    final S s = AppLocale.of(context).s;
    final b = status.balance;
    final bool verified = status.proof.verified;
    final List<WalletTx> recent = transactions.take(3).toList();
    return ListView(
      padding: const EdgeInsets.fromLTRB(20, 8, 20, 20),
      children: [
        Text(s.available.toUpperCase(), style: uiStyle(9.5, weight: FontWeight.w800, color: UPalette.text3).copyWith(letterSpacing: 1.1)),
        const SizedBox(height: 5),
        Row(
          crossAxisAlignment: CrossAxisAlignment.end,
          children: [
            Flexible(
              child: FittedBox(
                fit: BoxFit.scaleDown,
                alignment: Alignment.centerLeft,
                child: Text('${shortGrin(b.availableNano)} ${unitFor(status.network)}', style: monoStyle(46, weight: FontWeight.w700, spacing: -2.2)),
              ),
            ),
            const Spacer(),
            Container(
              width: 6,
              height: 58,
              decoration: BoxDecoration(
                borderRadius: BorderRadius.circular(99),
                gradient: LinearGradient(begin: Alignment.topCenter, end: Alignment.bottomCenter, colors: verified ? [UPalette.mint, UPalette.mint.withValues(alpha: 0.15)] : [UPalette.amber, UPalette.amber.withValues(alpha: 0.12)]),
              ),
            ),
          ],
        ),
        const SizedBox(height: 3),
        Text(s.spendableHint, style: uiStyle(10.5, color: UPalette.text3)),
        const SizedBox(height: 13),
        _WebProofPill(status: status, onTap: onVerification),
        const SizedBox(height: 14),
        Row(
          children: [
            Expanded(child: UButton(label: s.send, icon: Icons.north_east_rounded, primary: true, height: 54, onTap: onSend)),
            const SizedBox(width: 9),
            Expanded(child: UButton(label: s.receive, icon: Icons.south_rounded, height: 54, onTap: onReceive)),
          ],
        ),
        const SizedBox(height: 12),
        Material(
          color: Colors.transparent,
          child: InkWell(
            borderRadius: BorderRadius.circular(16),
            onTap: onOpenMessenger,
            child: Container(
              padding: const EdgeInsets.symmetric(horizontal: 13, vertical: 12),
              decoration: BoxDecoration(color: UPalette.surface, border: Border.all(color: UPalette.line), borderRadius: BorderRadius.circular(16)),
              child: Row(
                children: [
                  const Icon(Icons.chat_bubble_outline_rounded, size: 18, color: UPalette.mint),
                  const SizedBox(width: 9),
                  Expanded(child: Text(s.messenger, style: uiStyle(12.5, weight: FontWeight.w600))),
                  const Icon(Icons.chevron_right_rounded, size: 18, color: UPalette.text3),
                ],
              ),
            ),
          ),
        ),
        if (status.headerProof) ...[
          const SizedBox(height: 10),
          _FutureStrip(),
        ],
        const SizedBox(height: 18),
        Row(
          children: [
            Expanded(child: Text(s.historyTitle, style: uiStyle(12.5, weight: FontWeight.w700))),
            if (transactions.length > 3)
              GestureDetector(onTap: onAll, child: Text(s.allLink, style: uiStyle(10.5, color: UPalette.text3))),
          ],
        ),
        const SizedBox(height: 8),
        _WebRecent(transactions: recent, network: status.network),
        const SizedBox(height: 13),
        Text(s.keysStayOnDevice, textAlign: TextAlign.center, style: uiStyle(9.5, color: UPalette.text3)),
      ],
    );
  }
}

class _WebProofPill extends StatelessWidget {
  const _WebProofPill({required this.status, required this.onTap});

  final WalletStatus status;
  final VoidCallback onTap;

  @override
  Widget build(BuildContext context) {
    final S s = AppLocale.of(context).s;
    final p = status.proof;
    final bool ok = p.verified;
    final Color c = status.headerProof ? UPalette.violet : (ok ? UPalette.mint : UPalette.amber);
    final Color bg = status.headerProof ? UPalette.violetBg : (ok ? UPalette.mintBg : UPalette.amberBg);
    final Color line = status.headerProof ? UPalette.violet.withValues(alpha: 0.4) : (ok ? UPalette.mintLine : UPalette.amberLine);
    return Material(
      color: Colors.transparent,
      child: InkWell(
        borderRadius: BorderRadius.circular(99),
        onTap: onTap,
        child: Container(
          padding: const EdgeInsets.symmetric(horizontal: 11, vertical: 6),
          decoration: BoxDecoration(color: bg, border: Border.all(color: line), borderRadius: BorderRadius.circular(99)),
          child: Row(
            mainAxisSize: MainAxisSize.min,
            children: [
              Icon(status.headerProof ? Icons.science_outlined : (ok ? Icons.check_circle_outline_rounded : Icons.sync_problem_rounded), size: 14, color: c),
              const SizedBox(width: 6),
              Flexible(
                child: Text(
                  status.headerProof
                      ? '${s.futureBadge} · header-proof'
                      : (ok ? s.proofLine(p.tipHeight ?? 0, p.independentNets, p.tipAgeSeconds ?? 0) : s.refreshNeeded),
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                  style: uiStyle(10.5, weight: FontWeight.w600, color: c),
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

class _WebHistoryPage extends StatelessWidget {
  const _WebHistoryPage({super.key, required this.status, required this.transactions, required this.onBack, required this.onRefresh});

  final WalletStatus status;
  final List<WalletTx> transactions;
  final VoidCallback onBack;
  final VoidCallback onRefresh;

  @override
  Widget build(BuildContext context) {
    final S s = AppLocale.of(context).s;
    return ListView(
      padding: const EdgeInsets.fromLTRB(18, 8, 18, 16),
      children: [
        Row(
          children: [
            UIconButton(icon: Icons.arrow_back_rounded, onTap: onBack, tooltip: s.back, size: 34, iconSize: 18),
            const SizedBox(width: 6),
            Expanded(child: Text(s.historyTitle, style: uiStyle(17, weight: FontWeight.w700))),
            UIconButton(icon: Icons.refresh_rounded, onTap: onRefresh, tooltip: s.update, size: 34, iconSize: 18),
          ],
        ),
        const SizedBox(height: 10),
        _WebRecent(transactions: transactions, network: status.network),
      ],
    );
  }
}

class _WebRecent extends StatelessWidget {
  const _WebRecent({required this.transactions, required this.network});

  final List<WalletTx> transactions;
  final String network;

  @override
  Widget build(BuildContext context) {
    final S s = AppLocale.of(context).s;
    final String unit = unitFor(network);
    return UCard(
      padding: const EdgeInsets.fromLTRB(14, 4, 14, 4),
      child: transactions.isEmpty
          ? Padding(
              padding: const EdgeInsets.symmetric(vertical: 18),
              child: Text(s.noTransactions, textAlign: TextAlign.center, style: uiStyle(12, color: UPalette.text3)),
            )
          : Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [for (final WalletTx tx in transactions) _TxRow(tx: tx, unit: unit)],
            ),
    );
  }
}

/// Доказательство платежа считается действительным, когда платёж уже в блоке
/// проверенной цепи; до этого оно только сохранено.
/// Сумма операции в том же формате, что и баланс (1.00), но без потери точности:
/// если есть знаки дальше сотых — показываем все.
String _txAmount(WalletTx tx, String unit) {
  final int n = tx.amountNano;
  final String v = n % 10000000 == 0 ? shortGrin(n) : nanoToGrin(n);
  return '${tx.incoming ? '+' : '−'}$v $unit';
}

/// Зелёный только когда деньги реально пришли (подтверждено).
/// До этого — янтарный (ждём) или нейтральный (в блоке), отменённые — серые.
Color _txAmountColor(WalletTx tx) {
  switch (tx.stage) {
    case TxStage.confirmed:
      return tx.incoming ? UPalette.mint : UPalette.text;
    case TxStage.inBlock:
    case TxStage.broadcast:
      return UPalette.text;
    case TxStage.cancelled:
      return UPalette.text3;
    case TxStage.reorged:
      return UPalette.red;
    case TxStage.finalized:
    case TxStage.waitingAnswer:
    case TxStage.unknown:
      return UPalette.amber;
  }
}

bool _proofFinal(WalletTx tx) => tx.stage == TxStage.inBlock || tx.stage == TxStage.confirmed;
