import 'package:flutter/material.dart';

import '../components.dart';
import '../core.dart';
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
    required this.transactions,
    required this.contacts,
    required this.delivery,
    required this.autoAccept,
    required this.loading,
    required this.torRunning,
    required this.onTorStart,
    required this.showCheckpointOffer,
    required this.onCheckpointOffer,
    required this.onDismissCheckpointOffer,
    required this.onSettings,
    required this.onLogout,
    required this.onSend,
    required this.onReceive,
    required this.onOpenMessenger,
    required this.onContact,
    required this.onDeliveryChanged,
    required this.onAutoAcceptChanged,
    required this.onVerification,
    required this.onRefresh,
  });

  final WalletCore core;
  final bool wide;
  final WalletStatus status;
  final List<WalletTx> transactions;
  final List<UContact> contacts;
  final String delivery;
  final String autoAccept;
  final bool loading;
  final bool torRunning;
  final VoidCallback onTorStart;
  final bool showCheckpointOffer;
  final VoidCallback onCheckpointOffer;
  final VoidCallback onDismissCheckpointOffer;
  final VoidCallback onSettings;
  final VoidCallback onLogout;
  final VoidCallback onSend;
  final VoidCallback onReceive;
  final VoidCallback onOpenMessenger;
  final ValueChanged<UContact> onContact;
  final ValueChanged<String> onDeliveryChanged;
  final ValueChanged<String> onAutoAcceptChanged;
  final VoidCallback onVerification;
  final VoidCallback onRefresh;

  @override
  Widget build(BuildContext context) {
    return Column(
      children: [
        _WalletHeader(
          status: status,
          wide: wide,
          onSettings: onSettings,
          onLogout: onLogout,
          onVerification: onVerification,
        ),
        Expanded(
          child: wide
              ? _WideBody(
                  core: core,
                  status: status,
                  transactions: transactions,
                  contacts: contacts,
                  delivery: delivery,
                  autoAccept: autoAccept,
                  torRunning: torRunning,
                  onTorStart: onTorStart,
                  showCheckpointOffer: showCheckpointOffer,
                  onCheckpointOffer: onCheckpointOffer,
                  onDismissCheckpointOffer: onDismissCheckpointOffer,
                  onDeliveryChanged: onDeliveryChanged,
                  onAutoAcceptChanged: onAutoAcceptChanged,
                  onContact: onContact,
                  onSend: onSend,
                  onReceive: onReceive,
                  onVerification: onVerification,
                  onRefresh: onRefresh,
                )
              : _NarrowBody(
                  core: core,
                  status: status,
                  transactions: transactions,
                  delivery: delivery,
                  autoAccept: autoAccept,
                  onOpenMessenger: onOpenMessenger,
                  showCheckpointOffer: showCheckpointOffer,
                  onCheckpointOffer: onCheckpointOffer,
                  onDismissCheckpointOffer: onDismissCheckpointOffer,
                  onSend: onSend,
                  onReceive: onReceive,
                  onVerification: onVerification,
                  onRefresh: onRefresh,
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
    required this.onLogout,
    required this.onVerification,
  });

  final WalletStatus status;
  final bool wide;
  final VoidCallback onSettings;
  final VoidCallback onLogout;
  final VoidCallback onVerification;

  @override
  Widget build(BuildContext context) {
    final S s = AppLocale.of(context).s;
    return Center(
      child: ConstrainedBox(
        constraints: BoxConstraints(maxWidth: wide ? 1040 : double.infinity),
        child: Padding(
      padding: EdgeInsets.fromLTRB(wide ? 32 : 24, 10, wide ? 32 : 24, 6),
      child: Row(
        children: [
          const ULogo(size: 32),
          const SizedBox(width: 11),
          Expanded(
            child: FittedBox(
              fit: BoxFit.scaleDown,
              alignment: Alignment.centerLeft,
              child: Row(
                mainAxisSize: MainAxisSize.min,
                children: [
                  Text('GrinSight', style: uiStyle(15, weight: FontWeight.w700)),
                  if (status.profile.isNotEmpty) ...[
                    const SizedBox(width: 8),
                    Text(status.profile, style: uiStyle(12, color: UPalette.text3)),
                  ],
                  // Тестовая сеть помечена на любой ширине; mainnet без метки.
                  if (status.network == 'floonet') ...[
                    const SizedBox(width: 10),
                    Container(
                      padding: const EdgeInsets.symmetric(horizontal: 9, vertical: 2),
                      decoration: BoxDecoration(color: UPalette.amberBg, border: Border.all(color: UPalette.amberLine), borderRadius: BorderRadius.circular(999)),
                      child: Text(
                        'TESTNET',
                        style: uiStyle(10.5, weight: FontWeight.w600, color: UPalette.amber).copyWith(letterSpacing: 0.4),
                      ),
                    ),
                  ],
                ],
              ),
            ),
          ),
          const SizedBox(width: 8),
          // Все служебные действия — в одной плашке справа.
          Container(
            decoration: BoxDecoration(
              color: UPalette.surface,
              border: Border.all(color: UPalette.line),
              borderRadius: BorderRadius.circular(14),
            ),
            child: Row(
              mainAxisSize: MainAxisSize.min,
              children: [
                const ULanguageChip(),
                UIconButton(icon: Icons.settings_outlined, onTap: onSettings, tooltip: s.settings),
                UIconButton(icon: Icons.logout_rounded, onTap: onLogout, tooltip: s.logout),
              ],
            ),
          ),
        ],
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
    required this.transactions,
    required this.contacts,
    required this.delivery,
    required this.autoAccept,
    required this.torRunning,
    required this.onTorStart,
    required this.showCheckpointOffer,
    required this.onCheckpointOffer,
    required this.onDismissCheckpointOffer,
    required this.onDeliveryChanged,
    required this.onAutoAcceptChanged,
    required this.onContact,
    required this.onSend,
    required this.onReceive,
    required this.onVerification,
    required this.onRefresh,
  });

  final WalletCore core;
  final WalletStatus status;
  final List<WalletTx> transactions;
  final List<UContact> contacts;
  final String delivery;
  final String autoAccept;
  final bool torRunning;
  final VoidCallback onTorStart;
  final bool showCheckpointOffer;
  final VoidCallback onCheckpointOffer;
  final VoidCallback onDismissCheckpointOffer;
  final ValueChanged<String> onDeliveryChanged;
  final ValueChanged<String> onAutoAcceptChanged;
  final ValueChanged<UContact> onContact;
  final VoidCallback onSend;
  final VoidCallback onReceive;
  final VoidCallback onVerification;
  final VoidCallback onRefresh;

  @override
  Widget build(BuildContext context) {
    return Center(
      child: ConstrainedBox(
        constraints: const BoxConstraints(maxWidth: 1040),
        child: Padding(
          padding: const EdgeInsets.fromLTRB(32, 2, 32, 8),
          child: Row(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              SizedBox(
                width: 340,
                child: SingleChildScrollView(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.stretch,
                    children: [
                  UCard(
                  padding: const EdgeInsets.all(18),
                  child: MessengerContent(
                    delivery: delivery,
                    autoAccept: autoAccept,
                    contacts: contacts,
                    torRunning: torRunning,
                    onTorStart: onTorStart,
                    onDelivery: onDeliveryChanged,
                    onAutoAccept: onAutoAcceptChanged,
                    onContact: onContact,
                  ),
                ),
                      const SizedBox(height: 14),
                      _HistoryCard(transactions: transactions, network: status.network),
                    ],
                  ),
                ),
              ),
              const SizedBox(width: 20),
              Expanded(
                child: SingleChildScrollView(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.stretch,
                    children: [
                      _BalanceCard(status: status),
                      const SizedBox(height: 10),
                      // Настоящая проверка показывается всегда; режим «будущее» —
                      // только пометка (живой header-proof путь ещё не подключён).
                      _VerificationStrip(status: status, onTap: onVerification, onRefresh: onRefresh),
                      if (status.headerProof) ...[
                        const SizedBox(height: 8),
                        const _FutureStrip(),
                      ],
                      const SizedBox(height: 14),
                      _Actions(onSend: onSend, onReceive: onReceive),
                      const SizedBox(height: 10),
                      InboxCard(core: core, network: status.network),
                      if (showCheckpointOffer) ...[
                        const SizedBox(height: 10),
                        _CheckpointOfferCard(onOpen: onCheckpointOffer, onDismiss: onDismissCheckpointOffer),
                      ],
                    ],
                  ),
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

class _NarrowBody extends StatelessWidget {
  const _NarrowBody({
    required this.core,
    required this.status,
    required this.transactions,
    required this.delivery,
    required this.autoAccept,
    required this.onOpenMessenger,
    required this.showCheckpointOffer,
    required this.onCheckpointOffer,
    required this.onDismissCheckpointOffer,
    required this.onSend,
    required this.onReceive,
    required this.onVerification,
    required this.onRefresh,
  });

  final WalletCore core;
  final WalletStatus status;
  final List<WalletTx> transactions;
  final String delivery;
  final String autoAccept;
  final VoidCallback onOpenMessenger;
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
      children: [
        _BalanceCard(status: status, compact: true),
        const SizedBox(height: 10),
        _VerificationStrip(status: status, onTap: onVerification, onRefresh: onRefresh),
        if (status.headerProof) ...[
          const SizedBox(height: 8),
          const _FutureStrip(),
        ],
        const SizedBox(height: 14),
        _Actions(onSend: onSend, onReceive: onReceive),
        const SizedBox(height: 10),
        InboxCard(core: core, network: status.network),
        const SizedBox(height: 14),
        _HistoryCard(transactions: transactions, network: status.network),
        const SizedBox(height: 12),
        const SizedBox(height: 8),
        const SizedBox(height: 12),
        Text(s.keysStayOnDevice, textAlign: TextAlign.center, style: uiStyle(11, color: UPalette.text3)),
      ],
    );
  }
}

class _BalanceCard extends StatelessWidget {
  const _BalanceCard({required this.status, this.compact = false});

  final WalletStatus status;
  final bool compact;

  @override
  Widget build(BuildContext context) {
    final S s = AppLocale.of(context).s;
    final WalletBalance b = status.balance;
    // Строки «зарезервировано / входит / созревает» только если там не ноль.
    final bool hasDetails = b.reservedNano != 0 || b.incomingNano != 0 || b.immatureNano != 0;
    return UCard(
      padding: const EdgeInsets.fromLTRB(14, 12, 14, 10),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Row(
            children: [
              SectionLabel(s.available),
              const Spacer(),
              _StatusBadge(status: status),
            ],
          ),
          const SizedBox(height: 6),
          Tooltip(
            message: '${nanoToGrin(b.availableNano)} ${unitFor(status.network)}',
            child: Row(
              crossAxisAlignment: CrossAxisAlignment.end,
              children: [
                Flexible(
                  child: FittedBox(
                    fit: BoxFit.scaleDown,
                    alignment: Alignment.centerLeft,
                    child: Text('${shortGrin(b.availableNano)} ${unitFor(status.network)}', style: monoStyle(34, weight: FontWeight.w600, spacing: -1.0)),
                  ),
                ),
              ],
            ),
          ),
          const SizedBox(height: 2),
          Text(s.spendableHint, style: uiStyle(11, color: UPalette.text3)),
          if (hasDetails && compact) ...[
            const SizedBox(height: 12),
            Row(
              children: [
                if (b.reservedNano != 0) _MiniBalance(label: s.reservedLabel, nano: b.reservedNano, unit: unitFor(status.network)),
                if (b.incomingNano != 0) _MiniBalance(label: s.incomingLabel, nano: b.incomingNano, unit: unitFor(status.network)),
                if (b.immatureNano != 0) _MiniBalance(label: s.immatureLabel, nano: b.immatureNano, unit: unitFor(status.network)),
              ],
            ),
            const SizedBox(height: 10),
            Text(
              '${s.totalLabel}: ${shortGrin(b.totalNano)} ${unitFor(status.network)}',
              style: uiStyle(12, color: UPalette.text3),
            ),
          ] else if (hasDetails) ...[
            const SizedBox(height: 10),
            const Divider(height: 1, color: UPalette.line),
            const SizedBox(height: 6),
            if (b.reservedNano != 0) _BalanceRow(label: s.reservedLabel, nano: b.reservedNano, hint: s.reservedHint, unit: unitFor(status.network)),
            if (b.incomingNano != 0) _BalanceRow(label: s.incomingLabel, nano: b.incomingNano, hint: s.incomingHint, unit: unitFor(status.network)),
            if (b.immatureNano != 0) _BalanceRow(label: s.immatureLabel, nano: b.immatureNano, hint: s.immatureHint, unit: unitFor(status.network)),
            const SizedBox(height: 4),
            Text(
              '${s.totalLabel}: ${shortGrin(b.totalNano)} ${unitFor(status.network)}',
              style: uiStyle(12, color: UPalette.text3),
            ),
          ],
        ],
      ),
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

class _MiniBalance extends StatelessWidget {
  const _MiniBalance({required this.label, required this.nano, required this.unit});

  final String label;
  final int nano;
  final String unit;

  @override
  Widget build(BuildContext context) {
    return Expanded(
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text('${shortGrin(nano)} $unit', style: monoStyle(12, weight: FontWeight.w600, color: UPalette.text2, spacing: -0.2)),
          const SizedBox(height: 2),
          Text(label, style: uiStyle(9.5, color: UPalette.text3), maxLines: 1, overflow: TextOverflow.ellipsis),
        ],
      ),
    );
  }
}

class _BalanceRow extends StatelessWidget {
  const _BalanceRow({required this.label, required this.nano, required this.hint, required this.unit});

  final String label;
  final int nano;
  final String hint;
  final String unit;

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 3),
      child: Row(
        children: [
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(label, style: uiStyle(12, weight: FontWeight.w600)),
                const SizedBox(height: 1),
                Text(hint, style: uiStyle(11, color: UPalette.text3)),
              ],
            ),
          ),
          const SizedBox(width: 10),
          Tooltip(
            message: '${nanoToGrin(nano)} $unit',
            child: Text('${shortGrin(nano)} $unit', style: monoStyle(12, weight: FontWeight.w600, color: UPalette.text2, spacing: -0.2)),
          ),
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

class _VerificationStrip extends StatelessWidget {
  const _VerificationStrip({required this.status, required this.onTap, required this.onRefresh});

  final WalletStatus status;
  final VoidCallback onTap;
  final VoidCallback onRefresh;

  @override
  Widget build(BuildContext context) {
    final S s = AppLocale.of(context).s;
    final WalletProof p = status.proof;
    // Единый критерий с бейджем и окном «Проверка»: WalletProof.verified
    // (сессия свежая, можно тратить И файл баланса привязан к ней).
    final bool ok = p.verified && p.tipHeight != null;
    final String text = ok
        ? s.proofLine(p.tipHeight!, p.independentNets > 0 ? p.independentNets : 1, p.tipAgeSeconds ?? 0)
        : !p.balanceOk && p.hasSession
            ? s.balanceUnproven
            : p.hasSession
                ? s.staleProof
                : s.refreshNeeded;
    final RefreshScope? refresh = RefreshScope.maybeOf(context);
    if (refresh != null && refresh.active) {
      // Идёт обновление: прогресс-полоса, этап и «Отмена» вместо кнопки.
      return Container(
        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
        decoration: BoxDecoration(
          color: UPalette.surface,
          border: Border.all(color: UPalette.line),
          borderRadius: BorderRadius.circular(14),
        ),
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
            UButton(label: s.jobCancel, dense: true, height: 36, expand: false, onTap: refresh.onCancel),
          ],
        ),
      );
    }
    return Material(
      color: Colors.transparent,
      child: InkWell(
        borderRadius: BorderRadius.circular(14),
        onTap: ok ? onTap : onRefresh,
        child: Container(
          padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
          decoration: BoxDecoration(
            color: UPalette.surface,
            border: Border.all(color: UPalette.line),
            borderRadius: BorderRadius.circular(14),
          ),
          child: Row(
            children: [
              Icon(ok ? Icons.check_circle_outline_rounded : Icons.sync_problem_rounded, size: 18, color: ok ? UPalette.mint : UPalette.amber),
              const SizedBox(width: 9),
              Expanded(
                child: Text(
                  text,
                  maxLines: 2,
                  softWrap: true,
                  overflow: TextOverflow.ellipsis,
                  style: uiStyle(11.5, weight: FontWeight.w600, color: UPalette.text2),
                ),
              ),
              const SizedBox(width: 8),
              if (!ok)
                // expand: false = ширина по тексту (раньше фикс. 96 px обрезал «Обновить»).
                UButton(label: s.refreshAction, dense: true, height: 36, expand: false, onTap: onRefresh)
              else
                const Icon(Icons.chevron_right_rounded, size: 18, color: UPalette.text3),
            ],
          ),
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
          child: UButton(label: s.send, icon: Icons.north_east_rounded, primary: true, height: 56, onTap: onSend),
        ),
        const SizedBox(width: 12),
        Expanded(
          child: UButton(label: s.receive, icon: Icons.south_rounded, height: 56, onTap: onReceive),
        ),
      ],
    );
  }
}

class _CheckpointOfferCard extends StatelessWidget {
  const _CheckpointOfferCard({required this.onOpen, required this.onDismiss});

  final VoidCallback onOpen;
  final VoidCallback onDismiss;

  @override
  Widget build(BuildContext context) {
    final S s = AppLocale.of(context).s;
    return UCard(
      padding: const EdgeInsets.all(12),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Row(
            children: [
              const UIconBadge(icon: Icons.verified_user_outlined, color: UPalette.mint, background: UPalette.mintBg, border: UPalette.mintLine, size: 28),
              const SizedBox(width: 9),
              Expanded(
                child: Text(s.checkpointOffer, style: uiStyle(11.5, weight: FontWeight.w600, height: 1.4)),
              ),
            ],
          ),
          const SizedBox(height: 8),
          Row(
            children: [
              Expanded(child: UButton(label: s.checkpointOfferLater, height: 32, dense: true, onTap: onDismiss)),
              const SizedBox(width: 8),
              Expanded(child: UButton(label: s.checkpointCreate, height: 32, dense: true, primary: true, onTap: onOpen)),
            ],
          ),
        ],
      ),
    );
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
            : Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [for (final WalletTx tx in transactions) _TxRow(tx: tx, unit: unitFor(network))],
              ),
      ),
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
                      const Icon(Icons.verified, size: 11, color: UPalette.mint),
                      const SizedBox(width: 3),
                      Flexible(
                        child: Text(
                          s.paymentProof,
                          style: uiStyle(10.5, color: UPalette.mint),
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
          SizedBox(
            width: 150,
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.end,
              children: [
                Text(
                  '${tx.incoming ? '+' : '−'}${nanoToGrin(tx.amountNano)} $unit',
                  textAlign: TextAlign.right,
                  style: monoStyle(11.5, weight: FontWeight.w600, color: tx.incoming ? UPalette.mint : UPalette.text, spacing: -0.2),
                ),
                const SizedBox(height: 2),
                Container(
                  padding: const EdgeInsets.symmetric(horizontal: 5, vertical: 2),
                  decoration: BoxDecoration(color: style.bg, border: Border.all(color: style.border), borderRadius: BorderRadius.circular(6)),
                  child: Text(
                    s.txStatusLabel(tx.stage, tx.direction, block: tx.height, confirmations: tx.confirmations),
                    textAlign: TextAlign.center,
                    style: uiStyle(9, weight: FontWeight.w700, color: style.color).copyWith(letterSpacing: 0.3),
                  ),
                ),
                if (tx.feeNano != null) ...[
                  const SizedBox(height: 2),
                  Text(s.feeLine('${nanoToGrin(tx.feeNano!)} $unit'), style: uiStyle(10.5, color: UPalette.text3)),
                ],
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


