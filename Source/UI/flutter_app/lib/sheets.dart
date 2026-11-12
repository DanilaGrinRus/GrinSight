import 'dart:async';

import 'package:flutter/material.dart';

import 'components.dart';
import 'core.dart';
import 'l10n.dart';
import 'messenger.dart';
import 'qr_scanner.dart';
import 'qr_widgets.dart';
import 'theme.dart';
import 'wallet_model.dart';

// ================================ SEND ================================

class SendFlowSheet extends StatefulWidget {
  const SendFlowSheet({
    super.key,
    required this.onClose,
    required this.core,
    this.status,
    this.initialStep = 0,
    this.initialTo,
  });

  final VoidCallback onClose;
  final WalletCore core;
  final WalletStatus? status;
  final int initialStep;
  final String? initialTo;

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
  String? _confirmState;
  int? _confirmDepth;
  int? _confirmHeight;

  @override
  void initState() {
    super.initState();
    _step = widget.initialStep.clamp(0, 1);
    _to = TextEditingController(text: widget.initialTo ?? '');
    _amount = TextEditingController();
  }

  @override
  void dispose() {
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
        return s.sentTitle;
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
    if (_to.text.trim().isEmpty) {
      showToast(context, s.recipientRequired);
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
    final int? nano = _parseAmount();
    if (nano == null) return;
    setState(() {
      _busy = true;
      _error = null;
      _phase = '';
      _lines = const <String>[];
    });
    try {
      final WalletJob job = await widget.core.sendJob(to: _to.text.trim(), amountNano: nano);
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
    return USheetCard(
      title: _title,
      onClose: widget.onClose,
      child: _step == 0
          ? _form()
          : _step == 1
              ? _review()
              : _sentView(),
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
            Text(_error!, style: uiStyle(11, color: UPalette.amber, height: 1.5))
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
              message: s.deliveryAutoHint('Tor'),
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
        Text(s.sentTitle, textAlign: TextAlign.center, style: uiStyle(17, weight: FontWeight.w600)),
        const SizedBox(height: 4),
        Text(s.sentViaManual, textAlign: TextAlign.center, style: uiStyle(11, color: UPalette.text3, height: 1.5)),
        const SizedBox(height: 12),
        if (sent != null) ...[
          SlatepackQrView(text: sent.slatepack, network: _network),
          if (sent.feeNano != null) ...[
            const SizedBox(height: 4),
            Text('${s.fee}: ${nanoToGrin(sent.feeNano!)} $_unit', style: uiStyle(11, color: UPalette.text3)),
          ],
          const SizedBox(height: 6),
          UButton(label: s.copySlatepack, height: 34, onTap: () => copyText(context, sent.slatepack, s.copiedSlatepack)),
          const SizedBox(height: 12),
          Text(s.answerLabel, style: uiStyle(11, weight: FontWeight.w600, color: UPalette.text2)),
          const SizedBox(height: 6),
          UTextField(label: '', controller: _answer, hint: s.answerLabel, fieldKey: const Key('send-answer'), suffix: _scanSuffix(_answer)),
          const SizedBox(height: 10),
          UButton(label: s.finalizeAction, primary: true, onTap: _busy ? null : _finalize),
          const SizedBox(height: 8),
          UButton(label: s.confirmAction, height: 36, onTap: _busy ? null : _confirm),
          if (_confirmState != null) ...[
            const SizedBox(height: 8),
            Text(
              '${_confirmState!}'
              '${_confirmHeight == null ? '' : ' · ${formatHeight(_confirmHeight!)}'}'
              '${_confirmDepth == null ? '' : ' · depth ${_confirmDepth!}'}',
              style: uiStyle(11, color: UPalette.text2),
            ),
          ],
        ],
        _jobStatus(),
        const SizedBox(height: 10),
        Text(s.paymentProofNote, style: uiStyle(10, color: UPalette.text3, height: 1.5)),
        const SizedBox(height: 12),
        UButton(label: s.done, primary: true, onTap: widget.onClose),
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
  const ReceiveSheet({super.key, required this.onClose, required this.core, required this.address, this.network = 'mainnet'});

  final VoidCallback onClose;
  final WalletCore core;
  final String address;
  final String network;

  @override
  State<ReceiveSheet> createState() => _ReceiveSheetState();
}

class _ReceiveSheetState extends State<ReceiveSheet> {
  S get s => AppLocale.of(context).s;
  Widget _scanSuffix(TextEditingController c) => qrInputSuffix(context, network: widget.network, controller: c);

  final TextEditingController _slate = TextEditingController();
  final TextEditingController _invoice = TextEditingController();
  final TextEditingController _pay = TextEditingController();
  ReceiveResult? _received;
  InvoiceResult? _invoiceResult;
  String? _payAnswer;
  bool _busy = false;
  String? _error;

  @override
  void dispose() {
    _slate.dispose();
    _invoice.dispose();
    _pay.dispose();
    super.dispose();
  }

  Future<void> _receive() async {
    if (_slate.text.trim().isEmpty) return;
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
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      final InvoiceResult r = await widget.core.invoice(amountNano: amount);
      if (!mounted) return;
      setState(() {
        _invoiceResult = r;
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

  Future<void> _payInvoice() async {
    if (_pay.text.trim().isEmpty) return;
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      final WalletJob job = await widget.core.payInvoiceJob(_pay.text.trim());
      final Map<String, dynamic> r = await job.wait();
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

  int _tab = 0;

  /// Один результат (slatepack + QR + копирование) под активной вкладкой.
  List<Widget> _result(S s, String text) => [
        const SizedBox(height: 10),
        SlatepackQrView(text: text, network: widget.network),
        const SizedBox(height: 6),
        UButton(label: s.copySlatepack, height: 36, onTap: () => copyText(context, text, s.copiedSlatepack)),
      ];

  Widget _tabBody(S s) {
    switch (_tab) {
      case 1:
        return Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            UTextField(label: s.invoiceAmount, controller: _invoice, hint: '0', fieldKey: const Key('invoice-amount'), onSubmitted: _busy ? null : _createInvoice),
            const SizedBox(height: 10),
            UButton(label: s.createInvoice, height: 40, primary: true, onTap: _busy ? null : _createInvoice),
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
            if (_payAnswer != null) ...[
              const SizedBox(height: 10),
              SlatepackQrView(text: _payAnswer!, network: widget.network),
            ],
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
          _tabBody(s),
          if (_error != null) ...[
            const SizedBox(height: 8),
            Text(_error!, style: uiStyle(11.5, color: UPalette.amber, height: 1.5)),
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
            Text(_error!, style: uiStyle(11, color: UPalette.amber, height: 1.5)),
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

  /// Режим «Пощупать будущее» (проверка без чекпоинта) — переключается здесь же.
  final bool future;
  final ValueChanged<bool>? onFutureChanged;
  final VoidCallback? onPeerSaved;
  final bool showTechInitially;
  final VoidCallback? onRefresh;

  @override
  State<VerificationSheet> createState() => _VerificationSheetState();
}

class _VerificationSheetState extends State<VerificationSheet> {
  bool _showTech = false;
  late bool _future;

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
      maxHeightFactor: 0.98,
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
                value: _future,
                onChanged: (bool v) {
                  setState(() => _future = v);
                  widget.onFutureChanged!(v);
                },
              ),
            ),
          const SizedBox(height: 8),
          if (status.headerProof || _future) ...[
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
          UButton(label: s.done, primary: true, onTap: widget.onClose),
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
            Text(_error!, style: uiStyle(10.5, color: UPalette.amber, height: 1.5)),
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
  const ContactFeedSheet({super.key, required this.onClose, required this.contact, this.onRename});

  final VoidCallback onClose;
  final UContact contact;

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
                          contact.verified ? s.signatureVerified : s.signatureMissing,
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

  late bool _future;

  @override
  void initState() {
    super.initState();
    _future = widget.futureEnabled;
  }

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
          // --- Проверка и сеть: чекпоинт, режим «Пощупать будущее», свой пир
          _group(s.groupVerify),
          URowTile(
            title: s.verificationTitle,
            hint: _future ? s.futureOnHint : s.verifyRowHint,
            topBorder: false,
            trailing: _smallButton(s.open, widget.onVerification),
          ),
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
          if (!kReleaseBuild)
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
            Text(_error!, style: uiStyle(11, color: UPalette.amber, height: 1.5)),
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
  bool _addToBook = true;
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
        addContact: accept && _addToBook && widget.pending.from != null,
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
    final String? from = p.from;
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
            p.overMessenger ? s.sourceSigned : s.sourceClaimed,
            style: uiStyle(11, color: p.overMessenger ? UPalette.mint : UPalette.text3, height: 1.5),
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
          else ...[
            UTextField(
              label: s.contactNameLabel,
              controller: _name,
              hint: s.contactNameHint,
              fieldKey: const Key('pending-contact-name'),
            ),
            const SizedBox(height: 12),
            UCheckline(
              title: s.addContactAndAuto,
              subtitle: s.addContactAndAutoHint,
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
            Text(_error!, style: uiStyle(11, color: UPalette.amber, height: 1.5)),
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
  const InboxCard({super.key, required this.core, required this.network});

  final WalletCore core;
  final String network;

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
          children: [
            Icon(Icons.move_to_inbox_rounded, size: 17, color: _count > 0 ? UPalette.mint : UPalette.text3),
            const SizedBox(width: 8),
            Text(s.inboxTitle, style: uiStyle(14, weight: FontWeight.w600)),
          ],
        ),
        count: _count,
        initiallyExpanded: false,
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
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      final WalletJob job = await widget.core.payInvoiceInboxJob(item.file);
      final Map<String, dynamic> r = await job.wait();
      if (!mounted) return;
      setState(() {
        _payAnswer = (r['answer'] ?? '').toString();
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
          if (_received != null && _received!.handoverSlatepack.isNotEmpty) ...[
            Text(s.receiveAnswerTitle, style: uiStyle(11, weight: FontWeight.w600, color: UPalette.text2)),
            const SizedBox(height: 6),
            SlatepackQrView(text: _received!.handoverSlatepack, network: widget.network),
            const SizedBox(height: 6),
            UButton(
              label: s.copySlatepack,
              height: 32,
              onTap: () => copyText(context, _received!.handoverSlatepack, s.copiedSlatepack),
            ),
            const SizedBox(height: 6),
            Text(s.inboxS2Hint, style: uiStyle(10.5, color: UPalette.text3, height: 1.5)),
            const Divider(height: 22, color: UPalette.line),
          ],
          if (_payAnswer != null && _payAnswer!.isNotEmpty) ...[
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
            Text(_error!, style: uiStyle(11, color: UPalette.amber, height: 1.5)),
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
            Text(_error!, style: uiStyle(11.5, color: UPalette.amber, height: 1.5)),
          ],
        ],
      ),
    );
  }
}
