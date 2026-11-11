import 'dart:async';

import 'package:flutter/foundation.dart';
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
  bool get _canScan => !kIsWeb && defaultTargetPlatform == TargetPlatform.android;

  Future<void> _scanInto(TextEditingController c) async {
    final String? text = await showQrScanner(context, network: _network);
    if (text != null && mounted) c.text = text;
  }

  Widget? _scanSuffix(TextEditingController c) => _canScan
      ? IconButton(
          icon: const Icon(Icons.qr_code_scanner, size: 19, color: UPalette.text3),
          tooltip: s.qrScan,
          onPressed: () => _scanInto(c),
        )
      : null;

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
        const SizedBox(height: 14),
        Text(s.amount, style: uiStyle(11.5, weight: FontWeight.w600, color: UPalette.text2)),
        const SizedBox(height: 6),
        UTextField(
          label: '',
          controller: _amount,
          hint: '0',
          fieldKey: const Key('send-amount'),
          keyboardType: const TextInputType.numberWithOptions(decimal: true),
        ),
        const SizedBox(height: 10),
        Text(s.feeHint, style: uiStyle(10.5, color: UPalette.text3)),
        const SizedBox(height: 14),
        Text(s.deliveryAutoHint('Tor'), style: uiStyle(10.5, color: UPalette.text3, height: 1.5)),
        const SizedBox(height: 16),
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
  bool get _canScan => !kIsWeb && defaultTargetPlatform == TargetPlatform.android;

  Future<void> _scanInto(TextEditingController c) async {
    final String? text = await showQrScanner(context, network: widget.network);
    if (text != null && mounted) c.text = text;
  }

  Widget? _scanSuffix(TextEditingController c) => _canScan
      ? IconButton(
          icon: const Icon(Icons.qr_code_scanner, size: 19, color: UPalette.text3),
          tooltip: s.qrScan,
          onPressed: () => _scanInto(c),
        )
      : null;

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

  @override
  Widget build(BuildContext context) {
    final S s = AppLocale.of(context).s;
    return USheetCard(
      title: s.receiveTitle,
      onClose: widget.onClose,
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Text(s.receiveHint, style: uiStyle(11.5, color: UPalette.text2, height: 1.6)),
          const SizedBox(height: 12),
          Container(
            padding: const EdgeInsets.all(12),
            decoration: BoxDecoration(color: UPalette.fieldBg, border: Border.all(color: UPalette.lineStrong), borderRadius: BorderRadius.circular(12)),
            child: SelectableText(widget.address.isEmpty ? '—' : widget.address, style: monoStyle(11.5, weight: FontWeight.w400, height: 1.6)),
          ),
          const SizedBox(height: 10),
          UButton(label: s.copyAddress, icon: Icons.copy_rounded, primary: true, height: 40, onTap: widget.address.isEmpty ? null : () => copyText(context, widget.address, s.copiedAddress)),
          if (widget.address.isNotEmpty) ...[
            const SizedBox(height: 12),
            AddressQrView(address: widget.address, size: MediaQuery.sizeOf(context).width >= 700 ? 360 : 280),
          ],
          const SizedBox(height: 16),
          Text(s.receiveSlatepackLabel, style: uiStyle(11, weight: FontWeight.w600, color: UPalette.text2)),
          const SizedBox(height: 6),
          UTextField(label: '', controller: _slate, hint: s.recipientHint, fieldKey: const Key('receive-slate'), suffix: _scanSuffix(_slate)),
          const SizedBox(height: 8),
          UButton(label: s.receiveAction, height: 36, onTap: _busy ? null : _receive),
          if (_received != null) ...[
            const SizedBox(height: 8),
            Text(s.receiveAnswerTitle, style: uiStyle(11, weight: FontWeight.w600, color: UPalette.text2)),
            const SizedBox(height: 4),
            SlatepackQrView(text: _received!.answer, network: widget.network),
            const SizedBox(height: 6),
            UButton(label: s.copySlatepack, height: 32, onTap: () => copyText(context, _received!.answer, s.copiedSlatepack)),
          ],
          const SizedBox(height: 16),
          Text(s.invoiceAmount, style: uiStyle(11, weight: FontWeight.w600, color: UPalette.text2)),
          const SizedBox(height: 6),
          UTextField(label: '', controller: _invoice, hint: '0', fieldKey: const Key('invoice-amount')),
          const SizedBox(height: 8),
          UButton(label: s.createInvoice, height: 36, onTap: _busy ? null : _createInvoice),
          if (_invoiceResult != null) ...[
            const SizedBox(height: 8),
            SlatepackQrView(text: _invoiceResult!.slatepack, network: widget.network),
            const SizedBox(height: 6),
            UButton(label: s.copySlatepack, height: 32, onTap: () => copyText(context, _invoiceResult!.slatepack, s.copiedSlatepack)),
          ],
          const SizedBox(height: 16),
          Text(s.payInvoice, style: uiStyle(11, weight: FontWeight.w600, color: UPalette.text2)),
          const SizedBox(height: 6),
          UTextField(label: '', controller: _pay, hint: s.invoiceSlatepack, fieldKey: const Key('pay-invoice'), suffix: _scanSuffix(_pay)),
          const SizedBox(height: 8),
          UButton(label: s.payInvoice, height: 36, onTap: _busy ? null : _payInvoice),
          if (_payAnswer != null) ...[
            const SizedBox(height: 8),
            SlatepackQrView(text: _payAnswer!, network: widget.network),
          ],
          if (_error != null) ...[
            const SizedBox(height: 8),
            Text(_error!, style: uiStyle(11, color: UPalette.amber, height: 1.5)),
          ],
          const SizedBox(height: 10),
          Text(s.receiveNote, style: uiStyle(10.5, color: UPalette.text3)),
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

class CheckpointSheet extends StatefulWidget {
  const CheckpointSheet({
    super.key,
    required this.onClose,
    required this.onDone,
    this.still = false,
    this.initiallyDone = false,
  });

  final VoidCallback onClose;
  final VoidCallback onDone;
  final bool still;
  final bool initiallyDone;

  @override
  State<CheckpointSheet> createState() => _CheckpointSheetState();
}

class _CheckpointSheetState extends State<CheckpointSheet> {
  S get s => AppLocale.of(context).s;

  double _progress = 0;
  bool _done = false;
  Timer? _timer;

  @override
  void initState() {
    super.initState();
    if (widget.still || widget.initiallyDone) {
      _progress = 1;
      _done = true;
      WidgetsBinding.instance.addPostFrameCallback((_) {
        if (mounted) widget.onDone();
      });
      return;
    }
    _timer = Timer.periodic(const Duration(milliseconds: 70), (Timer t) {
      if (!mounted) return;
      setState(() {
        _progress = (_progress + 0.08).clamp(0.0, 1.0);
        if (_progress >= 1) {
          _done = true;
          t.cancel();
        }
      });
      if (_done) widget.onDone();
    });
  }

  @override
  void dispose() {
    _timer?.cancel();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return USheetCard(
      title: s.checkpoint,
      onClose: widget.onClose,
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Text(
            s.checkpointNote,
            style: uiStyle(11.5, color: UPalette.text2, height: 1.6),
          ),
          const SizedBox(height: 16),
          if (!_done) ...[
            UProgress(value: _progress),
            const SizedBox(height: 8),
            Row(
              children: [
                Text(s.checkpointChecking, style: uiStyle(10.5, color: UPalette.text3)),
                const Spacer(),
                Text(s.tenSeconds, style: uiStyle(10.5, color: UPalette.text3)),
              ],
            ),
          ] else ...[
            Row(
              children: [
                Container(
                  width: 40,
                  height: 40,
                  decoration: BoxDecoration(
                    color: UPalette.mintBg,
                    border: Border.all(color: UPalette.mintLine),
                    borderRadius: BorderRadius.circular(999),
                  ),
                  child: const Icon(Icons.check_rounded, size: 21, color: UPalette.mint),
                ),
                const SizedBox(width: 12),
                Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(s.checkpointUpdated, style: uiStyle(13.5, weight: FontWeight.w600)),
                    const SizedBox(height: 2),
                    Text(s.checkpointUpdatedMeta, style: uiStyle(11, color: UPalette.text3)),
                  ],
                ),
              ],
            ),
            const SizedBox(height: 18),
            UButton(label: s.done, primary: true, onTap: widget.onClose),
          ],
        ],
      ),
    );
  }
}

// =========================== VERIFICATION =============================

class VerificationSheet extends StatefulWidget {
  const VerificationSheet({
    super.key,
    required this.onClose,
    required this.status,
    required this.core,
    this.showTechInitially = false,
    this.onRefresh,
  });

  final VoidCallback onClose;
  final WalletStatus status;
  final WalletCore core;
  final bool showTechInitially;
  final VoidCallback? onRefresh;

  @override
  State<VerificationSheet> createState() => _VerificationSheetState();
}

class _VerificationSheetState extends State<VerificationSheet> {
  bool _showTech = false;

  @override
  void initState() {
    super.initState();
    _showTech = widget.showTechInitially;
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
          CheckpointSection(core: widget.core),
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
                fontSize: 10.5,
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
  const ContactFeedSheet({super.key, required this.onClose, required this.contact});

  final VoidCallback onClose;
  final UContact contact;

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
    required this.delivery,
    required this.autoAccept,
    required this.futureEnabled,
    required this.onDeliveryChanged,
    required this.onAutoAcceptChanged,
    required this.onFutureChanged,
    required this.onCheckpoint,
    required this.onPeer,
    required this.onLogout,
  });

  final VoidCallback onClose;
  final String profile;
  final String networkLabel;
  final String delivery;
  final String autoAccept;
  final bool futureEnabled;
  final ValueChanged<String> onDeliveryChanged;
  final ValueChanged<String> onAutoAcceptChanged;
  final ValueChanged<bool> onFutureChanged;
  final VoidCallback onCheckpoint;
  final VoidCallback onPeer;
  final VoidCallback onLogout;

  @override
  State<SettingsSheet> createState() => _SettingsSheetState();
}

class _SettingsSheetState extends State<SettingsSheet> {
  S get s => AppLocale.of(context).s;

  late int _delivery;
  late int _autoAccept;
  late bool _future;

  @override
  void initState() {
    super.initState();
    _delivery = widget.delivery == 'grinmail' ? 1 : 0;
    _autoAccept = switch (widget.autoAccept) {
      'all' => 2,
      'off' => 0,
      _ => 1,
    };
    _future = widget.futureEnabled;
  }

  Widget _group(String text) {
    return Padding(
      padding: const EdgeInsets.only(top: 10, bottom: 2),
      child: SectionLabel(text),
    );
  }

  Widget _smallButton(String label, VoidCallback onTap) {
    return UButton(label: label, dense: true, height: 32, expand: false, onTap: onTap);
  }

  Future<void> _askPasswordForSeed(BuildContext context) async {
    final TextEditingController pass = TextEditingController();
    await showDialog<void>(
      context: context,
      barrierColor: const Color(0xA604070B),
      builder: (BuildContext ctx) {
        return AlertDialog(
          backgroundColor: UPalette.surface2,
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(20),
            side: const BorderSide(color: UPalette.lineStrong),
          ),
          title: Text(s.confirmPasswordTitle, style: uiStyle(16, weight: FontWeight.w600)),
          content: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              Text(
                s.confirmPasswordNote,
                style: uiStyle(11.5, color: UPalette.text2, height: 1.5),
              ),
              const SizedBox(height: 12),
              UTextField(
                label: s.password,
                controller: pass,
                obscure: true,
                autocorrect: false,
                enableSuggestions: false,
              ),
            ],
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.of(ctx).pop(),
              child: Text(s.cancel, style: uiStyle(12, color: UPalette.text2)),
            ),
            TextButton(
              onPressed: () {
                if (pass.text.isEmpty) {
                  showToast(ctx, s.enterPassword);
                  return;
                }
                Navigator.of(ctx).pop();
                showToast(context, s.seedHiddenToast);
              },
              child: Text(s.show, style: uiStyle(12, color: UPalette.mint)),
            ),
          ],
        );
      },
    );
    pass.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return USheetCard(
      title: s.settings,
      width: 480,
      padding: const EdgeInsets.all(18),
      maxHeightFactor: 0.98,
      onClose: widget.onClose,
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          _group(s.groupWallet),
          URowTile(
            title: s.loginLabel,
            hint: '${widget.profile} · ${widget.networkLabel} · ${s.profileOnDevice}',
            topBorder: false,
            trailing: _smallButton(s.renameProfile, () => showToast(context, s.changeLoginToast)),
          ),
          URowTile(
            title: s.checkpoint,
            hint: s.checkpointVerified,
            trailing: _smallButton(s.update, widget.onCheckpoint),
          ),
          _group(s.groupMessenger),
          URowTile(
            title: s.delivery,
            hint: s.deliveryHint,
            trailing: USegmented(
              options: const ['Tor', 'Relay'],
              selected: _delivery,
              height: 26,
              fontSize: 11,
              onChanged: (int i) {
                setState(() => _delivery = i);
                widget.onDeliveryChanged(i == 1 ? 'grinmail' : 'tor');
              },
            ),
          ),
          URowTile(
            title: s.autoAccept,
            hint: s.autoAcceptHint,
            trailing: USegmented(
              options: <String>[s.autoOff, s.autoContacts, s.autoAll],
              selected: _autoAccept,
              height: 26,
              fontSize: 10.5,
              onChanged: (int i) {
                setState(() => _autoAccept = i);
                widget.onAutoAcceptChanged(i == 2 ? 'all' : i == 1 ? 'contacts' : 'off');
              },
            ),
          ),
          _group(s.groupNetwork),
          URowTile(
            title: s.peer,
            hint: s.peerHint,
            trailing: _smallButton(s.configure, widget.onPeer),
          ),
          _group(s.groupSecurity),
          URowTile(
            title: s.password,
            hint: s.passwordHintSettings,
            trailing: _smallButton(s.change, () => showToast(context, s.changePasswordToast)),
          ),
          URowTile(
            title: s.seedSettings,
            hint: s.seedSettingsHint,
            trailing: _smallButton(s.show, () => _askPasswordForSeed(context)),
          ),
          _group(s.groupMore),
          URowTile(
            title: s.language,
            hint: 'RU / EN',
            trailing: const ULanguageToggle(),
          ),
          URowTile(
            title: s.future,
            hint: s.futureHint,
            trailing: USwitch(
              value: _future,
              onChanged: (bool v) {
                setState(() => _future = v);
                widget.onFutureChanged(v);
                showToast(context, v ? s.futureOnToast : s.futureOffToast);
              },
            ),
          ),
          URowTile(
            title: s.logout,
            hint: s.logoutHint,
            trailing: _smallButton(s.logoutAction, widget.onLogout),
          ),
          Container(
            margin: const EdgeInsets.only(top: 8),
            padding: const EdgeInsets.only(top: 8),
            decoration: const BoxDecoration(
              border: Border(top: BorderSide(color: UPalette.line)),
            ),
            child: Text(
              s.prototypeFooter,
              textAlign: TextAlign.center,
              style: uiStyle(11, color: UPalette.text3),
            ),
          ),
        ],
      ),
    );
  }
}

// =============================== FUTURE ===============================

class FutureSheet extends StatefulWidget {
  const FutureSheet({
    super.key,
    required this.onClose,
    required this.enabled,
    required this.onChanged,
  });

  final VoidCallback onClose;
  final bool enabled;
  final ValueChanged<bool> onChanged;

  @override
  State<FutureSheet> createState() => _FutureSheetState();
}

class _FutureSheetState extends State<FutureSheet> {
  S get s => AppLocale.of(context).s;

  late bool _value;

  @override
  void initState() {
    super.initState();
    _value = widget.enabled;
  }

  @override
  Widget build(BuildContext context) {
    return USheetCard(
      title: s.futureTitle,
      onClose: widget.onClose,
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          Text(
            s.futureNote,
            style: uiStyle(11.5, color: UPalette.text2, height: 1.6),
          ),
          const SizedBox(height: 14),
          Wrap(
            spacing: 6,
            runSpacing: 6,
            children: [s.testnet, 'GrinMail', s.newProtocols]
                .map((String label) => Container(
                      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
                      decoration: BoxDecoration(
                        color: UPalette.line,
                        border: Border.all(color: UPalette.line),
                        borderRadius: BorderRadius.circular(999),
                      ),
                      child: Text(label, style: uiStyle(10.5, weight: FontWeight.w600, color: UPalette.text2)),
                    ))
                .toList(),
          ),
          const SizedBox(height: 16),
          URowTile(
            title: s.experimentalMode,
            hint: s.experimentalModeHint,
            topBorder: false,
            trailing: USwitch(
              value: _value,
              onChanged: (bool v) {
                setState(() => _value = v);
                widget.onChanged(v);
              },
            ),
          ),
          const SizedBox(height: 6),
          Text(
            s.experimentalModeNote,
            style: uiStyle(10.5, color: UPalette.text3, height: 1.5),
          ),
          const SizedBox(height: 18),
          UButton(label: s.done, primary: true, onTap: widget.onClose),
        ],
      ),
    );
  }
}

// ================================ PEER ================================

class PeerSheet extends StatefulWidget {
  const PeerSheet({super.key, required this.onClose, required this.core, this.onSaved});

  final VoidCallback onClose;
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
      widget.onClose();
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
    return USheetCard(
      title: s.peerTitle,
      onClose: widget.onClose,
      child: Column(
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
      ),
    );
  }
}
