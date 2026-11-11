import 'dart:async';

import 'package:flutter/material.dart';
import 'package:qr_flutter/qr_flutter.dart';

import 'components.dart';
import 'l10n.dart';
import 'qr_codec.dart';
import 'theme.dart';

/// Статичный QR адреса Grin. Коррекция M, белый фон и тихая зона.
class AddressQrView extends StatelessWidget {
  const AddressQrView({super.key, required this.address, this.size = 280});

  final String address;
  final double size;

  @override
  Widget build(BuildContext context) {
    return Center(
      child: Container(
        padding: const EdgeInsets.all(16),
        decoration: BoxDecoration(color: Colors.white, borderRadius: BorderRadius.circular(14)),
        child: QrImageView(
          data: address,
          version: QrVersions.auto,
          size: size,
          backgroundColor: Colors.white,
          errorCorrectionLevel: QrErrorCorrectLevel.M,
          padding: EdgeInsets.zero,
        ),
      ),
    );
  }
}

/// Показ slatepack: текст или QR. Длинный текст идёт анимированными частями GS:.
class SlatepackQrView extends StatefulWidget {
  const SlatepackQrView({super.key, required this.text, required this.network});

  final String text;
  final String network;

  @override
  State<SlatepackQrView> createState() => _SlatepackQrViewState();
}

class _SlatepackQrViewState extends State<SlatepackQrView> {
  S get s => AppLocale.of(context).s;

  late List<String> _parts;
  int _index = 0;
  bool _qr = false;
  bool _playing = true;
  Timer? _timer;

  bool get _animated => _parts.length > 1;

  @override
  void initState() {
    super.initState();
    _buildParts();
  }

  @override
  void didUpdateWidget(covariant SlatepackQrView oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (oldWidget.text != widget.text) {
      _buildParts();
      _index = 0;
    }
  }

  void _buildParts() {
    final int bytes = widget.text.length; // slatepack ASCII, 1 char = 1 byte
    _parts = bytes > qrStaticLimitBytes ? qrPackets(widget.text) : <String>[widget.text];
    _startTimer();
  }

  void _startTimer() {
    _timer?.cancel();
    if (!_qr || !_animated || !_playing) return;
    _timer = Timer.periodic(const Duration(milliseconds: 400), (_) {
      if (!mounted) return;
      setState(() => _index = (_index + 1) % _parts.length);
    });
  }

  void _setQr(bool qr) {
    setState(() {
      _qr = qr;
      _index = 0;
      _playing = true;
    });
    _startTimer();
  }

  void _togglePlay() {
    setState(() => _playing = !_playing);
    _startTimer();
  }

  void _step(int delta) {
    setState(() {
      _playing = false;
      _index = (_index + delta + _parts.length) % _parts.length;
    });
    _timer?.cancel();
  }

  @override
  void dispose() {
    _timer?.cancel();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final S s = AppLocale.of(context).s;
    final double qrSize = MediaQuery.sizeOf(context).width >= 700 ? 360 : 280;
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Row(
          children: [
            Expanded(child: Text(s.slatepack, style: uiStyle(11, weight: FontWeight.w600, color: UPalette.text2))),
            USegmented(
              options: <String>[s.qrText, s.qrCode],
              selected: _qr ? 1 : 0,
              height: 26,
              fontSize: 10.5,
              onChanged: (int i) => _setQr(i == 1),
            ),
          ],
        ),
        const SizedBox(height: 6),
        if (!_qr)
          Container(
            padding: const EdgeInsets.all(10),
            decoration: BoxDecoration(color: UPalette.fieldBg, border: Border.all(color: UPalette.line), borderRadius: BorderRadius.circular(10)),
            child: SelectableText(widget.text, style: monoStyle(10, weight: FontWeight.w400, height: 1.5)),
          )
        else ...[
          Center(
            child: Container(
              padding: const EdgeInsets.all(16),
              decoration: BoxDecoration(color: Colors.white, borderRadius: BorderRadius.circular(14)),
              child: QrImageView(
                data: _parts[_index],
                version: QrVersions.auto,
                size: qrSize,
                backgroundColor: Colors.white,
                errorCorrectionLevel: QrErrorCorrectLevel.L,
                padding: EdgeInsets.zero,
              ),
            ),
          ),
          if (_animated) ...[
            const SizedBox(height: 6),
            Text(s.qrPartOf(_index + 1, _parts.length), textAlign: TextAlign.center, style: uiStyle(10.5, color: UPalette.text3)),
            const SizedBox(height: 4),
            Row(
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                UIconButton(icon: Icons.chevron_left_rounded, onTap: () => _step(-1), size: 32, iconSize: 18, tooltip: s.qrPrev),
                const SizedBox(width: 2),
                UButton(
                  label: _playing ? s.qrPause : s.qrPlay,
                  height: 32,
                  dense: true,
                  onTap: _togglePlay,
                ),
                const SizedBox(width: 2),
                UIconButton(icon: Icons.chevron_right_rounded, onTap: () => _step(1), size: 32, iconSize: 18, tooltip: s.qrNext),
              ],
            ),
          ],
        ],
      ],
    );
  }
}
