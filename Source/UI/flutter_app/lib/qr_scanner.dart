import 'package:flutter/material.dart';
import 'package:mobile_scanner/mobile_scanner.dart';

import 'components.dart';
import 'l10n.dart';
import 'qr_codec.dart';
import 'theme.dart';

/// Камера для Android: обычный QR или части GS:, склейка и проверка SHA-256.
Future<String?> showQrScanner(BuildContext context, {required String network}) {
  return showModalBottomSheet<String>(
    context: context,
    isScrollControlled: true,
    backgroundColor: Colors.transparent,
    barrierColor: const Color(0xA604070B),
    builder: (BuildContext ctx) => Material(
      type: MaterialType.transparency,
      child: QrScannerSheet(network: network),
    ),
  );
}

class QrScannerSheet extends StatefulWidget {
  const QrScannerSheet({super.key, required this.network});

  final String network;

  @override
  State<QrScannerSheet> createState() => _QrScannerSheetState();
}

class _QrScannerSheetState extends State<QrScannerSheet> {
  S get s => AppLocale.of(context).s;

  final MobileScannerController _controller = MobileScannerController(
    formats: <BarcodeFormat>[BarcodeFormat.qrCode],
    detectionSpeed: DetectionSpeed.noDuplicates,
  );
  QrAssembler _assembler = QrAssembler(network: 'mainnet');
  String? _error;
  String? _progress;
  bool _done = false;

  @override
  void initState() {
    super.initState();
    _assembler = QrAssembler(network: widget.network);
  }

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  void _reset() {
    _assembler = QrAssembler(network: widget.network);
    _progress = null;
  }

  void _onDetect(BarcodeCapture capture) {
    if (_done) return;
    String? raw;
    for (final Barcode b in capture.barcodes) {
      if (b.rawValue != null && b.rawValue!.isNotEmpty) {
        raw = b.rawValue;
        break;
      }
    }
    if (raw == null) return;
    final QrScanResult r = _assembler.add(raw);
    if (r.complete && r.text != null) {
      _done = true;
      if (mounted) Navigator.of(context).pop(r.text);
      return;
    }
    if (r.error != null) {
      setState(() {
        _error = r.error;
        _progress = null;
        _reset();
      });
      return;
    }
    setState(() {
      _error = null;
      _progress = r.total > 0 ? s.qrCollected(r.collected, r.total) : null;
    });
  }

  @override
  Widget build(BuildContext context) {
    final S s = AppLocale.of(context).s;
    final double height = MediaQuery.sizeOf(context).height * 0.82;
    return Align(
      alignment: Alignment.bottomCenter,
      child: Container(
        height: height,
        width: double.infinity,
        decoration: const BoxDecoration(
          color: UPalette.surface2,
          borderRadius: BorderRadius.vertical(top: Radius.circular(24)),
        ),
        child: SafeArea(
          top: false,
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              Padding(
                padding: const EdgeInsets.fromLTRB(18, 12, 8, 8),
                child: Row(
                  children: [
                    Expanded(child: Text(s.qrScan, style: uiStyle(16, weight: FontWeight.w600))),
                    UIconButton(icon: Icons.close, onTap: () => Navigator.of(context).pop(), size: 32, iconSize: 17),
                  ],
                ),
              ),
              Expanded(
                child: ClipRRect(
                  borderRadius: const BorderRadius.vertical(top: Radius.circular(12)),
                  child: MobileScanner(controller: _controller, onDetect: _onDetect),
                ),
              ),
              Padding(
                padding: const EdgeInsets.all(14),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.stretch,
                  children: [
                    Text(s.qrScanHint, textAlign: TextAlign.center, style: uiStyle(11, color: UPalette.text3)),
                    if (_progress != null) ...[
                      const SizedBox(height: 6),
                      Text(_progress!, textAlign: TextAlign.center, style: uiStyle(12, weight: FontWeight.w600, color: UPalette.mint)),
                    ],
                    if (_error != null) ...[
                      const SizedBox(height: 6),
                      Text(
                        _error == 'damaged'
                            ? s.qrDamaged
                            : _error == 'wrong_network'
                                ? s.qrWrongNetwork
                                : s.qrWrongType,
                        textAlign: TextAlign.center,
                        style: uiStyle(11.5, color: UPalette.amber, height: 1.4),
                      ),
                    ],
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
