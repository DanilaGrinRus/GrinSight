import 'dart:convert';

import 'package:crypto/crypto.dart';

/// QR-формат GrinSight: короткий текст — одним QR, длинный slatepack — частями.
///
/// Часть: `GS:<номер>/<всего>:<id>:<кусок>`, номер с 1, id — первые 8 hex
/// SHA-256 всего текста. Склеивание проверяет id и порядок.
const int qrStaticLimitBytes = 1000;
const int qrChunkBytes = 500;

class QrScanResult {
  const QrScanResult._({this.complete = false, this.text, this.collected = 0, this.total = 0, this.error});
  const QrScanResult.progress(int collected, int total)
      : this._(collected: collected, total: total);
  const QrScanResult.done(String text) : this._(complete: true, text: text);
  const QrScanResult.fail(String error) : this._(error: error);

  final bool complete;
  final String? text;
  final int collected;
  final int total;
  final String? error;
}

String qrIdFor(String text) => sha256.convert(utf8.encode(text)).toString().substring(0, 8);

bool isQrPacket(String raw) => raw.trimLeft().startsWith('GS:');

List<String> qrPackets(String text) {
  final int total = (text.length / qrChunkBytes).ceil();
  final String id = qrIdFor(text);
  return <String>[
    for (int i = 0; i < total; i++)
      'GS:${i + 1}/$total:$id:${text.substring(i * qrChunkBytes, (i + 1) * qrChunkBytes > text.length ? text.length : (i + 1) * qrChunkBytes)}',
  ];
}

/// Проверка текста, который может быть адресом или slatepack.
/// Возвращает текст ошибки или null.
String? validateGrinText(String raw, String network) {
  final String text = raw.trim();
  if (text.isEmpty) return 'empty';
  if (text.contains('BEGINSLATEPACK') && text.contains('ENDSLATEPACK.')) return null;
  final RegExp address = RegExp(r'^(grin1|tgrin1)[a-z0-9]{20,}$');
  if (address.hasMatch(text)) {
    final String expected = network == 'floonet' ? 'tgrin1' : 'grin1';
    if (!text.startsWith(expected)) return 'wrong_network';
    return null;
  }
  return 'not_grin';
}

class _GsPart {
  const _GsPart(this.index, this.total, this.id, this.payload);
  final int index;
  final int total;
  final String id;
  final String payload;

  static _GsPart? parse(String raw) {
    final RegExpMatch? m = RegExp(r'^GS:(\d+)/(\d+):([0-9a-fA-F]{8}):([\s\S]*)$').firstMatch(raw.trim());
    if (m == null) return null;
    final int? i = int.tryParse(m.group(1)!);
    final int? t = int.tryParse(m.group(2)!);
    if (i == null || t == null || i < 1 || t < 1 || i > t) return null;
    return _GsPart(i, t, m.group(3)!.toLowerCase(), m.group(4)!);
  }
}

class QrAssembler {
  QrAssembler({required this.network});
  final String network;
  String? _id;
  int? _total;
  final Map<int, String> _parts = <int, String>{};

  QrScanResult add(String raw) {
    final _GsPart? part = _GsPart.parse(raw);
    if (part == null) {
      if (isQrPacket(raw)) return const QrScanResult.fail('damaged');
      final String? why = validateGrinText(raw, network);
      if (why != null) return QrScanResult.fail(why);
      return QrScanResult.done(raw.trim());
    }
    if (_id != part.id || _total != part.total) {
      _id = part.id;
      _total = part.total;
      _parts.clear();
    }
    final String? old = _parts[part.index];
    if (old != null && old != part.payload) {
      _parts.clear();
      _id = null;
      _total = null;
      return const QrScanResult.fail('damaged');
    }
    _parts[part.index] = part.payload;
    if (_parts.length < part.total) return QrScanResult.progress(_parts.length, part.total);
    final StringBuffer joined = StringBuffer();
    for (int i = 1; i <= part.total; i++) {
      final String? chunk = _parts[i];
      if (chunk == null) {
        _parts.clear();
        return const QrScanResult.fail('damaged');
      }
      joined.write(chunk);
    }
    final String text = joined.toString();
    if (qrIdFor(text) != part.id) {
      _parts.clear();
      _id = null;
      _total = null;
      return const QrScanResult.fail('damaged');
    }
    final String? why = validateGrinText(text, network);
    if (why != null) return QrScanResult.fail(why);
    return QrScanResult.done(text);
  }
}
