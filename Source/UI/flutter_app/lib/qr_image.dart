import 'package:file_picker/file_picker.dart';
import 'package:flutter/foundation.dart';
import 'package:image/image.dart' as img;
import 'package:zxing2/qrcode.dart';

import 'qr_codec.dart';

/// Результат чтения QR из файлов-картинок.
///
/// [text] — готовый текст (адрес, slatepack), иначе [error]:
/// `not_image`, `too_big`, `no_code` или код сборщика (`damaged`,
/// `wrong_network`, `wrong_type`); при нехватке частей GS: — [collected]/[total].
class QrImageOutcome {
  const QrImageOutcome({this.text, this.error, this.collected = 0, this.total = 0});

  final String? text;
  final String? error;
  final int collected;
  final int total;
}

const List<String> kQrImageExtensions = <String>['png', 'jpg', 'jpeg', 'gif', 'bmp', 'webp'];
const int kQrImageMaxBytes = 8 * 1024 * 1024;
const int kQrImageMaxFiles = 12;

/// Это действительно картинка (по первым байтам, а не по имени файла).
bool looksLikeImage(Uint8List b) {
  bool at(int i, List<int> sig) {
    if (b.length < i + sig.length) return false;
    for (int k = 0; k < sig.length; k++) {
      if (b[i + k] != sig[k]) return false;
    }
    return true;
  }

  return at(0, <int>[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]) || // PNG
      at(0, <int>[0xFF, 0xD8, 0xFF]) || // JPEG
      at(0, <int>[0x47, 0x49, 0x46, 0x38]) || // GIF
      at(0, <int>[0x42, 0x4D]) || // BMP
      (at(0, <int>[0x52, 0x49, 0x46, 0x46]) && at(8, <int>[0x57, 0x45, 0x42, 0x50])); // WEBP
}

/// Читает QR с картинки (чистый Dart, работает на всех платформах).
String? decodeQrFromBytes(Uint8List bytes) {
  try {
    return _decode(bytes);
  } catch (_) {
    return null; // битая или необычная картинка: просто «QR не найден»
  }
}

String? _decode(Uint8List bytes) {
  img.Image? image = img.decodeImage(bytes);
  if (image == null) return null;
  const int maxSide = 1600;
  if (image.width > maxSide || image.height > maxSide) {
    image = image.width >= image.height ? img.copyResize(image, width: maxSide) : img.copyResize(image, height: maxSide);
  }
  final img.Image rgba = image.convert(numChannels: 4);
  final LuminanceSource source = RGBLuminanceSource(
    rgba.width,
    rgba.height,
    rgba.getBytes(order: img.ChannelOrder.abgr).buffer.asInt32List(),
  );
  final DecodeHints hints = DecodeHints()..put(DecodeHintType.tryHarder);
  for (final Binarizer Function(LuminanceSource) make in <Binarizer Function(LuminanceSource)>[
    (LuminanceSource s) => HybridBinarizer(s),
    (LuminanceSource s) => GlobalHistogramBinarizer(s),
  ]) {
    try {
      return QRCodeReader().decode(BinaryBitmap(make(source)), hints: hints).text;
    } catch (_) {}
  }
  return null;
}

/// Диалог выбора файлов: только картинки (расширение + первые байты), до
/// [kQrImageMaxFiles] штук по [kQrImageMaxBytes]. null — выбор отменён.
Future<QrImageOutcome?> pickQrFromImages({required String network}) async {
  // file_picker 12+: pickFiles() возвращает список (пустой, если выбор отменён).
  final List<PlatformFile> picked = await FilePicker.pickFiles(
    type: FileType.custom,
    allowedExtensions: kQrImageExtensions,
  );
  if (picked.isEmpty) return null;
  final QrAssembler assembler = QrAssembler(network: network);
  QrScanResult? last;
  for (final PlatformFile f in picked.take(kQrImageMaxFiles)) {
    // Размер проверяем до чтения, чтобы не грузить в память что попало.
    final int? size = await f.length();
    if (size != null && size > kQrImageMaxBytes) return const QrImageOutcome(error: 'too_big');
    final Uint8List bytes = await f.readAsBytes();
    if (!looksLikeImage(bytes)) return const QrImageOutcome(error: 'not_image');
    final String? raw = await compute(decodeQrFromBytes, bytes);
    if (raw == null) return const QrImageOutcome(error: 'no_code');
    last = assembler.add(raw);
    if (last.complete && last.text != null) return QrImageOutcome(text: last.text);
    if (last.error != null) return QrImageOutcome(error: last.error);
  }
  if (last != null && last.total > 0) {
    return QrImageOutcome(error: 'incomplete', collected: last.collected, total: last.total);
  }
  return const QrImageOutcome(error: 'no_code');
}
