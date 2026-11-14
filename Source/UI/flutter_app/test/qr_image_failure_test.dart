import 'dart:convert';
import 'dart:typed_data';
import 'package:flutter_test/flutter_test.dart';
import 'package:grinsight/qr_image.dart';
import 'package:image/image.dart' as img;

void main() {
  test('plain image without a QR is identified as an image but decodes no code', () {
    final bytes = Uint8List.fromList(img.encodePng(img.Image(width: 80, height: 80)));
    expect(looksLikeImage(bytes), isTrue);
    expect(decodeQrFromBytes(bytes), isNull);
  });
  test('text renamed to .png is rejected by its bytes', () {
    final bytes = Uint8List.fromList(utf8.encode('not an image'));
    expect(looksLikeImage(bytes), isFalse);
    expect(decodeQrFromBytes(bytes), isNull);
  });
}
