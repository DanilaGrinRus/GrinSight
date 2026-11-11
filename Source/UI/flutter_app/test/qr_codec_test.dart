import 'package:flutter_test/flutter_test.dart';
import 'package:grinsight/qr_codec.dart';

void main() {
  test('address validation by network', () {
    final String main = 'grin1${'a' * 60}';
    final String test = 'tgrin1${'a' * 60}';
    expect(validateGrinText(main, 'mainnet'), isNull);
    expect(validateGrinText(test, 'floonet'), isNull);
    expect(validateGrinText(main, 'floonet'), 'wrong_network');
    expect(validateGrinText(test, 'mainnet'), 'wrong_network');
    expect(validateGrinText('hello', 'mainnet'), 'not_grin');
  });

  test('qr packets split, reassemble in mixed order and tolerate repeats', () {
    final String text = 'BEGINSLATEPACK. ${'x' * 1800} ENDSLATEPACK.';
    final List<String> packets = qrPackets(text);
    expect(packets.length, greaterThan(1));
    expect(packets.every((String p) => p.startsWith('GS:')), isTrue);
    expect(packets.first.split(':').last.length, 500);
    final QrAssembler a = QrAssembler(network: 'mainnet');
    // shuffled: 3, 1, 2, 4...
    final List<int> order = List<int>.generate(packets.length, (int i) => i)..shuffle();
    QrScanResult result = const QrScanResult.progress(0, 0);
    for (final int i in order) {
      result = a.add(packets[i]);
    }
    expect(result.complete, isTrue);
    expect(result.text, text);
    // repeat a part after completion does not corrupt
    final QrAssembler b = QrAssembler(network: 'mainnet');
    b.add(packets.first);
    b.add(packets.first);
    result = b.add(packets[1]);
    expect(result.complete, packets.length == 2);
  });

  test('wrong hash is rejected', () {
    final String text = 'BEGINSLATEPACK. ${'y' * 1200} ENDSLATEPACK.';
    final List<String> packets = qrPackets(text);
    final QrAssembler a = QrAssembler(network: 'mainnet');
    for (int i = 0; i < packets.length - 1; i++) {
      a.add(packets[i]);
    }
    final String last = packets.last;
    final String broken = '${last.substring(0, last.length - 1)}Z';
    final QrScanResult r = a.add(broken);
    expect(r.complete, isFalse);
    expect(r.error, 'damaged');
  });
}

