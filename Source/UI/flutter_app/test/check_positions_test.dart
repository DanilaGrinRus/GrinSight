import 'dart:math' show Random;

import 'package:flutter_test/flutter_test.dart';
import 'package:grinsight/screens/login.dart';

void main() {
  // Минимальное расстояние между проверяемыми словами: 12 -> 4, 18 -> 6, 24 -> 10.
  for (final (int n, int gap) in <(int, int)>[(12, 4), (18, 6), (24, 10)]) {
    test('pickCheckPositions: $n слов, разброс не меньше $gap', () {
      final Random rng = Random(7);
      final Set<int> seen = <int>{};
      for (int k = 0; k < 2000; k++) {
        final List<int> p = pickCheckPositions(n, rng: rng);
        expect(p.length, 2);
        expect(p[0], lessThan(p[1]));
        expect(p[0], greaterThanOrEqualTo(0));
        expect(p[1], lessThan(n));
        expect(p[1] - p[0], greaterThanOrEqualTo(gap));
        seen..add(p[0])..add(p[1]);
      }
      // позиции действительно случайные: встречается большинство индексов
      expect(seen.length, greaterThan(n ~/ 2));
    });
  }

  test('isPhraseLength: 12, 15, 18, 21, 24', () {
    for (final int n in <int>[12, 15, 18, 21, 24]) {
      expect(isPhraseLength(n), isTrue);
    }
    for (final int n in <int>[0, 11, 13, 23, 25]) {
      expect(isPhraseLength(n), isFalse);
    }
  });
}
