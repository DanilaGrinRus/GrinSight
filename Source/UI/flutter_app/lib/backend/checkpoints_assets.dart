import 'dart:io';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:flutter/services.dart' show rootBundle;

/// Чекпоинты, которые поставляются внутри APK.
///
/// Список совпадает с тем, что `make_android.ps1` кладёт в
/// `dist/android/checkpoints` и в `UI/flutter_app/assets/checkpoints`
/// (каталог объявлен в pubspec.yaml).
const Map<String, List<String>> bundledCheckpoints = <String, List<String>>{
  'mainnet': <String>['checkpoint.rwm', 'recent-headers.bin', 'release.sig', 'release.txt'],
  'floonet': <String>['checkpoint.rwm', 'pin.txt', 'recent-headers.bin'],
};

/// Сверяет чекпоинты из assets с [destDir] по SHA-256 и перезаписывает
/// отличающиеся файлы. Новая версия приложения приносит новую подписанную точку,
/// поэтому сверка делается при каждом запуске.
///
/// Возвращает `true`, если хотя бы один файл был обновлён.
Future<bool> syncBundledCheckpoints(String destDir) async {
  bool updated = false;
  for (final MapEntry<String, List<String>> network in bundledCheckpoints.entries) {
    final Directory dir = Directory('$destDir/${network.key}');
    if (!dir.existsSync()) dir.createSync(recursive: true);
    for (final String name in network.value) {
      final ByteData data = await rootBundle.load('assets/checkpoints/${network.key}/$name');
      final Uint8List asset = data.buffer.asUint8List(data.offsetInBytes, data.lengthInBytes);
      final File file = File('${dir.path}/$name');
      if (file.existsSync() && file.lengthSync() == asset.length) {
        final List<int> existing = await file.readAsBytes();
        if (sha256.convert(existing).toString() == sha256.convert(asset).toString()) continue;
      }
      await file.writeAsBytes(asset, flush: true);
      updated = true;
    }
  }
  return updated;
}
