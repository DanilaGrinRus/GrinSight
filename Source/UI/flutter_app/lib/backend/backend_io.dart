import 'dart:io';

import '../core.dart';
import 'grinsight_service.dart';
import 'real_core.dart';

/// Запускает `grinsight-service serve` и отдаёт реальное ядро.
///
/// Путь к сервису: `GRINSIGHT_SERVICE_EXE`, затем `<папка grinsight.exe>\grinsight-core\`,
/// затем dev-путь `C:\DHW\GrinFlyClient\Unity\dist\grinsight-core`.
/// Данные: `GRINSIGHT_DATA_DIR`; в dev-режиме — `evidence\grinsight-data`,
/// иначе каталог по умолчанию ядра (`%APPDATA%\GrinSight`).
Future<WalletCore> startBackend() async {
  final String exe = _serviceExe();
  final String? dataDir = _dataDir(dev: !_packagedExists());
  final GrinSightService service = await GrinSightService.start(exePath: exe, dataDir: dataDir);
  return RealWalletCore(service);
}

String get devAutoProfile => Platform.environment['GRINSIGHT_DEV_PROFILE'] ?? '';
String get devAutoPassword => Platform.environment['GRINSIGHT_DEV_PASSWORD'] ?? '';
String get devAutoNetwork => Platform.environment['GRINSIGHT_DEV_NETWORK'] ?? '';

String? _env(String name) {
  final String? v = Platform.environment[name];
  return (v == null || v.isEmpty) ? null : v;
}

bool _packagedExists() {
  final String dir = File(Platform.resolvedExecutable).parent.path;
  return File('$dir\\grinsight-core\\grinsight-service.exe').existsSync();
}

String _serviceExe() {
  final String? env = _env('GRINSIGHT_SERVICE_EXE');
  if (env != null && File(env).existsSync()) return env;
  final String dir = File(Platform.resolvedExecutable).parent.path;
  final String packaged = '$dir\\grinsight-core\\grinsight-service.exe';
  if (File(packaged).existsSync()) return packaged;
  const String dev = r'C:\DHW\GrinFlyClient\Unity\dist\grinsight-core\grinsight-service.exe';
  if (File(dev).existsSync()) return dev;
  throw GrinSightError('grinsight-service.exe не найден. Положите папку grinsight-core рядом с grinsight.exe.');
}

String? _dataDir({required bool dev}) {
  final String? env = _env('GRINSIGHT_DATA_DIR');
  if (env != null) return env;
  if (dev) {
    const String evidence = r'C:\DHW\GrinFlyClient\Unity\evidence\grinsight-data';
    if (Directory(evidence).existsSync()) return evidence;
  }
  return null;
}
