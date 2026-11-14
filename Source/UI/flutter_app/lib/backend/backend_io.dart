import 'dart:io';

import 'package:flutter/services.dart';

import '../core.dart';
import 'checkpoints_assets.dart';
import 'grinsight_service.dart';
import 'real_core.dart';

/// Пути, которые знает только Android (см. MainActivity.kt).
const MethodChannel _pathsChannel = MethodChannel('grinsight/paths');

/// `true`, если при запуске чекпоинты из APK заменили лежавшие на телефоне.
bool _checkpointAssetsUpdated = false;

/// Признак для экрана запуска: поставка принесла новый чекпоинт.
bool get checkpointAssetsUpdated => _checkpointAssetsUpdated;

/// Запускает `grinsight-service serve` и отдаёт реальное ядро.
///
/// Desktop (Windows и Linux): путь к сервису — `GRINSIGHT_SERVICE_EXE`, затем
/// `<папка приложения>\grinsight-core\`, затем dev-путь из репозитория.
/// Имя файла: `grinsight-service.exe` на Windows, `grinsight-service` на Linux.
/// На десктопе `--bin-dir`/`--checkpoints` не передаются: сервис сам берёт
/// соседние программы и `checkpoints/` из своей папки (как в `.deb`).
///
/// Android: программы ядра лежат в `nativeLibraryDir` под именами `lib*.so`
/// (их собирает `make_android.ps1`); данные и чекпоинты — в `filesDir`,
/// поэтому там пути передаются явно.
///
/// Данные Windows: `GRINSIGHT_DATA_DIR`; в dev-режиме — `dev-data`,
/// иначе каталог по умолчанию ядра (`%APPDATA%\GrinSight`). На Linux каталог
/// по умолчанию выбирает само ядро.
Future<WalletCore> startBackend() async {
  if (Platform.isAndroid) return _startAndroidBackend();
  final String exe = _serviceExe();
  final String? dataDir = _dataDir(dev: !_packagedExists());
  final GrinSightService service = await GrinSightService.start(exePath: exe, dataDir: dataDir);
  return RealWalletCore(service);
}

/// Android: ядро запускается из папки нативных библиотек приложения.
Future<WalletCore> _startAndroidBackend() async {
  final Map<Object?, Object?>? paths = await _pathsChannel.invokeMapMethod<Object?, Object?>('paths');
  final String? nativeDir = paths?['nativeLibraryDir'] as String?;
  final String? filesDir = paths?['filesDir'] as String?;
  if (nativeDir == null || filesDir == null) {
    throw GrinSightError('Android не отдал пути приложения (канал grinsight/paths).');
  }

  final String exe = '$nativeDir/libgrinsight_service.so';
  if (!File(exe).existsSync()) {
    throw GrinSightError('Сборка без ядра: запустите make_android.ps1 перед flutter build apk.');
  }

  final String checkpointsDir = '$filesDir/checkpoints';
  _checkpointAssetsUpdated = await syncBundledCheckpoints(checkpointsDir);
  final String dataDir = '$filesDir/data';
  Directory(dataDir).createSync(recursive: true);

  final GrinSightService service = await GrinSightService.start(
    exePath: exe,
    binDir: nativeDir,
    checkpointsDir: checkpointsDir,
    dataDir: dataDir,
  );
  return RealWalletCore(service);
}

String get devAutoProfile => Platform.environment['GRINSIGHT_DEV_PROFILE'] ?? '';
String get devAutoPassword => Platform.environment['GRINSIGHT_DEV_PASSWORD'] ?? '';
String get devAutoNetwork => Platform.environment['GRINSIGHT_DEV_NETWORK'] ?? '';

String? _env(String name) {
  final String? v = Platform.environment[name];
  return (v == null || v.isEmpty) ? null : v;
}

/// Имя исполняемого файла ядра: на Windows с `.exe`, на Linux без него.
String get _exeName => Platform.isWindows ? 'grinsight-service.exe' : 'grinsight-service';

String _join(String dir, String name) => '$dir${Platform.pathSeparator}$name';

/// `<папка приложения>/grinsight-core/<ядро>` — как кладёт `make_deb.sh`.
String _packagedService(String appDir) => _join(_join(appDir, 'grinsight-core'), _exeName);

bool _packagedExists() {
  final String dir = File(Platform.resolvedExecutable).parent.path;
  return File(_packagedService(dir)).existsSync();
}

/// Dev-ядро из репозитория, когда `flutter run` пускают из `UI/flutter_app`.
String? _devService() {
  if (Platform.isWindows) {
    const String dev = r'C:\DHW\GrinSight\Source\dist\grinsight-core\grinsight-service.exe';
    return File(dev).existsSync() ? dev : null;
  }
  final String appDir = Directory.current.path;
  final String dev = _join(_join(_join(_join(_join(appDir, '..'), '..'), 'dist'), 'grinsight-core'), _exeName);
  return File(dev).existsSync() ? dev : null;
}

String _serviceExe() {
  final String? env = _env('GRINSIGHT_SERVICE_EXE');
  if (env != null && File(env).existsSync()) return env;
  final String dir = File(Platform.resolvedExecutable).parent.path;
  final String packaged = _packagedService(dir);
  if (File(packaged).existsSync()) return packaged;
  final String? dev = _devService();
  if (dev != null) return dev;
  throw GrinSightError(Platform.isWindows
      ? 'grinsight-service.exe не найден. Положите папку grinsight-core рядом с grinsight.exe.'
      : 'grinsight-service не найден. Положите папку grinsight-core рядом с приложением grinsight.');
}

/// Preview builds must not open the installed application's profiles.
/// Fail closed if Windows does not provide an application-data directory.
String? previewWindowsDataDir({required bool enabled, required bool windows, required String? appData}) {
  if (!enabled || !windows) return null;
  if (appData == null || appData.trim().isEmpty) {
    throw GrinSightError('Windows APPDATA is unavailable; preview profiles cannot be isolated.');
  }
  return '${appData.trim()}\\GrinSight-Preview';
}

String? _dataDir({required bool dev}) {
  final preview = previewWindowsDataDir(
    enabled: const bool.fromEnvironment('GS_PREVIEW_ISOLATED'),
    windows: Platform.isWindows,
    appData: _env('APPDATA'),
  );
  if (preview != null) return preview;
  final String? env = _env('GRINSIGHT_DATA_DIR');
  if (env != null) return env;
  if (dev) {
    const String evidence = r'C:\DHW\GrinSight\dev-data';
    if (Directory(evidence).existsSync()) return evidence;
  }
  return null;
}
