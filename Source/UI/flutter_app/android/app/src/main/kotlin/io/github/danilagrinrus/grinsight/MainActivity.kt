package io.github.danilagrinrus.grinsight

import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel

/**
 * Отдаёт Dart-коду пути, которые знает только Android:
 * `nativeLibraryDir` (там лежат программы ядра) и `filesDir` (данные приложения).
 */
class MainActivity : FlutterActivity() {
    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, CHANNEL)
            .setMethodCallHandler { call, result ->
                when (call.method) {
                    "paths" ->
                        result.success(
                            mapOf(
                                "nativeLibraryDir" to applicationInfo.nativeLibraryDir,
                                "filesDir" to filesDir.absolutePath,
                            ),
                        )
                    else -> result.notImplemented()
                }
            }
    }

    private companion object {
        const val CHANNEL = "grinsight/paths"
    }
}
