package io.github.danilagrinrus.grinsight

import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel

/**
 * Отдаёт Dart-коду пути, которые знает только Android:
 * `nativeLibraryDir` (там лежат программы ядра) и `filesDir` (данные приложения).
 */
class MainActivity : FlutterActivity() {
    private var sessionBiometrics: SessionBiometrics? = null
    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        if (android.os.Build.VERSION.SDK_INT >= 28) {
            val biometric = SessionBiometrics(this)
            sessionBiometrics = biometric
            MethodChannel(flutterEngine.dartExecutor.binaryMessenger, "grinsight/biometrics")
                .setMethodCallHandler { call, result -> biometric.handle(call, result) }
        } else {
            MethodChannel(flutterEngine.dartExecutor.binaryMessenger, "grinsight/biometrics")
                .setMethodCallHandler { call, result ->
                    if (call.method == "supported" || call.method == "available") result.success(false)
                    else result.error("biometric_unavailable", "Use wallet password", null)
                }
        }
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

    override fun onDestroy() {
        sessionBiometrics?.cancel()
        sessionBiometrics = null
        super.onDestroy()
    }

    private companion object {
        const val CHANNEL = "grinsight/paths"
    }
}
