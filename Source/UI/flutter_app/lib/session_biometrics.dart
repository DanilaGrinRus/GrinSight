import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart';

/// Optional Android biometric shortcut. Native AndroidKeyStore protects the
/// encrypted credential; cancellation always leaves ordinary password entry.
class SessionBiometrics {
  static const MethodChannel _channel = MethodChannel('grinsight/biometrics');
  static bool get _supported => !kIsWeb && defaultTargetPlatform == TargetPlatform.android;

  static bool get isAndroid => _supported;

  static Future<bool> forgetAll() async {
    if (!_supported) return false;
    try { return await _channel.invokeMethod<bool>('forgetAll') == true; }
    catch (_) { return false; }
  }

  static Future<bool?> supported() async {
    if (!_supported) return false;
    try { return await _channel.invokeMethod<bool>('supported') == true; }
    catch (_) { return null; }
  }

  static Future<bool> available() async {
    if (!_supported) return false;
    try { return await _channel.invokeMethod<bool>('available') == true; }
    catch (_) { return false; }
  }

  static Future<bool> hasCredential(String profile, String network) async {
    if (!_supported) return false;
    try { return await _channel.invokeMethod<bool>('hasCredential', {'profile': profile, 'network': network}) == true; }
    catch (_) { return false; }
  }

  static Future<bool> hasStoredCredential(String profile, String network) async {
    if (!_supported) return false;
    try { return await _channel.invokeMethod<bool>('hasStoredCredential', {'profile': profile, 'network': network}) == true; }
    catch (_) { return false; }
  }

  static Future<bool?> storedCredentialState(String profile, String network) async {
    if (!_supported) return false;
    try { return await _channel.invokeMethod<bool>('hasStoredCredential', {'profile': profile, 'network': network}); }
    catch (_) { return null; }
  }

  static Future<bool> enroll(String profile, String network, String password, String digest) async {
    if (!_supported) return false;
    try { return await _channel.invokeMethod<bool>('enroll', {'profile': profile, 'network': network, 'password': password, 'vault_digest': digest}) == true; }
    catch (_) { return false; }
  }

  static Future<Map<String, String>?> unlockSecret(String profile, String network) async {
    if (!_supported) return null;
    try {
      final result = await _channel.invokeMapMethod<String, String>('unlockSecret', {'profile': profile, 'network': network});
      if (result == null || result['password'] == null || result['vault_digest'] == null) return null;
      return result;
    }
    catch (_) { return null; }
  }

  static Future<bool> forget(String profile, String network) async {
    if (!_supported) return false;
    try { return await _channel.invokeMethod<bool>('forget', {'profile': profile, 'network': network}) == true; }
    catch (_) { return false; }
  }
}
