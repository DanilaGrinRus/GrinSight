import 'package:flutter_test/flutter_test.dart';
import 'package:grinsight/backend/backend_io.dart';

void main() {
  test('Windows preview isolates its data directory', () {
    expect(previewWindowsDataDir(enabled: true, windows: true, appData: r'C:\Users\Example\AppData\Roaming'),
      r'C:\Users\Example\AppData\Roaming\GrinSight-Preview');
  });
  test('non-preview and non-Windows keep their existing resolution', () {
    expect(previewWindowsDataDir(enabled: false, windows: true, appData: null), isNull);
    expect(previewWindowsDataDir(enabled: true, windows: false, appData: null), isNull);
  });
  test('preview refuses to fall back to shared data if APPDATA is missing', () {
    expect(() => previewWindowsDataDir(enabled: true, windows: true, appData: null), throwsException);
    expect(() => previewWindowsDataDir(enabled: true, windows: true, appData: '   '), throwsException);
  });
}
