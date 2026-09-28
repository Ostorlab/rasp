import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_rasp/flutter_rasp.dart';
import 'package:integration_test/integration_test.dart';

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();
  testWidgets('native scan, Keystore storage and transport rejection', (
    tester,
  ) async {
    final report = await Rasp.start(const RaspConfig(devMode: true));
    expect(
      report.signals.map((s) => s.detector),
      isNot(contains('native.core_missing')),
    );
    await Rasp.secureClear();
    await Rasp.securePut('binary', Uint8List.fromList([0, 1, 127, 128, 255]));
    expect(await Rasp.secureGet('binary'), [0, 1, 127, 128, 255]);
    await Rasp.secureDelete('binary');
    expect(await Rasp.secureGet('binary'), isNull);
    await expectLater(
      Rasp.request(url: 'http://localhost/'),
      throwsA(isA<PlatformException>()),
    );
    await expectLater(
      Rasp.request(url: 'https://unconfigured.invalid/'),
      throwsA(isA<PlatformException>()),
    );
    await Rasp.securePut('old', Uint8List.fromList([42]));
    await Rasp.secureClear();
    expect(await Rasp.secureGet('old'), isNull);
    await Rasp.stop();
  });
}
