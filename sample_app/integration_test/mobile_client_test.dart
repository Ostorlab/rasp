import 'dart:io';

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
  testWidgets('expired cached policy recovers without accepting rollback', (
    tester,
  ) async {
    final cache = File(
      '/data/data/dev.ostorlab.rasp.demo_bank/no_backup/rasp/policy.json',
    );
    await cache.parent.create(recursive: true);
    await cache.writeAsString(
      r'''{"kid": "test", "payload": "eyJ0ZW5hbnRJZCI6InRlc3QiLCJhcHBJZCI6ImRldi5vc3RvcmxhYi5yYXNwLmRlbW9fYmFuayIsInJldmlzaW9uIjo3LCJpc3N1ZWRBdCI6OTAwLCJleHBpcmVzQXQiOjEwMDAsImNvbmZpZyI6eyJjaGVja0ludGVydmFsU2Vjb25kcyI6MzB9fQ", "signature": "1hAwuYjkxE1jbBYJJ_mZ1ZY9CRWy7tnK9LpRJxXXIlaiAQTXHZfZ2TCyKooDZZbkVtX2lHkAO_4ngxD4T1qg2Q"}''',
    );
    try {
      await Rasp.start(
        const RaspConfig(
          devMode: true,
          tenantId: 'test',
          policyKeys: {
            'test': 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE/CHzcdhnxiucB9usrdT8OzGHgsEviomCE76swAp/AzbzWYb0UnWD4peXVljyi9Lk66azM0ULIu0c2w1341MqGw==',
          },
        ),
      );
      await expectLater(
        Rasp.secureGet('any'),
        throwsA(isA<PlatformException>()),
      );
      await expectLater(
        Rasp.guard('payment'),
        throwsA(isA<PlatformException>()),
      );
      await Rasp.applyPolicy(
        r'''{"kid": "test", "payload": "eyJ0ZW5hbnRJZCI6InRlc3QiLCJhcHBJZCI6ImRldi5vc3RvcmxhYi5yYXNwLmRlbW9fYmFuayIsInJldmlzaW9uIjo4LCJpc3N1ZWRBdCI6OTAwLCJleHBpcmVzQXQiOjQxMDI0NDQ4MDAsImNvbmZpZyI6eyJjaGVja0ludGVydmFsU2Vjb25kcyI6MzB9fQ", "signature": "z8hdbjVmAUKgFlHQWL5R0jBhOP0JmWVQlMJ6vQiEK1A4NCc5l7yjh8HKf1Y0Hf_K89vyODzb-WDDvp5i-BygiQ"}''',
      );
      await Rasp.securePut('recovered', Uint8List.fromList([8]));
      expect(await Rasp.secureGet('recovered'), [8]);
      await expectLater(
        Rasp.applyPolicy(
          r'''{"kid": "test", "payload": "eyJ0ZW5hbnRJZCI6InRlc3QiLCJhcHBJZCI6ImRldi5vc3RvcmxhYi5yYXNwLmRlbW9fYmFuayIsInJldmlzaW9uIjo3LCJpc3N1ZWRBdCI6OTAwLCJleHBpcmVzQXQiOjEwMDAsImNvbmZpZyI6eyJjaGVja0ludGVydmFsU2Vjb25kcyI6MzB9fQ", "signature": "1hAwuYjkxE1jbBYJJ_mZ1ZY9CRWy7tnK9LpRJxXXIlaiAQTXHZfZ2TCyKooDZZbkVtX2lHkAO_4ngxD4T1qg2Q"}''',
        ),
        throwsA(isA<PlatformException>()),
      );
    } finally {
      await Rasp.stop();
      await cache.delete();
    }
  });
}
