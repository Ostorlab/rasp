import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_rasp/flutter_rasp.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  const channel = MethodChannel('flutter_rasp');
  final calls = <MethodCall>[];
  setUp(() {
    calls.clear();
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(channel, (call) async {
          calls.add(call);
          if (call.method == 'secureGet') return Uint8List.fromList([1, 2]);
          if (call.method == 'request') {
            return {
              'status': 200,
              'body': Uint8List.fromList([3]),
              'headers': <String, String>{},
            };
          }
          if (call.method == 'playIntegrityToken') return 'google-token';
          return null;
        });
  });
  test('secure store transports binary values and explicit wipe', () async {
    await Rasp.securePut('session', Uint8List.fromList([1, 2]));
    expect(calls.last.arguments, {
      'key': 'session',
      'value': [1, 2],
    });
    expect(await Rasp.secureGet('session'), [1, 2]);
    await Rasp.secureClear();
    expect(calls.last.method, 'secureClear');
  });
  test('network preserves the exact signed bytes', () async {
    final response = await Rasp.request(
      url: 'https://api.example.com',
      method: 'POST',
      body: Uint8List.fromList([1, 2]),
    );
    expect((calls.last.arguments as Map)['body'], [1, 2]);
    expect(response.status, 200);
    expect(response.body, [3]);
  });
  test(
    'integrity forwards project and nonce and returns platform token',
    () async {
      expect(
        await Rasp.playIntegrityToken(nonce: 'nonce', cloudProjectNumber: 123),
        'google-token',
      );
      expect(calls.last.arguments, {
        'nonce': 'nonce',
        'cloudProjectNumber': 123,
      });
    },
  );
}
