import 'package:flutter/services.dart';
import 'package:flutter_rasp/flutter_rasp.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  const channel = MethodChannel('flutter_rasp');
  final calls = <MethodCall>[];

  final report = {
    'riskLevel': 'medium',
    'threats': [
      {
        'type': 'root',
        'reactions': ['report', 'blockSensitive', 'futureReaction'],
      },
    ],
    'signals': [
      {'threat': 'root', 'detector': 'native.su_binary', 'confidence': 90, 'evidence': '/system/xbin/su'},
    ],
    'timestamp': 1790000000000,
  };

  setUp(() {
    calls.clear();
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger.setMockMethodCallHandler(channel, (call) async {
      calls.add(call);
      switch (call.method) {
        case 'start':
        case 'check':
          return report;
        case 'guard':
          return {
            'flow': 'transfer',
            'allowed': false,
            'blockingThreats': ['root'],
            'report': report,
          };
      }
      return null;
    });
  });

  test('start sends the config and parses the report', () async {
    final result = await Rasp.start(const RaspConfig(
      expectedPackageName: 'dev.example',
      expectedSigningCertSha256: ['AA:BB'],
      sensitiveFlows: {'transfer'},
      policy: {
        ThreatType.emulator: {Reaction.report},
      },
      devMode: true,
    ));

    final args = calls.single.arguments as Map;
    expect(args['expectedPackageName'], 'dev.example');
    expect(args['sensitiveFlows'], ['transfer']);
    expect(args['policy'], {
      'emulator': ['report'],
    });
    expect(args['devMode'], true);

    expect(result.riskLevel, RiskLevel.medium);
    expect(result.threats[ThreatType.root], {Reaction.report, Reaction.blockSensitive});
    expect(result.signals.single.evidence, '/system/xbin/su');
    expect(result.isClean, isFalse);
  });

  test('guard parses a denial', () async {
    final result = await Rasp.guard('transfer');
    expect(calls.single.arguments, {'flow': 'transfer'});
    expect(result.allowed, isFalse);
    expect(result.blockingThreats, [ThreatType.root]);
  });

  test('threat event flags', () {
    final event = ThreatEvent.fromMap({
      'timestamp': 1790000000000,
      'riskLevel': 'high',
      'newThreats': ['tamper'],
      'reactions': ['report', 'closeApp'],
      'signals': <Object?>[],
    });
    expect(event.shouldWarnUser, isTrue);
    expect(event.willCloseApp, isTrue);
  });
}
