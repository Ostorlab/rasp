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
            'warnings': ['activeCall'],
            'report': report,
          };
        case 'bindDevice':
          return {
            'installId': 'install-1',
            'keyAlias': 'k',
            'strongBox': false,
            'userAuthRequired': true,
            'publicKey': 'cHVi',
            'certificateChain': ['bGVhZg==', 'cm9vdA=='],
          };
        case 'prepareToken':
          return {
            'installId': 'install-1',
            'proof': 'cHJvb2Y',
            'sessionPublicKey': 'c2Vzcw==',
            'sealedReport': {'report': '{"v":"rasp-report-1"}', 'mac': 'ab12'},
          };
        case 'signRequest':
          return {'key': 'c2Vzcw==', 'sig': 'c2ln', 'ts': 1790000000000, 'counter': 1};
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
    expect(result.warnings, [ThreatType.activeCall]);
  });

  test('bindDevice sends the challenge as base64', () async {
    final result = await Rasp.bindDevice(Uint8List.fromList(List.filled(16, 1)));
    expect(calls.single.arguments, {'challenge': 'AQEBAQEBAQEBAQEBAQEBAQ==', 'requireUserAuth': true});
    expect(result.installId, 'install-1');
    expect(result.certificateChain, hasLength(2));
    expect(result.userAuthRequired, isTrue);
    expect(result.strongBox, isFalse);
  });

  test('prepareToken returns a token authorization for /v1/token', () async {
    final auth = await Rasp.prepareToken(nonce: 'n1', confirmationText: 'Send \$5.00');
    expect(calls.single.arguments, {
      'nonce': 'n1',
      'confirmationTitle': 'Authorize',
      'confirmationText': 'Send \$5.00',
    });
    expect(auth.sessionPublicKey, 'c2Vzcw==');
    expect(auth.sealedReport['mac'], 'ab12');
    final request = auth.toRequest('n1', playIntegrityToken: 'pi');
    expect(request['proof'], 'cHJvb2Y');
    expect(request['playIntegrityToken'], 'pi');
  });

  test('signRequest builds DPoP headers', () async {
    final proof = await Rasp.signRequest(method: 'POST', path: '/v1/transfers', body: Uint8List.fromList([1, 2, 3]));
    expect((calls.single.arguments as Map)['path'], '/v1/transfers');
    final headers = proof.headers('tok');
    expect(headers['X-Integrity-Token'], 'tok');
    expect(headers['X-Integrity-Sig'], 'c2ln');
    expect(headers['X-Integrity-Counter'], '1');
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
