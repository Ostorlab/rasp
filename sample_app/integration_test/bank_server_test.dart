// Device binding and a signed transfer against the reference backend, on an Android emulator:
//   (cd ../verifier && python3 -m rasp_verifier.server --package dev.ostorlab.rasp.demo_bank \
//      --cert-sha256 $(../sample_app/tool/cert_digest.sh) --allow-software-attestation)
//   flutter drive --profile --dart-define=RASP_E2E=true --dart-define=BANK_SERVER=http://10.0.2.2:8787 \
//     --dart-define=RASP_CERT_SHA256=$(tool/cert_digest.sh) \
//     --driver=test_driver/integration_test.dart --target=integration_test/bank_server_test.dart
import 'package:demo_bank/data/bank_api.dart';
import 'package:demo_bank/rasp_setup.dart';
import 'package:flutter_rasp/flutter_rasp.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  testWidgets('binds with Key Attestation and the server decides on the signed verdict', (tester) async {
    expect(bankServer, isNotEmpty, reason: 'run with --dart-define=BANK_SERVER=...');
    await Rasp.start(raspConfig);
    final api = BankApi.instance;

    await api.bindDevice();
    expect(api.deviceId, isNotNull);
    expect(await Rasp.isDeviceBound(), isTrue);
    // The emulator's Keystore attests in software or an emulated TEE, never under Google's roots.
    expect(api.securityLevel, isIn(['software', 'tee', 'strongbox']));

    final result = await api.transfer(payee: 'Alex Smith', amountCents: 5000);
    // flutter drive builds are debuggable, reported as tamper; the server reads it from the signed verdict.
    expect(result.decision, ServerDecision.deny);
    expect(result.reasons, contains('threat:tamper'));

    // The signed payload carries the verdict and cannot be replayed: a second transfer needs a new nonce.
    final signed = await Rasp.signTransaction(flow: Flows.transfer, nonce: 'n', fields: {'amountCents': '1'});
    expect(signed.signedData, contains('threats='));
    expect(signed.signedData, contains('emulator'));
    expect(signed.signedData, contains('f.amountCents=1'));
  });
}
