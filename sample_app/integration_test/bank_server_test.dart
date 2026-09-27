// Binds with Key Attestation, gets an integrity token, and sends a signed transfer to the reference
// trust service + bank, on an Android emulator:
//   adb shell locksettings set-pin 1111     (user-auth keys need a secure lock screen)
//   (cd ../verifier && python3 -m rasp_verifier.server --package dev.ostorlab.rasp.demo_bank \
//      --cert-sha256 $(../sample_app/tool/cert_digest.sh) \
//      --build-id test-build \
//      --build-key-hex 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff \
//      --allow-software-attestation --no-revocation-check)
//   flutter drive --profile --dart-define=RASP_E2E=true --dart-define=BANK_SERVER=http://10.0.2.2:8787 \
//     --dart-define=RASP_CERT_SHA256=$(tool/cert_digest.sh) \
//     --driver=test_driver/integration_test.dart --target=integration_test/bank_server_test.dart
// When the test prints RASP_CONFIRM_PROMPT, approve the system prompt with the PIN:
//   adb shell input text 1111 && adb shell input keyevent 66
//
// The build-id and build-key must match flutter_rasp/android/src/main/cpp/build_config.h (dev defaults here).
// The reference runs in the trust service's degraded mode (no Play Integrity), so a clean device would be
// medium risk; a flutter drive build is debuggable, reported as tamper, so the server denies the transfer.
import 'package:demo_bank/data/bank_api.dart';
import 'package:demo_bank/rasp_setup.dart';
import 'package:flutter_rasp/flutter_rasp.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  testWidgets('binds, gets a token, and the bank decides on the signed request', (tester) async {
    expect(bankServer, isNotEmpty, reason: 'run with --dart-define=BANK_SERVER=...');
    await Rasp.start(raspConfig);
    final api = BankApi.instance;

    // login() binds the install with Key Attestation on first sign-in.
    await api.login(customerId: 'demo', pin: '1234');
    expect(api.installId, isNotNull);
    expect(await Rasp.isDeviceBound(), isTrue);
    // The emulator's Keystore attests in software or an emulated TEE, never under Google's roots.
    expect(api.deviceSecurityLevel, isIn(['software', 'tee', 'strongbox']));
    // The trust service read from the attestation that every signature needs the user.
    expect(api.userAuthRequired, isTrue);

    // The transfer authorizes a token (one biometric prompt showing the amount), then sends a signed request.
    // ignore: avoid_print
    print('RASP_CONFIRM_PROMPT');
    final result = await api.transfer(payee: 'Alex Smith', amountCents: 5000);
    // flutter drive builds are debuggable, sealed into the report as tamper; the trust service scores that
    // critical, and the bank denies the transfer.
    expect(result.decision, ServerDecision.deny);
    expect(result.reasons, contains('threat:tamper'));
  });
}
