import 'package:flutter/foundation.dart';
import 'package:flutter_rasp/flutter_rasp.dart';

/// Flows the RASP policy may deny.
abstract final class Flows {
  static const transfer = 'transfer';
  static const addPayee = 'addPayee';
}

/// SHA-256 of the release signing certificate, passed at build time:
/// `flutter build apk --dart-define=RASP_CERT_SHA256=<digest>` (see tool/cert_digest.sh).
const _certDigest = String.fromEnvironment('RASP_CERT_SHA256');

/// Set by the on-device integration test. `flutter drive` builds are debuggable, which the engine
/// rightly treats as tampering and answers by closing the app; the test only needs that reported.
const _e2e = bool.fromEnvironment('RASP_E2E');

final raspConfig = RaspConfig(
  expectedPackageName: 'dev.ostorlab.rasp.demo_bank',
  expectedSigningCertSha256: [if (_certDigest.isNotEmpty) _certDigest],
  allowedInstallers: const ['com.android.vending'],
  checkIntervalSeconds: 15,
  sensitiveFlows: const {Flows.transfer, Flows.addPayee},
  policy: {
    if (_e2e) ThreatType.tamper: {Reaction.report},
  },
  // Debug builds only report, so the app stays usable under a debugger and on emulators.
  devMode: kDebugMode,
);
