// Waits for a phone call placed from the host, e.g.:
//   adb emu gsm call 5551234 && sleep 3 && adb emu gsm accept 5551234
// then checks that the transfer flow warns about it. Ends the call with: adb emu gsm cancel 5551234
import 'package:demo_bank/rasp_setup.dart';
import 'package:flutter_rasp/flutter_rasp.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  testWidgets('a call in progress raises a warning on the transfer flow', (tester) async {
    await Rasp.start(raspConfig);
    // ignore: avoid_print
    print('RASP_WAITING_FOR_CALL');
    GuardResult? guard;
    final end = DateTime.now().add(const Duration(seconds: 90));
    while (DateTime.now().isBefore(end)) {
      guard = await Rasp.guard(Flows.transfer);
      if (guard.report.threats.containsKey(ThreatType.activeCall)) break;
      await Future<void>.delayed(const Duration(seconds: 1));
    }
    expect(guard!.report.threats.keys, contains(ThreatType.activeCall));
    expect(guard.warnings, contains(ThreatType.activeCall));
    expect(guard.report.signals.map((s) => s.detector), contains('fraud.active_call'));
  });
}
