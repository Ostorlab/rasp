// End-to-end check on an Android emulator with the real (non-dev) policy:
//   flutter drive --profile --dart-define=RASP_E2E=true --dart-define=RASP_CERT_SHA256=$(tool/cert_digest.sh) \
//     --driver=test_driver/integration_test.dart --target=integration_test/rasp_emulator_test.dart
import 'package:demo_bank/main.dart' as app;
import 'package:flutter/material.dart';
import 'package:flutter_rasp/flutter_rasp.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';

Future<void> pumpUntilFound(WidgetTester tester, Finder finder, {Duration timeout = const Duration(seconds: 15)}) async {
  final end = DateTime.now().add(timeout);
  while (DateTime.now().isBefore(end)) {
    await tester.pump(const Duration(milliseconds: 200));
    if (finder.evaluate().isNotEmpty) return;
  }
  final onScreen = find.byType(Text).evaluate().map((e) => (e.widget as Text).data).whereType<String>().join(' | ');
  throw TestFailure('Timed out waiting for $finder. On screen: $onScreen');
}

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  testWidgets('emulator is detected and the transfer is blocked', (tester) async {
    await app.main();
    await pumpUntilFound(tester, find.byKey(const Key('pin')));

    // On a device the real keyboard owns text input; route enterText through the test input instead.
    tester.testTextInput.register();
    await tester.enterText(find.byKey(const Key('pin')), '1234');
    // Submit from the keyboard; the soft keyboard can cover the Log in button on small viewports.
    await tester.testTextInput.receiveAction(TextInputAction.done);
    await pumpUntilFound(tester, find.byKey(const Key('balance')));
    expect(find.text('\$12,843.50'), findsOneWidget);

    await tester.tap(find.byKey(const Key('transfer')));
    await pumpUntilFound(tester, find.byKey(const Key('send')));
    await tester.tap(find.byKey(const Key('send')));
    await pumpUntilFound(tester, find.text('Transfer blocked'));
    expect(find.textContaining('emulator'), findsWidgets);
    await tester.tap(find.text('OK'));
    await tester.pumpAndSettle();

    await tester.pageBack();
    await pumpUntilFound(tester, find.byKey(const Key('security')));
    await tester.tap(find.byKey(const Key('security')));
    await pumpUntilFound(tester, find.byKey(const Key('risk')));
    // flutter drive builds are debuggable, which counts as tampering, so the risk is high.
    expect(find.text('Risk: high'), findsOneWidget);

    final report = await Rasp.check();
    final detectors = report.signals.map((s) => s.detector).toSet();
    expect(detectors, containsAll(['native.emulator_files', 'platform.emulator_build', 'platform.debuggable_flag']));
    // Signed with the expected certificate and running under the expected package name.
    expect(detectors, isNot(contains('platform.signing_cert')));
    expect(detectors, isNot(contains('platform.package_name')));
    // No root, debugger or hooking tool on a stock emulator image.
    expect(report.threats.keys, isNot(contains(ThreatType.root)));
    expect(report.threats.keys, isNot(contains(ThreatType.hooking)));
    expect(report.threats[ThreatType.emulator], contains(Reaction.blockSensitive));
    // No fraud false positives on a clean emulator (it has two displays, neither is a presentation display).
    for (final threat in [
      ThreatType.accessibilityAbuse,
      ThreatType.overlay,
      ThreatType.screenRecording,
      ThreatType.screenMirroring,
      ThreatType.remoteAccessApp,
      ThreatType.activeCall,
    ]) {
      expect(report.threats.keys, isNot(contains(threat)), reason: '$threat');
    }

    final events = await Rasp.eventLog();
    expect(events.expand((e) => e.newThreats), containsAll([ThreatType.emulator, ThreatType.tamper]));
  });
}
