// End-to-end check on an Android emulator with the real (non-dev) policy:
//   flutter drive --profile --dart-define=RASP_CERT_SHA256=$(tool/cert_digest.sh) \
//     --driver=test_driver/integration_test.dart --target=integration_test/rasp_emulator_test.dart
import 'package:demo_bank/main.dart' as app;
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';

Future<void> pumpUntilFound(WidgetTester tester, Finder finder, {Duration timeout = const Duration(seconds: 15)}) async {
  final end = DateTime.now().add(timeout);
  while (DateTime.now().isBefore(end)) {
    await tester.pump(const Duration(milliseconds: 200));
    if (finder.evaluate().isNotEmpty) return;
  }
  throw TestFailure('Timed out waiting for $finder');
}

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  testWidgets('emulator is detected and the transfer is blocked', (tester) async {
    await app.main();
    await pumpUntilFound(tester, find.byKey(const Key('pin')));

    await tester.enterText(find.byKey(const Key('pin')), '1234');
    await tester.tap(find.byKey(const Key('login')));
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
    expect(find.text('Risk: medium'), findsOneWidget);
    expect(find.textContaining('native.emulator_files'), findsWidgets);
    // Signed with the expected certificate and package name, so no tamper signal.
    expect(find.textContaining('platform.signing_cert'), findsNothing);
  });
}
