import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_rasp/flutter_rasp.dart';

import 'rasp_setup.dart';
import 'screens/login.dart';

final navigatorKey = GlobalKey<NavigatorState>();

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  final initial = await Rasp.start(raspConfig);
  runApp(DemoBankApp(initialReport: initial));
}

class DemoBankApp extends StatefulWidget {
  const DemoBankApp({super.key, required this.initialReport});

  final SecurityReport initialReport;

  @override
  State<DemoBankApp> createState() => _DemoBankAppState();
}

class _DemoBankAppState extends State<DemoBankApp> {
  StreamSubscription<ThreatEvent>? _subscription;

  @override
  void initState() {
    super.initState();
    _subscription = Rasp.events.listen(_onThreat);
  }

  @override
  void dispose() {
    _subscription?.cancel();
    super.dispose();
  }

  void _onThreat(ThreatEvent event) {
    final context = navigatorKey.currentContext;
    if (!event.shouldWarnUser || context == null) return;
    showDialog<void>(
      context: context,
      barrierDismissible: !event.willCloseApp,
      builder: (context) => AlertDialog(
        icon: const Icon(Icons.gpp_bad_outlined),
        title: const Text('Security warning'),
        content: Text(
          'Demo Bank detected: ${event.newThreats.map(threatLabel).join(', ')}.\n\n'
          '${event.willCloseApp ? 'The app will close to protect your account.' : 'Payments are disabled on this device.'}',
        ),
        actions: [
          if (!event.willCloseApp) TextButton(onPressed: () => Navigator.pop(context), child: const Text('OK')),
        ],
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Demo Bank',
      navigatorKey: navigatorKey,
      theme: ThemeData(colorSchemeSeed: const Color(0xFF1B5E9A), useMaterial3: true),
      home: const LoginScreen(),
    );
  }
}

String threatLabel(ThreatType threat) => switch (threat) {
      ThreatType.root => 'rooted device',
      ThreatType.emulator => 'emulator',
      ThreatType.debugger => 'debugger attached',
      ThreatType.hooking => 'hooking or instrumentation tool',
      ThreatType.tamper => 'modified app',
      ThreatType.untrustedInstaller => 'installed outside the Play Store',
      ThreatType.devOptions => 'developer options on',
      ThreatType.adbEnabled => 'USB debugging on',
      ThreatType.noScreenLock => 'no screen lock',
      ThreatType.accessibilityAbuse => 'an app controlling your screen (accessibility service)',
      ThreatType.overlay => 'another app drawing over Demo Bank',
      ThreatType.screenCapture => 'a screenshot',
      ThreatType.screenRecording => 'screen recording',
      ThreatType.screenMirroring => 'screen mirroring',
      ThreatType.remoteAccessApp => 'a remote-access app',
      ThreatType.activeCall => 'a phone call in progress',
      ThreatType.netMitm => 'a proxy or added certificate (possible interception)',
      ThreatType.detectorFailure => 'a security check that could not run',
    };
