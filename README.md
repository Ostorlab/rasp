# RASP v1: headless, offline

This repo holds two things:

- **`flutter_rasp/`**: a Flutter plugin (Android) that runs runtime self-protection checks on the device. It has no server: detection, policy and reactions all run locally.
- **`sample_app/`**: *Demo Bank*, a small Flutter banking app used as the protection target.

See `rasp-research.md` for background and the design document for the full platform. This v1 covers the on-device part only (sections 4, 5 and 9 of the design), without the trust service, the control plane or build-time hardening.

## What v1 detects

| Threat | Detectors | Layer |
| --- | --- | --- |
| `root` | su binaries, root-manager data dirs, root mounts in `/proc/self/mounts`, SELinux permissive, root-manager packages, `test-keys` | native + Kotlin |
| `emulator` | QEMU/goldfish device files, build fingerprint/model/hardware/product | native + Kotlin |
| `debugger` | `TracerPid` in `/proc/self/status`, JDWP debugger connected | native + Kotlin |
| `hooking` | Frida/Xposed/LSPosed/Substrate libraries in `/proc/self/maps`, Frida thread names, Frida default port, Xposed classes and stack frames | native + Kotlin |
| `tamper` | Signing certificate SHA-256 vs expected, package name, `debuggable` flag on a release build | Kotlin |
| `untrustedInstaller` | Installer package not in the allowlist | Kotlin |
| `devOptions`, `adbEnabled`, `noScreenLock` | Device settings | Kotlin |

## Reactions (local policy)

| Reaction | Effect |
| --- | --- |
| `report` | Appends to the on-device event log (`files/flutter_rasp/events.jsonl`, last 500 entries) and emits a `ThreatEvent` |
| `warnUser` | The event asks the app to show a warning |
| `blockSensitive` | `Rasp.guard(flow)` denies flows listed in `sensitiveFlows` |
| `secureScreen` | Sets `FLAG_SECURE` on the window while the threat is active |
| `closeApp` | Closes the app 4 s after the event, so the warning can be shown first |

Default policy: root → report, warn, block sensitive · emulator → report, block sensitive · debugger → report, block sensitive, secure screen · hooking → report, warn, block sensitive, secure screen · tamper → report, warn, close app · everything else → report. `devMode: true` turns every reaction into report only.

## Using the plugin

```dart
await Rasp.start(RaspConfig(
  expectedPackageName: 'dev.ostorlab.rasp.demo_bank',
  expectedSigningCertSha256: ['15a894...'],
  allowedInstallers: ['com.android.vending'],
  sensitiveFlows: {'transfer'},
  devMode: kDebugMode,
));

Rasp.events.listen((event) { /* show a warning */ });

final guard = await Rasp.guard('transfer');   // fresh scan right before the action
if (!guard.allowed) { /* refuse */ }
```

## Build and run the sample

```bash
export PATH="$HOME/development/flutter/bin:$PATH"
cd sample_app
flutter build apk --release --dart-define=RASP_CERT_SHA256=$(tool/cert_digest.sh)
adb install -r build/app/outputs/flutter-apk/app-release.apk
```

`tool/cert_digest.sh [keystore] [alias] [storepass]` prints the digest; it defaults to the Android debug keystore, which the sample's release build is signed with.

## Tests

```bash
# Dart API and models
(cd flutter_rasp && flutter test)
# Sample app
(cd sample_app && flutter test)
# Kotlin policy engine (JVM)
(cd sample_app/android && ./gradlew :flutter_rasp:testDebugUnitTest)
# Native core on the host
gcc -Wall -Wextra -Werror -I flutter_rasp/android/src/main/cpp \
  flutter_rasp/android/src/test/cpp/native_test.c \
  flutter_rasp/android/src/main/cpp/{detectors,signals}.c -o /tmp/native_test && /tmp/native_test
```

## Known limits of v1

- Android only. iOS is not implemented.
- No obfuscation or build-time hardening. The checks are standard and can be found and bypassed by a determined reverse engineer, as the research notes explain. v1 raises the bar and gives the app signals; it is not tamper-proof.
- Offline means the app itself decides. There is no server-side attestation, so backends cannot yet verify a device's state (design section 7).
