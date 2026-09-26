# RASP for banking apps

This repo holds three things:

- **`flutter_rasp/`**: a Flutter plugin (Android) for runtime self-protection. Detection, policy and reactions run on the device and work offline.
- **`verifier/`**: server-side verification for a bank's backend. It checks Android Key Attestation (device binding) and transactions signed by the bound key, then decides allow, step-up or deny. It includes a small reference backend.
- **`sample_app/`**: *Demo Bank*, a Flutter banking app used as the protection target.

See `rasp-research.md` for background and the design document for the full platform.

| Tier | Contents |
| --- | --- |
| v1 (on device, offline) | Root, emulator, debugger, hooking, tamper and installer detection; local policy and reactions; event log |
| Banking tier | Anti-fraud (accessibility abuse, overlays and tapjacking, screen capture, recording and mirroring, remote-access apps, calls during a transfer); sensitive-screen mode; hardware-backed device binding with Key Attestation; transactions signed together with the RASP verdict; server-side verifier and decision |

## What the plugin detects

| Threat | Detectors | Layer |
| --- | --- | --- |
| `root` | su binaries, root-manager data dirs, root mounts in `/proc/self/mounts`, SELinux permissive, root-manager packages, `test-keys` | native + Kotlin |
| `emulator` | QEMU/goldfish device files, build fingerprint/model/hardware/product | native + Kotlin |
| `debugger` | `TracerPid` in `/proc/self/status`, JDWP debugger connected | native + Kotlin |
| `hooking` | Frida/Xposed/LSPosed/Substrate libraries in `/proc/self/maps`, Frida thread names, Frida default port, Xposed classes and stack frames | native + Kotlin |
| `tamper` | Signing certificate SHA-256 vs expected, package name, `debuggable` flag on a release build | Kotlin |
| `untrustedInstaller` | Installer package not in the allowlist | Kotlin |
| `devOptions`, `adbEnabled`, `noScreenLock` | Device settings | Kotlin |
| `accessibilityAbuse` | Enabled accessibility services that can read the screen or perform gestures and are not known assistive tools (TalkBack, Voice Access, Switch Access...); higher confidence when sideloaded | Kotlin |
| `overlay` | Touches on a sensitive screen that arrive through another app's window (`FLAG_WINDOW_IS_OBSCURED` / `PARTIALLY_OBSCURED`) | Kotlin |
| `screenCapture` | Screenshot callback (Android 14+) | Kotlin |
| `screenRecording` | Screen-recording callback, including the initial state (Android 15+) | Kotlin |
| `screenMirroring` | Presentation displays (Cast, Miracast, external screens) | Kotlin |
| `remoteAccessApp` | AnyDesk, TeamViewer QuickSupport, RustDesk, AirDroid and similar installed | Kotlin |
| `activeCall` | Phone or VoIP call in progress (audio mode; no permission needed) | Kotlin |

Event-type signals (screenshots, obscured touches) stay active for 5 minutes, so the next guard still sees them.

## Reactions (local policy)

| Reaction | Effect |
| --- | --- |
| `report` | Appends to the on-device event log (`files/flutter_rasp/events.jsonl`, last 500 entries) and emits a `ThreatEvent` |
| `warnUser` | The event asks the app to show a warning; `Rasp.guard()` returns the threat in `warnings` |
| `blockSensitive` | `Rasp.guard(flow)` denies flows listed in `sensitiveFlows` |
| `secureScreen` | Sets `FLAG_SECURE` on the window while the threat is active |
| `closeApp` | Closes the app 4 s after the event, so the warning can be shown first |

Default policy:

| Threat | Reactions |
| --- | --- |
| `root` | report, warn, block sensitive |
| `emulator` | report, block sensitive |
| `debugger` | report, block sensitive, secure screen |
| `hooking` | report, warn, block sensitive, secure screen |
| `tamper` | report, warn, close app |
| `accessibilityAbuse` | report, warn, block sensitive |
| `overlay` | report, block sensitive |
| `screenRecording`, `screenMirroring` | report, secure screen, block sensitive |
| `screenCapture` | report, secure screen |
| `activeCall` | report, warn (scam warning; the user decides) |
| everything else | report |

`devMode: true` turns every reaction into report only.

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

// PIN and transfer screens: no screenshots or recording, overlays hidden, touches through
// overlays dropped and reported, content hidden from non-assistive accessibility services.
await Rasp.setSensitiveScreen(true);

final guard = await Rasp.guard('transfer');   // fresh scan right before the action
if (!guard.allowed) { /* refuse */ }
if (guard.warnings.contains(ThreatType.activeCall)) { /* "Is someone on the phone asking you to pay?" */ }

// Device binding: the server sends a random challenge and verifies the Key Attestation chain.
final binding = await Rasp.bindDevice(challengeBytes);   // send publicKey + certificateChain to the server

// Every transfer: sign the fields and the RASP verdict with the bound key, using a server nonce.
final signed = await Rasp.signTransaction(flow: 'transfer', nonce: nonce, fields: {'amountCents': '5000'});
```

### Signed transaction format (`rasp-tx-1`)

```
v=rasp-tx-1
nonce=<server nonce>
ts=<device time, ms>
app=<package name>
risk=none|low|medium|high
threats=<comma-separated, sorted>
f.<field>=<value>          (sorted by name; %, CR and LF percent-escaped)
```

The signature is ECDSA P-256 / SHA-256 over the UTF-8 text, made with the hardware-backed key. The verdict is inside the signed text, so hiding a threat or changing the amount breaks the signature.

## Server side (`verifier/`)

- `verify_key_attestation(chain, challenge, package, signer_digests)` runs these checks in order:
    - chain signatures, and validity of the issuing certificates;
    - Google root (both published roots are bundled, including the EC P-384 root used from February 2026);
    - revocation list (optional);
    - challenge;
    - **app identity**: package name and signing-certificate digest in `attestationApplicationId`. This blocks relaying the challenge to another app or phone;
    - key security level (TEE or StrongBox);
    - locked bootloader and verified boot.
- `verify_transaction(...)` checks the bound key's signature, the single-use nonce, the app and the clock skew.
- `decide(tx)` returns:
    - **deny** for tamper, hooking, a debugger, accessibility abuse, overlays, recording or mirroring;
    - **step-up** for root, emulator, a call in progress, remote-access apps or screenshots;
    - **allow** otherwise.
- `python -m rasp_verifier.server --package <pkg> --cert-sha256 <digest> [--allow-software-attestation]` runs the reference backend with these endpoints:
    - `/v1/challenge`
    - `/v1/devices`
    - `/v1/transfers`

    `--allow-software-attestation` is for emulators only; never use it in production.

Demo Bank uses the backend when built with `--dart-define=BANK_SERVER=http://10.0.2.2:8787` (the host as seen from the emulator). Without it, the app runs offline as before.

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
# Kotlin policy engine, fraud signal store, signed payload (JVM)
(cd sample_app/android && ./gradlew :flutter_rasp:testDebugUnitTest)
# Verifier and reference backend
(cd verifier && python3 -m unittest discover -s tests -t .)
# Native core on the host
gcc -Wall -Wextra -Werror -I flutter_rasp/android/src/main/cpp \
  flutter_rasp/android/src/test/cpp/native_test.c \
  flutter_rasp/android/src/main/cpp/{detectors,signals}.c -o /tmp/native_test && /tmp/native_test
```

On an Android emulator, with the profile build and the real policy:

```bash
cd sample_app
DEFINES="--dart-define=RASP_E2E=true --dart-define=RASP_CERT_SHA256=$(tool/cert_digest.sh)"
DRIVE="flutter drive --profile -d emulator-5554 --driver=test_driver/integration_test.dart"
# UI flow: login, transfer blocked on the emulator, no fraud false positives
$DRIVE $DEFINES --target=integration_test/rasp_emulator_test.dart
# Device binding and signed transfer against the reference backend (start it first, see the test header)
$DRIVE $DEFINES --dart-define=BANK_SERVER=http://10.0.2.2:8787 --target=integration_test/bank_server_test.dart
# Scam call: run, then from the host: adb emu gsm call 5551234; adb emu gsm accept 5551234
$DRIVE $DEFINES --target=integration_test/scam_call_test.dart
```

`RASP_E2E` makes `tamper` report-only in test builds. `flutter drive` builds are debuggable, and the engine otherwise treats that as tampering and closes the app.

## Verified on an emulator (Pixel Fold, Android 16, x86_64)

- **UI flow:** login works, and the transfer is blocked because the emulator is detected. There are no false positives for signing certificate, package name, root, hooking or any fraud threat. The Fold's second display is not taken for mirroring.
- **Device binding:** real Android Keystore attestation from the emulator is verified by the reference backend. The signed transfer reaches the server, which denies it from the signed verdict (the test build reports `tamper`).
- **Scam call:** a GSM call placed from the host and answered is detected as `activeCall` within a few seconds, and the transfer flow returns the warning.
- **Sensitive screens:** `FLAG_SECURE` is set on the login screen, so screenshots come out black.
- **Repackaging:** the release APK re-signed with a different key is flagged as `tamper` and closes itself after the warning. The genuine release APK stays open.

## Known limits

- Android only. iOS is not implemented.
- No obfuscation or build-time hardening. The checks are standard and can be found and bypassed by a determined reverse engineer, as the research notes explain. The server-side checks (attestation, signed verdicts, single-use nonces) are what keeps a bypass from turning into an accepted payment.
- Accessibility-abuse, overlay and mirroring detection are covered by unit tests and a clean-device check, not yet by a live malicious-app test.
- The emulator cannot produce hardware attestation under Google's roots. The strict (production) path is covered by the verifier's unit tests with synthetic chains, and still needs checking on a physical device.
- Play Integrity is not integrated yet; it needs a Google Cloud project for the app.
