# flutter_rasp: Android/iOS runtime application self-protection for Flutter

Proprietary Flutter plugin for runtime application self-protection. Consume through an authorized private Git checkout or local path; public package publication is disabled.

## How do I install the plugin?

Add the authorized checkout to your app's `pubspec.yaml`, then run `flutter pub get`:

```yaml
dependencies:
  flutter_rasp:
    path: ../flutter_rasp
```

For private Git distribution, replace the path dependency with your authorized repository URL and pinned revision:

```yaml
dependencies:
  flutter_rasp:
    git:
      url: ssh://git@YOUR_PRIVATE_GIT_HOST/YOUR_ORG/rasp.git
      path: flutter_rasp
      ref: YOUR_APPROVED_COMMIT
```

## How do I configure protected flows?

```dart
await Rasp.start(RaspConfig(
  expectedPackageName: 'com.example.app',
  expectedSigningCertSha256: ['release certificate SHA256 hex'],
  sensitiveFlows: {'payment'},
  pins: {'api.example.com': ['base64 SHA256 of leaf SPKI']},
  wipeOnThreats: {ThreatType.tamper},
));
final guard = await Rasp.guard('payment');
if (!guard.allowed) return;
```

## What protections are available on Android?

- **Detection:** native root, emulator and instrumentation checks plus framework debugger, signing-certificate and installer checks. Configured reactions can block sensitive flows through `Rasp.guard`.
- **Policy:** signed local policy updates.
- **Fraud signals:** accessibility abuse, overlay touches, screen capture/recording/mirroring, remote-access apps and active calls.
- **Screen protection:** Android `FLAG_SECURE` for protected screens and obscured-touch detection.
- **Storage:** erasable Keystore-wrapped secrets.
- **Attestation:** hardware install-key attestation and Play Integrity tokens.
- **Authorization:** user-authorized token preparation.
- **Request proofs:** ephemeral per-request signatures.

The server-side [trust service](../verifier) evaluates attestation and risk; resource servers enforce final allow/deny decisions.

## What protections are available on iOS?

- **Attestation:** App Attest install binding and assertions.
- **Transport:** pinned HTTPS.
- **Detection:** jailbreak, debugger, instrumentation and screen-capture checks.
- **Storage:** Keychain-wrapped secrets.
- **Policy:** signed local updates.
- **Screen capture:** public screen APIs obscure captured/background content; they cannot guarantee screenshot prevention.

The SDK requires iOS 14+. Android-only fraud signals and Play Integrity are unavailable on iOS. See the [iOS enrollment and validation contract](../docs/mobile-platform.md#ios-build-and-api) for entitlement configuration and explicit server-confirmed enrollment.

## Which APIs enforce these protections?

- `Rasp.request` performs pinned HTTPS and returns exact response bytes. Configure every destination hostname; redirects and cleartext HTTP are rejected.
- `Rasp.playIntegrityToken` requests genuine Google tokens using your enabled Cloud project.
- `Rasp.securePut/Get/Delete/Clear` provide authenticated private storage with erasable Android Keystore wrapping keys.
- `Rasp.applyPolicy` accepts only signed, current policies using configured bootstrap trust keys and tenant identity.
- `Rasp.stop` cancels scans and pending reactions.

See [mobile platform contracts and validation](../docs/mobile-platform.md), [sample app](../sample_app), and [trust service](../verifier). Android consumers must enable core library desugaring for API24/25; the sample shows the Gradle configuration.

## What are the validation limits?

A rooted device can interfere with local protections. Hardware backing and platform attestation availability vary by device. Live Play Integrity requires your project configuration; unit and emulator tests do not substitute for physical-device bypass testing.
