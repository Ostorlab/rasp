# flutter_rasp

Proprietary Flutter plugin for runtime application self-protection. Consume through an authorized private Git checkout or local path; public package publication is disabled.

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

Android capabilities:

- **Detection:** native and framework checks.
- **Policy:** signed local policy updates.
- **Fraud signals:** platform fraud checks.
- **Screen protection:** sensitive-screen controls.
- **Storage:** erasable Keystore-wrapped secrets.
- **Attestation:** hardware install-key attestation and Play Integrity tokens.
- **Authorization:** user-authorized token preparation.
- **Request proofs:** ephemeral per-request signatures.

The trust service remains authoritative.

- `Rasp.request` performs pinned HTTPS and returns exact response bytes. Configure every destination hostname; redirects and cleartext HTTP are rejected.
- `Rasp.playIntegrityToken` requests genuine Google tokens using your enabled Cloud project.
- `Rasp.securePut/Get/Delete/Clear` provide authenticated private storage with erasable Android Keystore wrapping keys.
- `Rasp.applyPolicy` accepts only signed, current policies using configured bootstrap trust keys and tenant identity.
- `Rasp.stop` cancels scans and pending reactions.

See [mobile platform contracts and validation](../docs/mobile-platform.md), [sample app](../sample_app), and [trust service](../verifier). Android consumers must enable core library desugaring for API24/25; the sample shows the Gradle configuration.

A rooted device can interfere with local protections. Hardware backing and platform attestation availability vary by device. Live Play Integrity requires your project configuration; unit and emulator tests do not substitute for physical-device bypass testing.
