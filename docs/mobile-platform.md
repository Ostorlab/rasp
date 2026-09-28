# Mobile platform implementation

All SDK packages are proprietary and intended for private distribution only.

Implementation sequence:
1. Compile the Android/Flutter baseline with isolated toolchain caches.
2. Add the shared Android client, pinned HTTPS, Play Integrity, erasable secure storage, signed policy and reaction lifecycle; expose the same operations through Flutter.
3. Add the iOS core and App Attest protocol, with device and macOS validation tracked separately.
4. Connect private framework adapters to the native SDKs and validate supported build targets.

Policy wire contract: `{kid,payload,signature}`. Payload and raw 64-byte ES256 signature are base64url; signature covers exact decoded payload bytes. Payload contains `tenantId`, `appId`, increasing integer `revision`, Unix-second `issuedAt` and `expiresAt`, and `config`. Verification keys are bootstrap P-256 SPKI keys indexed by `kid`.

App Attest bind: `POST /v1/ios/bind` with `{installId,nonce,keyId,attestationObject}`; clientDataHash is SHA256 of UTF-8 nonce. Token: `POST /v1/ios/token` with `{installId,nonce,keyId,assertion,sealedReport,sessionPublicKey}`; assertion covers SHA256 of `rasp-token-1\n{nonce}\n{sealedReport.mac}\n{sessionJkt}`. Challenge purposes are `ios-bind` and `ios-token`.

## Android build and API

Verified toolchain selection: Flutter **3.47.5** at `6a19cca56475dbfba1478ee68d7bd0c2ef891da1`, Dart **3.13.4**, Java 21, Android API 36, NDK 28.2.13676358, CMake 3.22.1, Gradle 9.3.1. Flutter and Android downloads/caches were isolated under `/tmp` during local validation. Consumers targeting Android 24/25 must enable core library desugaring (`com.android.tools:desugar_jdk_libs:2.1.5`).

`RaspClient.execute(method, arguments)` is the shared Android entry point, called on a worker thread. Flutter exposes typed methods. `request` rejects HTTP, credentials in URLs, unconfigured hosts and redirects; it checks system certificate trust, hostname, and a configured **leaf** SPKI pin before sending HTTP data. Pins are base64 SHA-256 of SubjectPublicKeyInfo, indexed by exact hostname. Include the current and next server leaf keys when rotating. No process-global trust or hostname verifier is changed.

Sample configuration:

```sh
flutter run --dart-define=BANK_SERVER=https://bank.example.com \
  --dart-define='RASP_PINS={"bank.example.com":["BASE64_SHA256_SPKI"]}' \
  --dart-define=PLAY_INTEGRITY_PROJECT=123456789
```

A zero/unset project explicitly selects degraded backend mode; a configured project invokes Google and surfaces errors. The project must enable Play Integrity. The request hash is base64url(SHA256(UTF8 nonce)), matching the trust service.

SecureStore uses random AES-256 data keys per value and AES-GCM authenticated encryption. An Android Keystore AES wrapping key protects data keys. Entry names are authenticated, files are atomically replaced, and no plaintext is stored. `secureClear` deletes the wrapping key before deleting files; copied old ciphertext remains unreadable. Hardware backing depends on the device's Keystore implementation; this API does not claim universal StrongBox availability. The store currently does not derive its data keys from the compiled native integrity root.

`wipeOnThreats` is explicitly configured; the local risk model remains none/low/medium/high. Detection immediately disables session signatures and storage access, then executes the wipe after the configured 0–60000ms delay. `silentDegrade` disables signatures/storage without a UI event reaction. `stop` cancels pending delayed work and discards the session key. A compromised client remains disabled for its lifetime.

Policy signatures cover decoded payload bytes before parsing. Trusted keys and tenant are bootstrap configuration; the running package is the app audience. Accepted envelopes persist atomically in no-backup storage. Revisions must increase, and expired policies fail closed. The signed config replaces bootstrap overrides; omitted fields use bootstrap values. Bootstrap trust keys, app identity and devMode cannot be changed through policy.

## Validation boundaries

Live Play Integrity needs a configured project and a suitable enrolled device. Device-farm bypass coverage, performance budgets and App Attest enrollment are separate deployment checks; source/unit validation is not evidence that those checks passed. No public package publication is configured.

Local Android verification: Flutter analyzer clean; 9 Dart tests passed; 20 Kotlin JVM tests passed, including an actual TLS server where invalid leaf pins and hostname mismatch deliver zero HTTP requests; Android debug APK assembled across the configured native ABIs. Device integration status is recorded separately below.

API35 emulator verification passed (`flutter test integration_test/mobile_client_test.dart -d emulator-5556`): actual JNI native scan loads, Android Keystore envelope values round-trip including binary bytes, delete/clear work, and cleartext/unconfigured HTTPS requests are rejected. Emulator was run read-only; no live Google attestation project was used.
