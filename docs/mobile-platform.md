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

`wipeOnThreats` is explicitly configured; the local risk model remains none/low/medium/high. Detection immediately disables session signatures and storage access, synchronously deletes the wrapping key, then delays ciphertext cleanup by the configured 0–60000ms. `silentDegrade` disables signatures/storage without a UI event reaction. `stop` cancels pending delayed work and discards the session key. A compromised client remains disabled for its lifetime.

Policy signatures cover decoded payload bytes before parsing. Trusted keys and tenant are bootstrap configuration; the running package is the app audience. Accepted envelopes persist atomically in no-backup storage. Revisions must increase, and expired policies fail closed. The signed config replaces bootstrap overrides; omitted fields use bootstrap values. Bootstrap trust keys, app identity and devMode cannot be changed through policy.

## Validation boundaries

Live Play Integrity needs a configured project and a suitable enrolled device. Device-farm bypass coverage, performance budgets and App Attest enrollment are separate deployment checks; source/unit validation is not evidence that those checks passed. No public package publication is configured.

Local Android verification: Flutter analyzer clean; 9 Dart tests passed; 20 Kotlin JVM tests passed, including an actual TLS server where invalid leaf pins and hostname mismatch deliver zero HTTP requests; Android debug APK assembled across the configured native ABIs. Device integration status is recorded separately below.

API35 emulator verification passed (`flutter test integration_test/mobile_client_test.dart -d emulator-5556`): actual JNI native scan loads, Android Keystore envelope values round-trip including binary bytes, delete/clear work, and cleartext/unconfigured HTTPS requests are rejected. Emulator was run read-only; no live Google attestation project was used.

Expired cached envelopes retain their verified revision while the engine initializes from bootstrap configuration. Token signing, storage and general network requests remain blocked until a newer, current policy is applied. `refreshPolicy(url)` fetches only a signed policy over bootstrap-pinned HTTPS and cannot return resource data. Staged deployments must publish a higher recovery revision before a cohort's policy expires; older stable policies are never accepted as rollback. Engine replacement cancels old reaction generations, including UI callbacks already posted.

Review regression verification: 24 JVM tests passed (expired-cache revision recovery, immediate wrapping-key invalidation, pending and already-dispatched reaction cancellation), 9 Dart tests passed, analyzer clean, and 2 API35 emulator cases passed including a real expired signed cache -> blocked guard/storage -> newer signed policy -> successful storage -> rollback rejection sequence.

## iOS

The private Swift package is `flutter_rasp/ios`, and the CocoaPods Flutter adapter compiles the same core sources. iOS 14+ is required. Core cryptographic contracts are also testable on Linux with Apple's swift-crypto 3.12.3; Apple-only APIs require Xcode and are separately compiled in the macOS CI job.

Enable the App Attest capability for your registered App ID and provision the entitlement `com.apple.developer.devicecheck.appattest-environment` for your intended environment. The SDK checks service support and surfaces Apple errors. Enrollment is explicit: `appAttestBind(nonce)` -> send returned body to `/v1/ios/bind` -> only after success call `confirmAppAttestBinding(keyId)`. `prepareAppAttestToken(nonce)` returns the complete token-route body with the new session key covered by an App Attest assertion. App Attest does not establish per-use biometric authorization; iOS tokens correctly carry `uauth=false`.

The iOS engine scans jailbreak artifacts, sandbox escape writes, debugger status, loaded instrumentation libraries, environment injection and screen capture status. Signed policies use the Android wire format and monotonic revisions. SecureStore uses device-only, unlocked Keychain storage for the envelope wrapping key. `wipeOnThreats` destroys that key immediately. `silentDegrade` disables signing/storage; `closeApp` on iOS degrades and emits the configured event instead of terminating the process. Public APIs obscure captured and background content; they cannot guarantee screenshot prevention. Android-only fraud signals and Play Integrity are not synthesized on iOS.

Build-time self-integrity uses selected bounded file regions, including executable code and resources. After linking, specify regions in a private JSON file, for example `[{"path":"Runner","offset":12345,"length":4096}]`. Choose immutable code/resource sections, excluding the code-signature blob and the manifest itself. Run:

```sh
node flutter_rasp/tool/ios_manifest.mjs APP_BUNDLE regions.json APP_BUNDLE/RaspBuild.json BUNDLE_ID private-server-manifest.json
```

Register the private server manifest with `BuildRegistry.register_manifest`, then sign/package the final app. Each runtime measurement derives the report key as `HMAC(buildKey, measuredIntegrityRoot)`; modified protected bytes yield an unregistered key. The client manifest contains build key material and must never be committed. This reference does not claim white-box key hiding or automatic Mach-O section selection. Keychain data keys currently do not incorporate this integrity root.

Local iOS validation: portable Swift signature/policy/integrity tests and Node manifest tests execute on Linux; all Apple-target Swift files undergo parser validation. Full UIKit/DeviceCheck typechecking, Flutter CocoaPods linkage, signed-device App Attest and iOS device detector behavior require the macOS CI/deployment checks and are not claimed as locally tested.

Portable iOS verification completed: 4 Swift tests passed using real P-256/AES-capable Apple swift-crypto; Node manifest registration test passed; all Swift files parsed for the arm64 iOS14 target. Flutter analysis and 9 channel/model tests remained green. Swift parser validation is not Apple SDK typechecking.

Reviewed iOS lifecycle behavior: general pinned requests fail while degraded. Enrollment writes are generation-guarded across Apple callbacks; stop/unbind cancel pending enrollment completion. New-threat notifications respect `reactionDelayMillis` (0–60000), are cancelled on stop/policy replacement, and recheck the active generation before delivery. Key deletion and session invalidation occur immediately when a threat is accepted. iOS `closeApp` disables protected operations and reports the reaction; it does not terminate the host application. Suspended attestation-service regression tests exercise stop and unbind before Apple completion.
