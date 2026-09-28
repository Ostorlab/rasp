# Mobile platform implementation

The mobile platform ships a proprietary Android/Flutter RASP client with pinned HTTPS, signed OTA policies, erasable Keystore-backed storage and Play Integrity, and an iOS SDK with App Attest binding and assertions, pinned HTTPS and local protections.

All SDK packages are proprietary and intended for private distribution only.

## Implementation sequence

1. **Done:** compile the Android/Flutter baseline with isolated toolchain caches.
2. **Done:** implement the shared Android client, pinned HTTPS, Play Integrity, erasable secure storage, signed policies and reactions; expose the operations through Flutter.
3. **Done:** implement the iOS core and App Attest protocol, with device and macOS validation tracked separately.
4. **Planned:** connect additional private framework adapters to the native SDKs and validate their build targets.

## Policy wire contract

- **Envelope:** `{kid,payload,signature}`.
- **Encoding:** payload and raw 64-byte ES256 signature use base64url.
- **Signature coverage:** exact decoded payload bytes.
- **Payload fields:** `tenantId`, `appId`, increasing integer `revision`, Unix-second `issuedAt` and `expiresAt`, and `config`.
- **Trust:** bootstrap P-256 SPKI verification keys indexed by `kid`.

## iOS App Attest wire contract

The iOS SDK implements this protocol; live App Attest enrollment requires a provisioned device and server verification.

| Endpoint | Request fields | Attestation coverage | Challenge purpose |
| --- | --- | --- | --- |
| `POST /v1/ios/bind` | `{installId,nonce,keyId,attestationObject}` | `clientDataHash` is SHA256 of the UTF-8 nonce | `ios-bind` |
| `POST /v1/ios/token` | `{installId,nonce,keyId,assertion,sealedReport,sessionPublicKey}` | Assertion covers SHA256 of `rasp-token-1\n{nonce}\n{sealedReport.mac}\n{sessionJkt}` | `ios-token` |

**Session key:** `sessionPublicKey` is a base64-encoded P-256 SPKI DER key.

**Thumbprint:** `sessionJkt` is the RFC 7638 JWK thumbprint of that key. Convert it to an EC JWK with base64url 32-byte `x` and `y` coordinates, then base64url-encode SHA256 of the UTF-8 JSON `{"crv":"P-256","kty":"EC","x":"...","y":"..."}` with that member order and no whitespace.

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

**SecureStore** encrypts each value with a random AES-256 data key and AES-GCM; an Android Keystore AES key wraps that data key.

- **Persistence:** entry names are authenticated, files are atomically replaced and no plaintext is stored.
- **Clear:** `secureClear` deletes the wrapping key before files; copied old ciphertext remains unreadable.
- **Recovery:** entries that fail authentication after key invalidation or tampering are deleted and read as absent.
- **No universal StrongBox:** hardware backing depends on the device Keystore.
- **Integrity boundary:** data keys do not derive from the compiled native integrity root.

`wipeOnThreats` is explicitly configured; the local risk model is none/low/medium/high.

- **On detection:** disable session signatures and storage; delete the wrapping key synchronously.
- **Then:** delay ciphertext cleanup by the configured 0–60000ms.
- **`silentDegrade`:** disable signatures/storage without a UI reaction.
- **`stop`:** cancel pending delayed work and discard the session key.
- **Lifetime:** a compromised client remains disabled.

### Signed policy lifecycle

- **Signature coverage:** decoded payload bytes, verified before parsing.
- **Trusted keys and tenant:** bootstrap configuration; the running package is the app audience.
- **Persistence:** atomic writes to no-backup storage.
- **Revision:** monotonic; expired policies fail closed.
- **Configuration:** signed fields override bootstrap values; omitted fields retain bootstrap values.
- **Override scope:** bootstrap trust keys, app identity and `devMode` cannot change through policy.

## Validation boundaries

Live Play Integrity needs a configured project and a suitable enrolled device. Device-farm bypass coverage, performance budgets and App Attest enrollment are separate deployment checks; source/unit validation is not evidence that those checks passed. No public package publication is configured.

Current Android validation: **25 JVM tests**, **9 Dart tests** and clean Flutter analysis. JVM regressions cover real TLS pin/hostname rejection before HTTP delivery, monotonic expired-cache recovery, cancellation of queued reactions, real AES-GCM recovery after wiping/tampering, and session invalidation on successful or failed device-key replacement. The rebind regression fails against the prior implementation because the previous session survives. Android debug APK assembly across the configured native ABIs and the API35 emulator checks below have also passed.

API35 emulator verification passed (`flutter test integration_test/mobile_client_test.dart -d emulator-5556`): actual JNI native scan loads, Android Keystore envelope values round-trip including binary bytes, delete/clear work, and cleartext/unconfigured HTTPS requests are rejected. No live Google attestation project was used.

Expired cached envelopes retain their verified revision while the engine initializes from bootstrap configuration. Token signing, storage and general network requests remain blocked until a newer, current policy is applied. `refreshPolicy(url)` fetches only a signed policy over bootstrap-pinned HTTPS and cannot return resource data. Staged deployments must publish a higher recovery revision before a cohort's policy expires; older stable policies are never accepted as rollback. Engine replacement cancels old reaction generations, including UI callbacks already posted.

The two API35 emulator cases include a real expired signed cache -> blocked guard/storage -> newer signed policy -> successful storage -> rollback rejection sequence. Secure-store AES-GCM tests confirm that leftover ciphertext after wrapping-key invalidation and tampered entries are deleted and read as absent; a new value can then be stored and retrieved.

## iOS build and API

The iOS SDK binds installs to App Attest-backed device keys, seals RASP reports with build-derived integrity, and enforces pinned HTTPS plus jailbreak/debugger/screen-capture detection. It ships as the private Swift package `flutter_rasp/ios`; the CocoaPods Flutter adapter compiles the same core sources. iOS 14+ is required. Core cryptographic contracts are also testable on Linux with Apple's swift-crypto 3.12.3; Apple-only APIs require Xcode and are separately compiled in the macOS CI job.

Enable the App Attest capability for your registered App ID and provision the entitlement `com.apple.developer.devicecheck.appattest-environment` with the value `development` or `production` to match the App Attest environment. The SDK checks service support and surfaces Apple errors. Enrollment is explicit:

1. Call `appAttestBind(nonce)`.
2. POST the returned body to `/v1/ios/bind`.
3. Only after success, call `confirmAppAttestBinding(keyId)`.

Confirmation must occur in the same enrollment generation. Stop/unbind revoke pending confirmation and delete the pending file; after a process restart, repeat enrollment rather than confirming an old pending key. Existing active bindings persist until explicitly unbound.

`prepareAppAttestToken(nonce)` returns the complete token-route body with the new session key covered by an App Attest assertion. App Attest does not establish per-use biometric authorization; iOS tokens correctly carry `uauth=false`.

- **Detection signals:** jailbreak artifacts, sandbox escape writes, debugger status, loaded instrumentation libraries, environment injection and screen capture status. Concurrent callers share one scan, and only newly detected threats contribute notification signals/reactions.
- **Policy:** Android wire format and monotonic revisions. A separate tenant/app-scoped Keychain item retains the accepted revision across process restarts; secret wipes do not reset it. Verified cached policies may equal the floor, but older cache revisions and repeated network revisions are rejected. The floor persists before the cache; interrupted updates block old trust and require a newer recovery revision. A missing cache with an existing floor permits policy refresh while protected operations remain blocked. If a stale/corrupt cache rejects startup after loading a positive floor, `refreshPolicy` can recover with a strictly newer signed policy over bootstrap-pinned HTTPS; protection activates only after its initial scan succeeds. Explicit stop cancels recovery. Keychain errors fail closed. This relies on Keychain protection, rather than a hardware monotonic counter; existing installs seed the floor from their first verified policy after upgrading.
- **Storage:** the envelope wrapping key lives in Keychain with `WhenUnlockedThisDeviceOnly` accessibility: device-only, no cross-device migration, and unavailable while locked. Entries that fail AES-GCM authentication are deleted and read as absent; Keychain, filesystem and framing errors propagate.
- **Reactions:** `wipeOnThreats` destroys the wrapping key and session immediately; `silentDegrade` disables signing/storage; `closeApp` degrades and emits the configured event because iOS has no supported force-close API. New-threat notifications use `reactionDelayMillis` (0–60000) and are generation-checked and cancelled on stop/policy replacement. General pinned requests fail while degraded.
- **Screen capture:** public APIs obscure captured and background content; they cannot guarantee screenshot prevention. Desired protection is recomputed per scan, and queued UI work cannot overwrite newer screen state or stop.
- **Enrollment lifecycle:** generation guards reject stale Apple callbacks and cancelled pending confirmations. Regression tests that stall the Apple attestation callback exercise stop and unbind before Apple completion.

Android-only fraud signals and Play Integrity are not synthesized on iOS.

**Build-time self-integrity** measures selected bounded file regions, including executable code and resources, while excluding the code-signature blob and the manifest itself. After linking, specify immutable regions in a private JSON file, for example `[{"path":"Runner","offset":12345,"length":4096}]`. Run:

```sh
node flutter_rasp/tool/ios_manifest.mjs \
  build/ios/iphoneos/Runner.app private/regions.json \
  build/ios/iphoneos/Runner.app/RaspBuild.json com.example.bank \
  private/private-server-manifest.json
```

Arguments, in order: application bundle path, protected-region JSON, client-manifest output, bundle identifier, private server-manifest output.

Register the private server manifest with `BuildRegistry.register_manifest`, then sign/package the final app. Each runtime measurement derives the report key as `HMAC(buildKey, measuredIntegrityRoot)`; modified protected bytes yield an unregistered key. The client manifest contains build key material and must never be committed. This reference does not claim white-box key hiding or automatic Mach-O section selection. Keychain data keys currently do not incorporate this integrity root.

### iOS validation

Current iOS validation uses the macOS CI gate for Swift unit tests, iOS typechecking and the Flutter CocoaPods build. The tests cover independent screen flags, startup rollback, scan coalescing, cancelled generations, stale screen callbacks, pending-binding cancellation/cleanup and real AES-GCM version-1 framing/recovery. The Node manifest test, all nine Dart tests and Flutter analysis passed locally. Live App Attest and physical-device detector behavior remain provisioning-based checks. The version-1 store format retains its fixed AES-256-GCM layout, with named framing lengths and explicit validation rather than a breaking header change.
