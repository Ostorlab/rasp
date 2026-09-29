# RASP for banking apps

This repo holds three things:

- **`flutter_rasp/`**: a Flutter plugin (Android) for runtime self-protection. Detection and local reactions run on the device and work offline; for server-enforced trust it seals a report and drives the trust-service flow below.
- **`verifier/`**: the **trust service** and a reference **bank resource server**. The trust service issues single-use challenges, binds an install with Android Key Attestation, and mints short-lived integrity tokens from a sealed RASP report, the hardware attestation and a platform (Play Integrity) verdict. The bank verifies those tokens and decides allow, step-up or deny.
- **`sample_app/`**: *Demo Bank*, a Flutter banking app used as the protection target.

See `rasp-research.md` for background and the design document for the full platform.

**Core decision: the device detects and reports; the server decides and enforces.** No client-side verdict is trusted on its own. A device that is rooted, hooked or repackaged still cannot turn a bypass into an accepted payment, because the backend acts only on a trust-service token, and that token is bound to a request-signing key held by a genuine, attested install.

| Tier | Contents |
| --- | --- |
| On device (offline) | Root, emulator, debugger, hooking, tamper, installer and network-interception detection; local policy and reactions; event log |
| Trust tier | Hardware device binding with Key Attestation; a sealed RASP report MAC'd with a per-build key; the trust service scores risk and issues an integrity token; each API request carries a DPoP-style proof bound to the token; the bank verifies the token via JWKS and decides |

## Trust flow

```
device                              trust service                     bank
  │  POST /v1/challenge (bind) ───────►                                │
  │  ◄─────────────────── nonce                                        │
  │  bindDevice(nonce) → key + Key Attestation chain                   │
  │  POST /v1/bind ───────────────────►  verify chain, store install   │
  │                                                                    │
  │  POST /v1/challenge (token) ──────►                                │
  │  ◄─────────────────── nonce                                        │
  │  prepareToken(nonce):                                              │
  │    seal report (per-build MAC), new session key,                   │
  │    install key signs proof (nonce+mac+session) via BiometricPrompt │
  │  POST /v1/token ──────────────────►  verify proof, report, Play    │
  │  ◄──────────── integrity token (ES256 JWT, cnf = session key)      │
  │                                                                    │
  │  signRequest → X-Integrity-* headers (session key) ───────────────►│  verify JWT (JWKS),
  │                                                                    │  verify DPoP proof, decide
  │  ◄─────────────────────────────────────────── allow | step_up | deny
```

Two keys keep this usable: the **install key** is hardware-backed and user-auth bound, and it authorizes token issuance with one biometric prompt (showing the action); the **session key** is ephemeral and signs each request's proof silently for the token's short life, so there is no prompt per request.

## What the plugin detects

| Threat | Detectors | Layer |
| --- | --- | --- |
| `root` | su binaries, root-manager data dirs, root mounts in `/proc/self/mounts`, KernelSU/APatch markers (`kernelsu`, `ksud`, `apatch`, `apd_`) in our threads' `/proc/self/task/*/wchan`, SELinux permissive, root-manager packages, `test-keys` | native + Kotlin |
| `emulator` | QEMU/goldfish device files, `goldfish`/`ranchu` in `/proc/cpuinfo`, goldfish tty in `/proc/tty/drivers`, build fingerprint/model/hardware/product | native + Kotlin |
| `debugger` | `TracerPid` in `/proc/self/status`, behavioral self-ptrace (`fork` + `PTRACE_TRACEME`), JDWP debugger connected | native + Kotlin |
| `hooking` | Frida/Xposed/LSPosed/Substrate libraries in `/proc/self/maps`, Frida thread names, Frida default port, Xposed classes and stack frames, executable mappings from tmp/memfd/deleted files | native + Kotlin |
| `tamper` | Signing certificate SHA-256 vs expected, package name, `debuggable` flag on a release build | Kotlin |
| `netMitm` | An HTTP(S) proxy is set, or a user-installed CA is in the system trust store | Kotlin |
| `untrustedInstaller` | Installer package not in the allowlist | Kotlin |
| `devOptions`, `adbEnabled`, `noScreenLock` | Device settings | Kotlin |
| `accessibilityAbuse` | Enabled accessibility services that can read the screen or perform gestures and are not known assistive tools (TalkBack, Voice Access, password managers...); higher confidence when sideloaded | Kotlin |
| `overlay` | Touches on a sensitive screen that arrive through another app's window (`FLAG_WINDOW_IS_OBSCURED` / `PARTIALLY_OBSCURED`) | Kotlin |
| `screenCapture` | Screenshot callback (Android 14+) | Kotlin |
| `screenRecording` | Screen-recording callback, including the initial state (Android 15+) | Kotlin |
| `screenMirroring` | Presentation displays (Cast, Miracast, external screens) | Kotlin |
| `remoteAccessApp` | AnyDesk, TeamViewer QuickSupport, RustDesk, AirDroid and similar installed | Kotlin |
| `activeCall` | Phone or VoIP call in progress (audio mode; no permission needed) | Kotlin |
| `detectorFailure` | A detector threw, so protection is degraded (reported instead of silently skipped) | native + Kotlin |

The native core runs its detectors twice: `nativeScan()` returns numeric signals for the local policy, and `nativeSeal()` reruns them, splices in the managed-layer (Kotlin) signals, and MACs the exact report bytes with the per-build key so the trust service can authenticate the report. The native methods are bound with `RegisterNatives` (no exported `Java_*` symbol).

Fail-closed rules: a missing native core (`librasp_core.so` removed) is reported as `tamper`; a release build without a pinned signing certificate or package name is `tamper`; a report the trust service cannot authenticate (unknown build, wrong per-build key, as with a repackaged app) is refused. An allowlisted assistive tool only counts when it is a system app or was installed from an app store.

## Reactions (local policy)

Local reactions still run on the device, offline. They are advisory; the **server decision on the token is authoritative** for API calls.

| Reaction | Effect |
| --- | --- |
| `report` | Appends to the on-device event log (`files/flutter_rasp/events.jsonl`, last 500 entries) and emits a `ThreatEvent` |
| `warnUser` | The event asks the app to show a warning; `Rasp.guard()` returns the threat in `warnings` |
| `blockSensitive` | `Rasp.guard(flow)` denies flows listed in `sensitiveFlows` |
| `secureScreen` | Sets `FLAG_SECURE` on the window while the threat is active |
| `closeApp` | Closes the app 4 s after the event, so the warning can be shown first |

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

// Sensitive screens: no screenshots or recording, overlays hidden, touches through overlays dropped,
// content hidden from non-assistive accessibility services.
await Rasp.setSensitiveScreen(true);

final guard = await Rasp.guard('transfer');   // local check right before the action
if (!guard.allowed) { /* refuse locally */ }

// 1. Bind the install (once): the trust service sends a challenge and verifies the Key Attestation chain.
final binding = await Rasp.bindDevice(challengeBytes);   // POST publicKey + certificateChain to /v1/bind

// 2. Authorize a token: seal a fresh report and sign it with the install key (one biometric prompt).
final auth = await Rasp.prepareToken(nonce: nonce, confirmationText: r'Send $50.00 to Alex Smith');
//    POST auth.toRequest(nonce) to /v1/token → integrity token

// 3. Sign each request with the session key (silent) and attach the headers.
final proof = await Rasp.signRequest(method: 'POST', path: '/v1/transfers', body: bodyBytes);
//    request headers: proof.headers(token)   → X-Integrity-Token / -Key / -Sig / -Ts / -Counter
```

`sample_app/lib/data/bank_api.dart` shows the whole flow end to end.

## Server side (`verifier/`)

One installable package (`rasp-verifier`) providing the trust service and a reference resource server.

**Trust service** (`trust.py`, `attestation.py`, `report.py`, `platform.py`, `policy.py`, `registry.py`, `jose.py`):

- `verify_key_attestation(...)` checks, in order: chain structure (only the leaf carries the attestation extension, the leaf is not a CA, every issuer is a CA — this stops a certificate forged with the attested key itself); chain signatures and validity; Google root (both published roots, including the EC P-384 root from February 2026); revocation list; challenge; **app identity** (package and signing-certificate digest in `attestationApplicationId`, blocking a relayed challenge); key security level (TEE or StrongBox); locked bootloader and verified boot; and optionally that every use of the key needs the user.
- `verify_sealed_report(...)` recomputes the per-build HMAC over the exact report bytes, then checks the version, that the report is bound to the challenge nonce, and freshness. A repackaged build cannot know the key, so its report fails.
- `assess_risk(...)` combines the report signals, the attestation summary and the platform verdict into one risk (`none`..`critical`); a missing platform attestation is the design's degraded mode (risk floor raised to medium).
- The trust service issues an ES256 JWT with `risk`, `signals`, `cnf.jkt` (the session key it is bound to), `uauth`, `exp` and a `jti`, and publishes its key at `/.well-known/jwks.json`.
- `RevocationList` keeps Google's revocation list fresh (every 12 h); binding fails closed when the list is missing or older than 48 h.

**Resource server** (`resource.py`): `verify_request(...)` verifies the token via JWKS, that the presented key matches the token's `cnf.jkt`, the request proof (method, path, body hash, timestamp, monotonic counter), and freshness; `decide(risk, ...)` maps risk to allow / step-up / deny with per-endpoint thresholds (a payment denies at `high`, steps up at `medium`).

Run the reference server (trust service + bank in one process, sharing the JWKS):

```bash
cd verifier
python -m rasp_verifier.server --package dev.ostorlab.rasp.demo_bank --cert-sha256 <digest> \
  --build-id test-build \
  --build-key-hex 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
```

Endpoints: `POST /v1/challenge`, `/v1/bind`, `/v1/token`, `GET /.well-known/jwks.json` (trust service); `POST /v1/sessions`, `/v1/transfers` (bank). By default it requires hardware attestation, user-auth keys, a fresh revocation list, and a platform attestation. The flags `--allow-software-attestation`, `--allow-no-user-auth`, `--no-revocation-check` and `--stub-play-integrity` are for emulators and offline demos only; never use them in production. The `--build-id`/`--build-key-hex` must match the app's `flutter_rasp/android/src/main/cpp/build_config.h` (dev defaults shown).

Demo Bank uses the server when built with `--dart-define=BANK_SERVER=http://10.0.2.2:8787` (the host as seen from the emulator). Without it, the app runs offline with local reactions only.

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
# Kotlin policy engine and fraud signal store (JVM)
(cd sample_app/android && ./gradlew :flutter_rasp:testDebugUnitTest)
# Trust service, resource server, attestation, revocation, build-manifest ingestion, and C↔Python seal interop
(cd verifier && python3 -m unittest discover -s tests -t .)
# Build-time hardener: per-build polymorphism, string encryption, guard mesh, build registration (C↔Python)
(cd hardener && python3 -m unittest discover -s tests -t .)
# Native core on the host
gcc -Wall -Wextra -Werror -I flutter_rasp/android/src/main/cpp \
  flutter_rasp/android/src/test/cpp/native_test.c \
  flutter_rasp/android/src/main/cpp/{detectors,signals,sha256,report,guard,strobf,literals}.c -o /tmp/native_test && /tmp/native_test
```

On an Android emulator, with the profile build and the real policy:

```bash
cd sample_app
DEFINES="--dart-define=RASP_E2E=true --dart-define=RASP_CERT_SHA256=$(tool/cert_digest.sh)"
DRIVE="flutter drive --profile -d emulator-5554 --driver=test_driver/integration_test.dart"
# UI flow: login, transfer blocked on the emulator, no fraud false positives
$DRIVE $DEFINES --target=integration_test/rasp_emulator_test.dart
# Bind, token, and a signed transfer against the reference server (see the test header for setup):
$DRIVE $DEFINES --dart-define=BANK_SERVER=http://10.0.2.2:8787 --target=integration_test/bank_server_test.dart
# Scam call: run, then from the host: adb emu gsm call 5551234; adb emu gsm accept 5551234
$DRIVE $DEFINES --target=integration_test/scam_call_test.dart
```

`RASP_E2E` makes `tamper` report-only in test builds; it is honoured in profile builds only. Release builds allow HTTPS only; the cleartext exception for `10.0.2.2` exists in debug and profile builds only.

## What is verified

- **Native binary hygiene:** registered plaintexts of at least four bytes and original internal symbol names are absent from the hardened host library; source scans reject raw protected literals. Optimized LTO, JNI-only release exports, detector-name lifetime, and byte-identical dev/hardened report JSON and full sealed envelopes are tested. Android NDK arm64, armv7 and x86_64 libraries were compiled and scanned, including the integrity-enabled JNI path.

- **Trust service and resource server:** the Python suite (74 tests) covers the full challenge → bind → token → request flow and its refusals — repackaged build (wrong MAC key), forged or replayed proof, replayed challenge, weak or missing platform attestation, forged/relayed/revoked attestation chains — plus the risk-to-decision mapping, ingestion of a hardener build manifest into the build registry, and integrity-derived report sealing (a tampered binary's report fails closed).
- **Build-time hardener:** the `hardener/` suite (108 tests) covers per-build polymorphism (seed → keys/opcodes/detector layout), string-constant encryption, the guard mesh and integrity roots, ELF `.so` region hashing, the build manifest, the CLI, and white-box AES-128 (FIPS-197 KAT for the reference, white-box tables vs the reference, and CTR + AES-CMAC SecureStore round trips with RFC-4493 KAT and tamper rejection). Cross-language tests compile the generated headers and the native primitives (`strobf.c`, `guard.c`, `wbaes.c`, `securestore.c`, `integrity.c`) and assert the C side agrees byte-for-byte with the Python reference — including AES-CMAC, that a tampered SecureStore blob is rejected on both sides, and that the device's runtime integrity root over a `.so` equals the build-time root and that a flipped byte changes both; one drives a hardener manifest through the trust service's build registry and verifies a report sealed with the derived build key.
- **Native core:** the host tests cover the detectors' parsers (including the added emulator/root-hiding/self-ptrace helpers), SHA-256/HMAC known-answer vectors, report sealing, the guard mesh and its integrity-derived key; a cross-language test compiles the native seal and verifies it with the Python trust service, so the device and server HMACs agree byte for byte.
- **On device:** the earlier offline detection, device binding, scam-call and sensitive-screen behaviour were verified on an emulator. The client trust-service wiring (`prepareToken`/`signRequest`, the two-key model, `RegisterNatives`, NET_MITM) is new and needs re-running on an emulator and a physical device; it has not yet been compiled or run on-device in this change.

## Known limits

- Android only. iOS is not implemented (the trust service's App Attest path is stubbed).
- Build-time hardening is partial (see `hardener/`). Per-build polymorphism (seed → build key/id, VM opcode permutation, detector order), per-build encryption of detector IDs, JSON keys, paths, needles, evidence, JNI literals and the build key, per-build internal symbol renaming, the mutually-hashing guard mesh, code-tamper hashing, and trust-service build registration are implemented and cross-language tested. The heavy native obfuscation (LLVM/O-LLVM control-flow flattening, MBA, code virtualization, class/asset encryption, anti-disassembly) and the DEX/ASM Gradle plugin are not done, so the device checks can still be found and bypassed by a determined reverse engineer; the trust service (attestation, the per-build-MAC'd report, single-use nonces, per-request proofs) remains what stops a bypass becoming an accepted payment.
- White-box crypto is partial (see `hardener/` §8). Plain white-box AES-128 (Chow tables) and an authenticated `SecureStore` for data at rest (CTR + AES-CMAC, encrypt-then-MAC) are implemented and cross-language tested against FIPS-197 and RFC 4493, so the AES key is not a contiguous literal in the binary and a tampered blob is rejected. These are the *plain* tables: without the internal encodings / mixing bijections (the next step) they do not yet resist key extraction, and `SecureStore` still needs key wipe-on-critical and the Kotlin/Dart API surface. The report build key is stored as an encrypted registry entry; its reversible XOR encoding does not hide it from a determined analyst. Hardware-backed keys (StrongBox/TEE) remain the primary key protection where available.
- The sealed report authenticates the build and stops forgery and replay, but a determined attacker running inside the app on a compromised device can still influence the managed-layer signals it contains. Hardware attestation and the server-side risk decision are the backstop. **Play Integrity per request** (a Google-signed verdict the app cannot forge) is the next step and needs a Google Cloud project; until then the reference runs in degraded mode (risk floored at medium) and `platform.py` carries the pluggable interface.
- Certificate pinning is detected around (NET_MITM) but not yet enforced in the client; enforcement belongs in the native/OkHttp layer per the design.
- The emulator cannot produce hardware attestation under Google's roots; the strict path is covered by unit tests with synthetic chains and still needs a physical device.
- The reference server keeps state in memory and uses a demo PIN; a bank uses its own authentication and a database for the registries.
