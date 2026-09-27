# TODO

Status of the RASP platform against the design document. Legend: **[x]** done, **[~]** partial, **[ ]** missing.

The current scope is Android + a trust service. "Verified" means covered by tests that run in this repo
(Python + native host); Kotlin/Dart client code is written but not yet compiled or run on-device.

## Done (this branch: `feat/trust-service`)

### Trust service (design §3, §7)
- [x] Single-use challenges bound to an install (`POST /v1/challenge`).
- [x] Device binding with Android Key Attestation (`POST /v1/bind`): chain structure, signatures, Google
  roots (incl. EC P-384), revocation (fail-closed), challenge, app identity, security level, verified boot,
  optional per-use user auth.
- [x] Integrity token issuance (`POST /v1/token`): ES256 JWT with `risk`, `signals`, `cnf.jkt`, `uauth`,
  `exp`, `jti`.
- [x] JWKS endpoint (`GET /.well-known/jwks.json`).
- [x] Sealed RASP report: native core MACs the exact report bytes with a per-build key (HMAC-SHA256);
  server refuses unknown build, wrong key (repackaged app), replayed or stale reports.
- [x] Server-side risk scoring (none..critical) from report + attestation + platform verdict; token TTL by
  risk; degraded mode when no platform attestation (risk floor raised).
- [x] Two-key model: user-auth install key authorizes issuance (one biometric prompt); ephemeral session
  key signs per-request proofs silently.
- [x] Build and install registries (in-memory reference).

### Resource server / backend (design §7, §9)
- [x] Token verification via JWKS + DPoP-style per-request proof (method, path, body hash, ts, counter).
- [x] Replay protection scoped to the session key; cross-token replay bounded by proof ts + token expiry.
- [x] Risk → allow / step-up / deny with per-endpoint thresholds (payment denies at high, steps up at medium).
- [x] Reference bank: login with PIN lockout, session→install binding.

### Runtime detection (design §4, §5)
- [x] Native detectors: root (files, mounts, SELinux), emulator, debugger (TracerPid), instrumentation
  (maps/threads/port), behavioral executable-mapping detector (tmp/memfd/deleted).
- [x] `RegisterNatives` (no exported `Java_*` symbol); direct file reads.
- [x] Kotlin detectors: root packages, build tags, emulator build, debugger, hooking frameworks, signing
  cert, package name, debuggable flag, installer, device settings.
- [x] Network-interception detection (`netMitm`): HTTP proxy or user-installed CA.
- [x] Fraud: accessibility abuse (allowlist incl. password managers), overlays/tapjacking, screenshots,
  recording, mirroring, remote-access apps, active call; sensitive-screen mode (`FLAG_SECURE`, hide
  overlays, drop obscured touches, accessibility-data-sensitive).
- [x] Fail-closed: missing native core → tamper; unpinned integrity config → tamper; detector exception →
  `detectorFailure`.

### Crypto (design §8)
- [x] Hardware-backed install key (StrongBox/TEE), non-exportable, attested, per-use user auth.
- [x] Per-build MAC key for the sealed report.

### Response engine (design §9)
- [x] Local reactions (report, warn, block sensitive, secure screen, close app), OTA-independent.
- [x] Authoritative server decision on the token.

### Fixes
- [x] Android 7–8.1 crash on user-auth signing (BiometricPrompt is API 28+): guarded, surfaces
  `auth_unsupported`.
- [x] Password managers no longer flagged as accessibility abuse.

### Tests
- [x] Python: trust flow, DPoP proofs, risk mapping, HTTP server, attestation, revocation, build-manifest
  ingestion (65 tests).
- [x] Hardener: per-build polymorphism, string encryption, guard mesh, code hashing, manifest, CLI (34 tests).
- [x] Native host: parsers, SHA-256/HMAC known-answer vectors, report sealing, guard mesh, string decode.
- [x] Cross-language: native seal, string decode, and guard root verified against the Python reference
  (byte-exact); hardener manifest verified through the trust-service build registry end-to-end.

## Partial

- [~] **Play Integrity / App Attest (design §7).** Pluggable interface + stub only; no real Google/Apple
  verification. Reference runs in degraded mode (needs a Google Cloud project).
- [~] **Certificate pinning (design §7).** Detection only (`netMitm`); no client-side pin enforcement.
- [~] **Detectors per threat (design §4).** Not yet "≥3 independent per threat"; missing root-hiding
  consistency checks (mount namespaces, zygote/PID anomalies, KernelSU/APatch side channels), behavioral
  Frida beyond names (D-Bus probe, RWX pages, prologue hashes), self-ptrace, timing, sensor/telephony
  plausibility.
- [~] **Client trust wiring.** `prepareToken`/`signRequest`, two-key model, `RegisterNatives`, `netMitm`
  are written but not yet compiled or re-verified on an emulator / physical device.
- [~] **Compliance mapping (design §14).** Documented in the design; detectors not yet linked to MASVS/
  MASWE/MASTG ids in code or an exported evidence report.

## Missing

### Platform
- [ ] **iOS** (SDK, jailbreak/instrumentation detection, App Attest, self-integrity).
- [ ] React Native, Flutter (pub.dev packaging), KMP, MAUI, Cordova/Capacitor, Unity wrappers.

### Build-time hardening (design §6) — `hardener/` toolchain started
- [~] **Compiler plugins / post-build CLI / SDK-only mode.** `rasp-hardener` CLI (`gen-build`/`show`/
  `register`) is the Python pre-build generator + post-build registration step. LLVM/O-LLVM Clang passes,
  the Xcode toolchain, and the DEX/ASM Gradle plugin are not implemented.
- [~] **Obfuscation.** String/constant encryption done for the five JNI registration literals (the class name,
  `nativeScan`/`nativeSeal`, and their two signatures): XOR-encrypted per build (`strenc.py`) and decrypted
  natively on use (`strobf.c`), cross-language verified. Detector IDs, JSON keys, and file paths remain
  cleartext; name obfuscation, control-flow flattening, MBA, code virtualization, class/asset encryption, and
  anti-disassembly are not done.
- [x] **Results feeding data (keys/offsets) not branches.** Guard-mesh output derives an offset/key
  (`rasp_guard_offset`, `guardmesh.fold_key`); a single flipped byte changes it, no `if(tampered)` branch.
- [ ] **Weave check calls into arbitrary app functions** (vs. only the RASP core) — not automated yet.
- [x] **Guard network (mutually-hashing integrity guards).** `guard.c` ↔ `guardmesh.py`, chained per-region
  hashing, known-answer + cross-language tests.
- [x] **Per-build polymorphism (seed → layout/keys/opcodes/detector placement) and build registration.**
  `seed.py` derives build key/id, string key, VM opcode permutation and detector order from a seed;
  `manifest.py` + `BuildRegistry.from_manifest` register the build with the trust service end-to-end.

### Crypto and storage (design §8)
- [ ] Integrity-derived keys (KDF over code hashes + signer + check outputs) so tampering fails closed.
- [ ] White-box crypto (build key, no-hardware devices; DCA/DFA countermeasures).
- [ ] `SecureStore` API; data keys; wipe on critical.
- [~] Code-tamper hashing folded into keys. `codehash.py` hashes the native sources + signer digest into a
  guard-mesh integrity root recorded in the build manifest; hashing `.so` `.text`/resources/`libapp.so`
  regions and folding the root into the live report/data keys at runtime is not wired yet.

### Control plane (design §10)
- [ ] OTA signed policy delivery (detector params, thresholds, reactions, pins, allowlists) — currently all
  compiled in.
- [ ] Console, dashboards, install timeline, bypass watch, policy editor with staged rollout + auto-rollback.
- [ ] Telemetry ingestion, signal store, risk ML model, SIEM export.
- [ ] Durable registries (Postgres) and multi-tenancy.

### Server-side agent (design §11) — not started
- [ ] Per-runtime instrumentation (Java, .NET, Node, Python, Go, PHP); sink-based detection.
- [ ] Virtual patching (CVE shields) driven by SCA.
- [ ] Optional eBPF sensor.

### Response engine (design §9)
- [ ] Silent degrade (poison derived keys / break signatures) instead of overt reactions.
- [ ] Reaction spreading/delay away from the detection site.

### Network (design §7)
- [ ] `/v1/secrets` (runtime secrets scoped to risk); server-side key rotation.
- [ ] Dynamic pin set delivered with policy.

### Validation and DX (design §12, §13, §15)
- [ ] Red-team bypass regression suite on a device farm (Frida forks, hidden root/jailbreak, attestation
  spoofing/relay, static patching).
- [ ] Enforcement checker (calls endpoints with no/expired/replayed token before go-live).
- [ ] CI integrations, build gate on coverage/size, crash-mapping upload.
- [ ] Performance/size budgets measured on reference devices.

### Housekeeping
- [ ] Choose and add a license (`flutter_rasp/LICENSE` is still a TODO placeholder).
