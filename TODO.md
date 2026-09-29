# TODO

Status of the RASP platform against the design document. Legend: **[x]** done, **[~]** partial, **[ ]** missing.

The current scope is Android + a trust service. "Verified" means covered by tests that run in this repo
(Python + native host); Kotlin/Dart client code is written but not yet compiled or run on-device.

## Implemented in this PR and its base

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
- [x] Source literal gate; compiled native plaintext/symbol hygiene; JNI-only release exports; every
  registry entry round-trips through C; dev/hardened report JSON and full sealed envelopes match.
  Android NDK arm64, armv7 and x86_64 compile and scan successfully (not an on-device execution test).
- [x] Python: trust flow, DPoP proofs, risk mapping, HTTP server, attestation, revocation, build-manifest
  ingestion, integrity-derived-key sealing (97 tests).
- [x] Hardener: per-build polymorphism, string encryption, guard mesh, code hashing, manifest, CLI, AES-128
  reference, white-box AES, CTR/SecureStore AEAD (CMAC), ELF/.so integrity hashing (126 tests).
- [x] Native host: parsers, new detector helpers (cpuinfo/tty/wchan/self-ptrace), SHA-256/HMAC vectors,
  report sealing, guard mesh + integrity-derived key, string decode.
- [x] Cross-language: native seal, string decode, guard root and fold-key, white-box AES block and
  SecureStore, and the `.so` integrity root (native runtime == build-time over the same regions, tamper flips
  both) verified against the Python reference (byte-exact); the hardener manifest is verified through the
  trust-service build registry, and integrity-derived sealing through the full token route, end-to-end.

### Build-time hardening (design §6) — `hardener/` toolchain started
- [x] **Native literal and symbol obfuscation.** All protected registry literals (detector IDs, JSON keys,
  paths, needles, evidence, formats, JNI registration and the build key) are encrypted per build and
  decoded into scratch buffers at use. Signal records own copied detector names. `symbols.def` generates
  per-build names and a private `symbols.map`; hidden visibility, an export map and stripped releases
  leave only JNI entry points. Source and compiled-binary gates enforce this, including optimized LTO.
- [x] **Results feeding data (keys/offsets) not branches.** Guard-mesh output derives an offset/key
  (`rasp_guard_offset`, `guardmesh.fold_key`); a single flipped byte changes it, no `if(tampered)` branch.
- [x] **Guard network (mutually-hashing integrity guards).** `guard.c` ↔ `guardmesh.py`, chained per-region
  hashing, known-answer + cross-language tests.
- [x] **Per-build polymorphism (seed → layout/keys/opcodes/detector placement) and build registration.**
  `seed.py` derives build key/id, string key, VM opcode permutation and detector order from a seed;
  `manifest.py` + `BuildRegistry.from_manifest` register the build with the trust service end-to-end.

### Crypto and storage (design §8)
- [x] Integrity-derived keys so tampering fails closed — end-to-end. The hardener hashes the compiled `.so`'s
  code/read-only regions (`elf.py` + `codehash.so_integrity_root`) into the registered integrity root and
  emits `integrity_regions.h`. The device reproduces the same root at runtime over its own `.so`
  (`integrity.c`, located via `dladdr`) and seals the report with `HMAC(build_key, root)` (`rasp_guard_fold_key`
  in `rasp_jni.c`); the trust service derives the same key from the registered root and wires it into the token
  route (`TrustService.token` → `verify_sealed_report(integrity_root=...)`), so a patched binary is refused
  with no on-device branch. Cross-language KAT: the native runtime root equals the build-time root over the
  same `.so`, and a flipped byte changes both; the token route accepts a derived seal and refuses a raw one.

### Validation and DX (design §12, §13, §15)
- [x] Enforcement checker with valid positive control and missing/malformed/expired/replayed-token probes.
- [x] Core CI, coverage floors, native compilation and host binary-size gate.

### Housekeeping
- [x] Proprietary license notices in the repository and Flutter SDK.

## Partial

- [~] **Play Integrity / App Attest (design §7).** Pluggable interface + stub only; no real Google/Apple
  verification. Reference runs in degraded mode (needs a Google Cloud project).
- [~] **Certificate pinning (design §7).** Detection only (`netMitm`); no client-side pin enforcement.
- [~] **Detectors per threat (design §4).** Counted as independent *signals* on the same axis as the README
  table (native + Kotlin). All four threats now meet ≥3: root = 7 (su binaries, root-manager dirs, mounts,
  KernelSU/APatch `wchan`, SELinux, root-manager packages, `test-keys`); emulator = 4 (qemu files, cpuinfo,
  goldfish tty, build fingerprint); debugger = 3 (native TracerPid, native self-ptrace via `fork`+
  `PTRACE_TRACEME`, Kotlin JDWP `Debug.isDebuggerConnected`); hooking = 5 (maps libs, Frida threads, Frida
  port, Xposed classes/frames, behavioral exec-mapping). This PR added the native cpuinfo/tty/`wchan`/
  self-ptrace signals. Still missing: a 4th debugger signal (timing/breakpoint scan, deferred pending
  false-positive tuning), mount-namespace/zygote-PID anomalies, D-Bus/prologue-hash Frida probes, and
  sensor/telephony plausibility.
- [~] **Client trust wiring.** `prepareToken`/`signRequest`, two-key model, `RegisterNatives`, `netMitm`
  are written but not yet compiled or re-verified on an emulator / physical device.
- [~] **Compliance mapping (design §14).** Documented in the design; detectors not yet linked to MASVS/
  MASWE/MASTG ids in code or an exported evidence report.

### Build-time hardening (design §6) — `hardener/` toolchain started
- [~] **Compiler plugins / post-build CLI / SDK-only mode.** LLVM 18 plugin and explicit Clang pipeline
  now flatten supported selected integer-return functions, substitute ADD/XOR MBA identities and weave
  integrity probes. Unsupported IR fails. Xcode custom-rule integration produces arm64 Mach-O smoke
  objects; actual Xcode archives/device runs remain. The Gradle ASM plugin emits reproducible hardened
  JVM JARs with allowlisted private static method renaming and private maps. Authenticated JVM class
  loading executes in tests; an API26+ InMemoryDexClassLoader helper compiles. Automatic AGP variant/DEX
  packaging and ART/device execution remain. See `hardener/DEEP_HARDENING.md`.
- [~] **Deeper obfuscation.** Bounded seeded uint32 VM, expression compiler and authenticated native
  package-to-VM execution are implemented. Assets/class bytes can be encrypted and authenticated, but
  Android ART/device class-loading validation, managed public-name/string obfuscation, arbitrary native virtualization, broader
  compiler coverage and anti-disassembly remain.
- [~] **Weave check calls into app functions.** LLVM and ASM allowlists insert probes into supported
  native/JVM functions, with executable tests. Native probes hash configured live regions; applications
  must supply trusted expected roots/region lifetimes and wire the JVM hook. Whole-app automatic region
  discovery and unsupported function kinds remain.

### Crypto and storage (design §8)
- [~] **Integrity-derived keys on device:** validate `dladdr` self-location on-device (host tests cover
  root computation), hash resources/`libapp.so`, and fold integrity roots into remaining data-key flows.
- [~] White-box crypto (build key, no-hardware devices; DCA/DFA countermeasures). Seeded invertible
  affine byte encodings at nine AES boundaries are absorbed into tables and preserve C/Python AES,
  CTR and CMAC KATs. These are byte-local mixing bijections, not complete nonlinear encoded-XOR networks
  or proven DCA resistance. Opt-in independent-table evaluation detects 32/32 injected exercised
  single-table faults; common-mode and comparison/control-flow faults remain outside that evidence. Asset encryption/authentication keys are separately derived from the
  expected/live guard root. The report build key still uses reversible literal encoding.
- [~] `SecureStore` API; data keys; wipe on critical. Native `securestore.c` provides authenticated
  data-at-rest under white-box AES-128: CTR for confidentiality + AES-CMAC for integrity, encrypt-then-MAC,
  framed `nonce||ciphertext||tag`; `open` verifies the tag in constant time before decrypting. CMAC is
  RFC-4493 KAT-verified and cross-language tested (C == Python; tamper rejected both sides). Missing: key
  wipe-on-critical, and the Kotlin/Dart API surface (JNI binding + method channel).

### Validation and DX (design §12, §13, §15)
- [~] Size/latency budget tooling implemented; physical reference-device measurements remain missing.

## Missing

### Platform
- [ ] **iOS** (SDK, jailbreak/instrumentation detection, App Attest, self-integrity).
- [ ] React Native, KMP, MAUI, Cordova/Capacitor, Unity wrappers; the existing Flutter plugin needs
  pub package-format packaging for a private pub registry.

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
- [ ] Private crash-mapping upload.
