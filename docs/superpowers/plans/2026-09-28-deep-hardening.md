# Deeper hardening implementation plan

> Execute sequentially with the executing-plans workflow. Each component gets its own executable tests and commit; unsupported inputs must fail explicitly.

**Goal:** Deliver usable opt-in compiler transformations, a constrained seeded VM, encoded AES, authenticated packaging, and build integrations without claiming universal transformation or resistance to dynamic cryptanalysis.

**Architecture:** An LLVM 18 new-PM module pass selects named functions, validates supported IR, substitutes integer MBA identities, spills cross-block SSA, and replaces branches with a seeded dispatcher. Woven probes affect return data through an application-configured integrity runtime. An independent arithmetic bytecode format reuses `BuildProfile.opcode_map`. AES round tables absorb invertible affine byte encodings across rounds without changing the native table evaluator ABI. Authenticated native packages bind resource identity and guard-root-derived keys before exposing plaintext. Gradle ASM and Xcode wrappers remain explicit opt-in integrations.

**Tech stack:** LLVM/Clang 18 C++, C99 native runtime, Python stdlib, Java/ASM/Gradle. Toolchain packages are extracted under `/tmp`; no system installation is required.

## Execution checklist

- [x] Compiler: `hardener/compiler/RaspPass.cpp`, build script, and Python smoke test. Test integer branch/loop behavior against the untransformed binary, dispatcher IR, per-seed diversity, guard invocation and rejected switch/EH/unsupported input. Use `opt -verify-each` and execute results.
- [x] Weaving runtime: native `weave.c/.h` with configured region digest; healthy probe yields zero, modified bytes produce a nonzero folded value. Compile the transformed application against the runtime and prove mutation changes output.
- [x] VM: `hardener/rasp_hardener/vm.py`, native `vm.c/.h`; eight 32-bit registers, bounded execution, explicit opcode/register/target validation and arithmetic semantics. Compile expression programs from a small validated input representation; cross-language fixtures cover wraparound and rejection.
- [x] Encoded white-box AES: add an optional deterministic 32-byte encoding seed to `whitebox.generate`; invertible affine GF(2) byte maps at nine state boundaries are absorbed into adjacent tables. Linear contributions preserve XOR composition, one contribution carries the affine offset, and the following round consumes the inverse. Preserve evaluator ABI. Test FIPS-197, random blocks, encoding diversity, C CTR/CMAC KATs, and tampering.
- [x] Guard-derived data keys and packaging: derive independent encryption/authentication material from a guard root and base key; authenticate format, resource identity and ciphertext before opening. Provide concrete pack/open CLI and native resource loader path; test wrong guard root, wrong identity, embedded NULs, truncation, mutations and empty resources. Authenticated JVM class loading executes in tests; the Android DEX helper only compiles against API35, with no on-device DEX/ART execution claim.
- [x] Build integrations: executable Gradle ASM task for selected JVM methods and Clang/Xcode wrapper with explicit version matching. Smoke-build and execute transformed Java and native fixtures. macOS/iOS execution remains unverified on Linux.
- [x] Run full hardener/verifier/native suites, compiler smoke, Java smoke and available NDK builds. Update TODO/README to distinguish implemented bounded scopes from remaining advanced obfuscation and DCA/DFA resistance.

## Contracts and limits

- **Compiler selection:** an explicit comma-separated function allowlist and required numeric build seed. Supported integer-returning branch CFGs are flattened; EH, block addresses, switches, dynamic stack operations and musttail are rejected with diagnostics. Unsupported selected functions fail explicitly.
- **Guard root:** the 32-byte digest of ordered guarded live regions, distinct from the `.so` integrity root used to derive report-sealing keys. Resource APIs use `guard_root`; resource CLI commands use `--guard-root`.
- **Guard lifecycle:** configuration completes before application threads start; an unconfigured probe perturbs results.
- **VM scope:** bounded arithmetic programs only, without arbitrary native memory access or system calls.
- **Authenticated loading:** plaintext is exposed only after authentication. JVM class loading executes in tests; the Android API26+ helper compiles against API35, without verified on-device DEX/ART execution.
- **Encoding limit:** affine byte encodings diversify tables without establishing DCA/DFA resistance.


## Execution evidence

Implementation commits: `f33ff2a` (LLVM/probes), `7aed157` (AES encodings), `d73c90b`
(authenticated VM/resources), `580d9a3` (build integrations and mandatory toolchain CI).
The bounded scopes above are implemented; broader native virtualization, Android ART/device validation,
automatic AGP variants, real Xcode archives/device runs and DCA/DFA resistance are explicitly pending.
Optional detector additions were deferred to the dedicated detector work to avoid concurrent edits.

LLVM 18 was extracted under `/tmp` without system installation. Gradle 7.3.3/JDK 17 CI builds and
executes reproducible seed-specific JARs with JVM verification. The plugin and test fixture set Java 11
source/target bytecode compatibility; execution on JDK 11 is not established by the recorded evidence.
Recorded native NDK arm64/armv7/x86_64
builds and plaintext/export scans passed. The recorded Python hardener coverage was 94%, above the 90% floor.


### Review-driven additions

- Allowlisted JVM private static methods are renamed per seed, including direct calls and lambda/method
  handles. Collision checks and a private map accompany the artifact. Reflection and out-of-input callers
  require explicit keep rules; no public API renaming is claimed.
- The JVM loader executes authenticated AES-GCM class envelopes and rejects four invalid-package modes.
  Android API26+ authenticated InMemoryDexClassLoader integration compiles against API35; ART/device
  execution and lower-API support are not claimed.
- Independent encoded-AES evaluators detect 32/32 injected exercised single-table faults and leave output
  unchanged on mismatch. This opt-in primitive does not establish DCA resistance or common-mode fault
  protection; those remain release-validation requirements.


## What does verification establish?

- **Recorded fully enabled run:** all 126 hardener tests passed with LLVM, Gradle, JVM and Android-JAR
  integration checks enabled, with no skips. This includes JVM execution and Android helper compilation,
  not on-device DEX/ART execution.
- **Review regression run:** the expanded suite discovers 136 tests and reports `OK (skipped=9)` with
  a C compiler and JDK available but `LLVM_HOME`, `GRADLE_HOME` and `ANDROID_JAR` unset. The nine skips
  are seven LLVM tests, one Gradle test and one Android compilation test. The current default environment
  therefore has nine unavailable-toolchain skips, rather than the previously suggested eight.
- **Hardener inventory:** compiler execution/rejection, live guard mutation, Python/C VM parity,
  authenticated native resources, direct affine encoding contracts, encoded-AES fault detection,
  Gradle ASM artifacts and authenticated JVM loading. Android coverage is API35 helper compilation.
- **Recorded verifier run:** 97 tests passed.
- **Recorded native gates:** host tests and the 1 MiB size budget passed with a 39,312-byte stripped host
  core; NDK arm64/armv7/x86_64 compilation, registered-plaintext scans and JNI-only exports passed.
