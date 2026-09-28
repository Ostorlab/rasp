# Deeper hardening implementation plan

> Execute sequentially with the executing-plans workflow. Each component gets its own executable tests and commit; unsupported inputs must fail explicitly.

**Goal:** Deliver usable opt-in compiler transformations, a constrained seeded VM, encoded AES, authenticated packaging, and build integrations without claiming universal transformation or resistance to dynamic cryptanalysis.

**Architecture:** An LLVM 18 new-PM module pass selects named functions, validates supported IR, substitutes integer MBA identities, spills cross-block SSA, and replaces branches with a seeded dispatcher. Woven probes affect return data through an application-configured integrity runtime. An independent arithmetic bytecode format reuses `BuildProfile.opcode_map`. AES round tables absorb invertible linear byte encodings across rounds without changing the native table evaluator ABI. Authenticated packages bind resource identity and code-root-derived keys before exposing plaintext. Gradle ASM and Xcode wrappers remain explicit opt-in integrations.

**Tech stack:** LLVM/Clang 18 C++, C99 native runtime, Python stdlib, Java/ASM/Gradle. Toolchain packages are extracted under `/tmp`; no system installation is required.

## Execution checklist

- [ ] Compiler: `hardener/compiler/RaspPass.cpp`, build script, and Python smoke test. Test integer branch/loop behavior against the untransformed binary, dispatcher IR, per-seed diversity, guard invocation and rejected switch/EH/unsupported input. Use `opt -verify-each` and execute results.
- [ ] Weaving runtime: native `weave.c/.h` with configured region digest; healthy probe yields zero, modified bytes produce a nonzero folded value. Compile the transformed application against the runtime and prove mutation changes output.
- [ ] VM: `hardener/rasp_hardener/vm.py`, native `vm.c/.h`; eight 32-bit registers, bounded execution, explicit opcode/register/target validation and arithmetic semantics. Compile expression programs from a small validated input representation; cross-language fixtures cover wraparound and rejection.
- [ ] Encoded white-box AES: add optional deterministic encoding seed to `whitebox.generate`; invertible GF(2) byte maps at nine state boundaries are absorbed into adjacent tables with balanced masks. Preserve evaluator ABI. Test FIPS-197, random blocks, encoding diversity, C CTR/CMAC KATs, and tampering.
- [ ] Integrity-derived data keys and packaging: derive independent encryption/authentication material from a code root and base key; authenticate format, resource identity and ciphertext before opening. Provide concrete pack/open CLI and native resource loader path where supported; test wrong root, wrong identity, truncation, mutations and empty resources. No DEX runtime loader claim.
- [ ] Build integrations: executable Gradle ASM task for selected JVM methods and Clang/Xcode wrapper with explicit version matching. Smoke-build and execute transformed Java and native fixtures. macOS/iOS execution remains unverified on Linux.
- [ ] Run full hardener/verifier/native suites, compiler smoke, Java smoke and available NDK builds. Update TODO/README to distinguish implemented bounded scopes from remaining advanced obfuscation and DCA/DFA resistance.

## Contracts and limits

Compiler selection is an explicit comma-separated function allowlist and a required numeric build seed. Only supported integer-returning, ordinary branch CFGs are flattened; EH, block addresses, switch terminators, dynamic stack operations and musttail are rejected with diagnostics. No silent partial protection of selected functions. Guard configuration must complete before application threads start, and an unconfigured probe must perturb results. The VM executes arithmetic programs only, never arbitrary native memory or system calls. Resource plaintext is returned only after authentication. Encodings diversify tables but do not establish DCA/DFA resistance.
