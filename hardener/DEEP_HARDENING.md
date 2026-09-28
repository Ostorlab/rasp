# Opt-in compiler, VM and resource hardening

These components add tested transformations with explicit input contracts. They do not establish
resistance to a determined analyst with dynamic instrumentation, DCA or DFA. The source SDK remains
readable; generated keys, tables, mappings and protected packages belong in private build storage.

## LLVM 18 compiler integration

`compiler/RaspPass.cpp` is an LLVM new-pass-manager plugin. It validates every selected function before
changing the module, substitutes modular integer ADD/XOR identities, demotes cross-block values and PHIs,
and replaces branch edges with a seeded volatile-state dispatcher. An integrity probe at entry is folded
into each integer return. The selected function and its direct call sites lose purity/returned attributes
that would otherwise permit an optimizer to remove the added effects.

Supported functions have a scalar integer return of at most 64 bits, fixed arguments, ordinary branches
and returns, and static entry-block allocations. SSA PHIs and loops are supported. Switch terminators,
EH pads/invoke, taken block addresses, musttail calls, dynamic/non-entry allocations, naked functions,
inline assembly, returns-twice/convergent calls, and stack/coroutine intrinsics are rejected. Selection
must name existing definitions and cannot select the probe. Unsupported selected functions fail the build;
no silent skip is treated as successful protection.

```sh
export LLVM_HOME=/path/to/llvm-18
hardener/compiler/build.sh /private/build/RaspPass.so
python3 hardener/compiler/compile.py \
  --llvm-prefix "$LLVM_HOME" --plugin /private/build/RaspPass.so \
  --functions compute,validate_amount --seed 192837 \
  --input app_sensitive.c --output /private/build/app_sensitive.o
```

The wrapper uses a matching LLVM 18 frontend, transforms before optimizer-driven call elimination, and
runs `opt -verify-each`. It owns optimization/output flags and rejects later `-O`/LTO flags that would undo
the transformation. It produces objects, not a complete app. Link the object with `weave.c`, `guard.c` and
`sha256.c`. Keep protected translation units small: this path prioritizes transformation preservation,
and the extra dispatcher/probe work has application-dependent runtime cost.

Configure `rasp_weave_configure(regions, count, expected_root)` before application threads start. The
expected root must come from the trusted build manifest. Do not establish it by trusting the current
possibly modified bytes. Descriptors are copied, but the region memory must remain readable for the
process lifetime. An unconfigured probe returns a nonzero result. Changed protected bytes perturb
returns; there is no guarantee that this defeats an attacker who can patch the probe or callers.

The default hook is `uint64_t rasp_guard_probe(uint64_t site)`. When the runtime uses generated symbol
renaming, pass its mapped name through `--probe-symbol` (or `RASP_PROBE_SYMBOL` for direct `opt` use).
The plugin seed is a nonzero uint32 layout seed; use a private build-derived value, not the report MAC key.

`integrations/xcode-compile.sh` is an Xcode custom build-rule command. Configure `LLVM_HOME`,
`RASP_PASS_PLUGIN`, `RASP_FUNCTIONS`, `RASP_SEED`, and `RASP_APPLE_TARGET` (for example
`arm64-apple-ios15.0`); Xcode provides `SDKROOT`, `INPUT_FILE_PATH` and `SCRIPT_OUTPUT_FILE_0`.
It cross-compiles selected sources with the matching LLVM toolchain. Linux smoke tests produce an arm64
Mach-O object; an Xcode archive, Apple code signing and device execution are not verified here. This is
not an iOS SDK implementation and does not load the plugin into an incompatible Apple Clang version.

## Constrained arithmetic virtualization

`vm.py` compiles expressions over `r0` through `r3`, uint32 constants and `+ - ^ & | << >>`. Registers
`r4` through `r7` are scratch space. Operations wrap modulo 2^32 and shifts mask their count by 31.
Excess register pressure, unsupported syntax and excessive nesting are rejected.

```sh
rasp-hardener compile-vm --seed 000102030405060708090a0b0c0d0e0f \
  --expression '(r0 + r1) ^ 123' --out /private/build/rules.vm
```

The artifact contains 16 opcode bytes in `seed.BASE_OPCODES` order, then fixed eight-byte instructions:
`opcode, destination, left, right, uint32_le_immediate`. `rasp_vm_run` validates the entire program before
execution and leaves its result untouched on error. Programs have at most 1,024 instructions and an
explicit budget of at most 1,000,000 steps. LOAD is immediate loading, MOV copies a register, CMP tests
equality, and JMP branches when the destination register is nonzero. There is no native memory access,
syscall bridge, or implementation of STORE/HASH/SVC. This is not an arbitrary native-code translator.

## Authenticated resources and integrity-derived data keys

`assets.py` derives separate AES-128 encryption and HMAC-SHA256 authentication keys from a 32-byte base key
and the expected 32-byte guard root, with distinct domain labels. Packages use random 96-bit nonces and
authenticate the version, nonce, SHA256 resource identity and ciphertext. The format is
`RAP1 || nonce[12] || identity_hash[32] || ciphertext || HMAC[32]`. Size is bounded to 16 MiB plaintext.
Never reuse a nonce under the same key. The CLI always generates a fresh nonce.

```sh
rasp-hardener pack-asset --key-file /private/base-key.bin \
  --integrity-root "$EXPECTED_ROOT_HEX" --identity rules.vm \
  --input /private/build/rules.vm --out /private/build/rules.rap \
  --tables /private/build/asset_tables.h
rasp-hardener open-asset --key-file /private/base-key.bin \
  --integrity-root "$EXPECTED_ROOT_HEX" --identity rules.vm \
  --input /private/build/rules.rap --out /private/build/opened.vm
```

`rasp_asset_open` computes the live root from caller-provided regions, derives the authentication key,
checks tag and identity, then decrypts through the generated encoded AES tables. Any failure leaves
output untouched. `rasp_asset_vm_run` composes authenticated opening with the bounded interpreter and
wipes its temporary program buffer. Tests prove wrong live bytes never reach VM execution.

Choose stable, readable integrity regions and finalize their expected root before packaging. Do not
include tables/packages derived from that root in the root's own inputs: that creates a circular build
configuration. The API does not automatically discover application regions or solve self-referential
`.so` layouts. Guarding additional generated tables requires a separately registered expected digest.

Native resource packages are separate from the JVM/DEX `RAJ1` envelope described below. General
SecureStore state migration and hardware-backed key provisioning remain separate concerns.

## Encoded AES tables

`whitebox.generate(key, encoding_seed=seed32)` absorbs independently seeded invertible affine GF(2)
byte mappings at nine state boundaries into adjacent lookup tables. Linear mappings preserve the XOR
composition; one contribution carries each affine offset, and the following round consumes the inverse.
The final table removes the last encoding. `gen-wbkey` enables deterministic key-derived encodings by
default. The C evaluator ABI, AES-128 vectors, CTR and CMAC remain unchanged. The Python API keeps
`encoding_seed=None` for the plain reference tables.

These are byte-local affine mixing bijections. The opt-in `encrypt_block_checked` / `rasp_wbaes_encrypt_block_checked` APIs evaluate two independently
encoded same-key table sets and refuse divergent results without changing output. Tests inject 32
single-bit faults into exercised first-round entries of one table set: Python and C detect 32/32.
This bounded redundancy is not used implicitly by existing CTR/CMAC calls. It does not detect all
common-mode faults, patching of the comparison/control flow, or leakage under DCA. Full nonlinear
encoded-XOR networks and wide mixing bijections are not implemented. Affine encodings alone do not
make the embedded key safe from extraction. Resource keys are integrity-derived; the report-key literal
encoding remains reversible and is not a white-box HMAC implementation.

## Private Gradle ASM plugin

`gradle-plugin/` provides `dev.ostorlab.rasp.hardening` for Gradle 7.3.3 with JDK 11/17 and ASM 9.1.
It produces a separate reproducible `hardenedJar`; the ordinary `jar` remains a development artifact.
The task masks integer constants in selected method instructions and folds `Guard.probe(site)` into
integer returns. A separate `renameMethods` allowlist renames private static methods, rewrites direct
calls and method handles (including lambda bootstrap arguments), and emits the private
`build/rasp/private-methods.map` outside the JAR. Missing/non-private-static selections and collisions
fail. Reflective lookup, native/JNI name binding, serialized method references and calls from artifacts
outside the transformed inputs are not supported: exclude those methods from the rename allowlist.
Public API/class names and string literals remain unchanged.

```groovy
// settings.gradle
pluginManagement {
    repositories { mavenCentral(); gradlePluginPortal() }
    includeBuild('/path/to/rasp/hardener/gradle-plugin')
}
```

```groovy
// build.gradle
plugins { id 'dev.ostorlab.rasp.hardening' }
tasks.named('hardenClasses') {
    seed = 192837L
    methods = ['com/example/Payment#compute(II)I']
    probeOwner = 'com/example/IntegrityGuard'
    renameMethods = ['com/example/Payment#internalRule(I)I']
}
```

Supply `public static int probe(int site)` in that class: zero for healthy state and nonzero to perturb
results. The plugin does not supply an always-healthy production hook. Selected methods must have JVM
bytecode and return `int`; absent, duplicate, abstract/native, wrong-return selections and selection of
the probe fail. The plugin consumes JVM class directories and emits a JAR suitable for an explicit
pre-D8 pipeline. Automatic AGP variant registration, DEX rewriting and Android runtime smoke execution
are not implemented.

## Authenticated JVM and Android class loading

`java-runtime/` provides a working parent-first `EncryptedClassLoader`. Its source supplies an encrypted
package for the requested binary class name; `AuthenticatedPackage.KeyProvider` supplies the AES key.
The loader authenticates the whole GCM tag and class-name AAD before `defineClass`, then wipes its
plaintext byte array. Class definitions and provider-managed key copies can remain in runtime memory;
this is not a sandbox or protection against an in-process observer.

The separate JVM/Android format is `RAJ1 || nonce[12] || AES-GCM ciphertext || tag[16]` with
`rasp/jvm-package/v1` plus the exact identity as AAD. `PackClass` is a real build utility:

```sh
javac --release 11 -d /private/java-runtime \
  hardener/java-runtime/src/main/java/dev/ostorlab/rasp/*.java
java -cp /private/java-runtime dev.ostorlab.rasp.PackClass \
  /private/aes-key.bin com.example.Secret /private/Secret.class /private/Secret.raj
```

Only trusted sources and keys should be passed to the loader. The supplied provider interface uses
software AES key bytes; hardware-backed key provisioning is not implemented by this Java utility.
Tests execute an encrypted class that is absent from the parent classpath and reject modified tags,
wrong identities, wrong keys and truncated packages before defining a class.

`android-runtime/.../EncryptedDexLoader.java` authenticates the same envelope and constructs an
`InMemoryDexClassLoader` over a read-only DEX buffer on API 26+. API <26 fails explicitly; there is no
file-based fallback. Use a stable resource identity such as `private-classes.dex` when sealing and
opening DEX bytes. The helper compiles against Android API35, but ART/device execution and automatic
AGP packaging are release-validation requirements. The DEX plaintext remains available to ART in
memory; no runtime extraction-resistance claim is made.

## Verification

```sh
cd hardener
LLVM_HOME=/path/to/llvm-18 JAVA_HOME=/path/to/jdk-17 \
GRADLE_HOME=/path/to/gradle-7.3.3 GRADLE_USER_HOME=/private/gradle-cache \
python3 -m unittest discover -s tests -t .
```

Resolve the Gradle plugin once with `gradle -p hardener/gradle-plugin build`; its smoke test then runs
offline. The dedicated hardening CI job installs matching LLVM and a checksum-pinned Gradle distribution
so toolchain tests run rather than skip. Tests execute flattened branch/loop/PHI functions, reject
unsupported IR, check real guard mutation, compare Python/C VM and AES, authenticate native packages,
execute seed-diverse JARs with JVM `-Xverify:all`, load authenticated JVM classes, and measure 32/32 detection of the specified single-table fault model. Core CI still enforces the 90% Python hardener
coverage floor and native binary hygiene/size gates.

Implementation references: [LLVM new pass manager](https://llvm.org/docs/WritingAnLLVMNewPMPass.html),
[LLVM IR semantics](https://llvm.org/docs/LangRef.html), and
[ASM ClassWriter/frame handling](https://asm.ow2.io/javadoc/org/objectweb/asm/ClassWriter.html).
