# rasp-hardener

Build-time hardening toolchain for `flutter_rasp` (design §6), run in CI around the app build.

A single random **build seed** produces everything that must differ build-to-build: keys, ids, opcode
orderings, detector layout, encrypted literals, guard hashes. Changing the seed changes these artifacts and internal symbol identities; it does not guarantee that
a bypass cannot transfer between builds. The trust service accepts the build it registered.

The toolchain also includes an opt-in LLVM 18 pass, Gradle ASM plugin, Clang/Xcode wrappers, a bounded
arithmetic VM, authenticated native resource loading and affine encoded AES tables. Supported inputs,
required application hooks, commands and remaining limits are documented in
[Deeper hardening](DEEP_HARDENING.md). These mechanisms do not establish DCA/DFA resistance.

## What does the hardener do?

| Piece | Module | Design |
| :--- | :--- | :--- |
| Per-build polymorphism: seed → build key, build id, string key, VM opcode permutation, detector order | `seed.py` | §6 per-build polymorphism |
| Protected literal registry and strict ASCII/C-escape parser | `literals.def`, `literals.py` | §6 obfuscation |
| Per-build literal encryption and scratch-buffer decoding | `strenc.py` ↔ `strobf.c`, `literals.c` | §6 obfuscation, §2 consteval strings |
| Per-build internal symbol names and private crash mapping | `names.py`, `symbols.def` → `build_names.h`, `symbols.map` | §6 name obfuscation |
| Guard mesh: mutually-hashing integrity guards; result feeds data (keys/offsets), not branches | `guardmesh.py` ↔ `guard.c` | §6 guard network, check weaving |
| Code-tamper hashing folded into an integrity root | `codehash.py` | §6 check weaving, §8 code-tamper hashing |
| `.so` code/read-only region hashing → device-reproducible integrity root (fail-closed sealing) | `elf.py`, `codehash.py` → `integrity_regions.h` ↔ `integrity.c` | §8 integrity-derived keys |
| Header generation the native build consumes | `emit.py` → `build_generated.h`, `build_seed.h` | §6 pre-build generator |
| Build-registration manifest the trust service loads | `manifest.py` → `BuildRegistry.from_manifest` | §6 build registration, §7 build registry |
| White-box AES-128 table generation (SecureStore data key) | `aes.py`, `whitebox.py` → `wbaes_tables.h` ↔ `wbaes.c`, `securestore.c` | §8 white-box crypto, SecureStore |
| CLI (`gen-build` / `show` / `register` / `gen-wbkey`) | `cli.py` | §6 post-build CLI, SDK-only mode |

The derivation is deterministic in the seed (HMAC-SHA256 as a PRF with distinct labels per output), so a build
is reproducible for debugging and re-registration, while the outputs stay independent — leaking the public
`build_id` does not reveal the secret `build_key`.

## Usage

Install the package (from the repo root) so the `rasp-hardener` entry point and the `rasp_hardener` module
resolve; the paths below are relative to the repo root:

```bash
pip install -e ./hardener

# Derive a build from a fresh random seed: write build_generated.h + build_seed.h into the native dir and the
# registration manifest to hand to the trust service. Pass --so on the compiled library to hash its code/
# read-only regions into the integrity root and emit integrity_regions.h (design §8 fail-closed sealing).
rasp-hardener gen-build \
    --cpp-dir flutter_rasp/android/src/main/cpp \
    --package dev.ostorlab.rasp.demo_bank \
    --cert <app-signing-cert-sha256> \
    --so app/build/.../arm64-v8a/librasp_core.so \
    --manifest build_manifest.json

# Echo the seed's derived, non-secret layout (build id, seed fingerprint, opcode map, detector order).
# The seed itself is secret — `show` never prints it, but treat its output as sensitive on shared runners.
rasp-hardener show --seed 000102030405060708090a0b0c0d0e0f

# Re-emit only the manifest for a known seed.
rasp-hardener register --seed <hex> --cert <sha256>

# Generate white-box AES-128 tables for SecureStore (key derived from the build seed, or --key <hex>).
rasp-hardener gen-wbkey --seed <hex> --out flutter_rasp/android/src/main/cpp/wbaes_tables.h
```

`gen-build` consumes `literals.def` and `symbols.def` beside the native sources. It also writes
`build_names.h` and `symbols.map`; retain the latter privately for crash symbolication and never package
it with the app. `build_generated.h` contains only the public build ID; the build key is replaced in the
`BUILD_KEY_HEX` encrypted slot. Detector order stays in the manifest, not in a plaintext native table.

`literals.def` is the single source of truth for protected native strings: detector IDs, JSON fragments,
paths, needles, evidence, formats, JNI registration and the build key. Dev builds expand it as plaintext;
hardened builds decode it into caller-owned scratch buffers. Only printable ASCII and C escapes
`\\`, `\"`, `\n`, `\r`, `\t` are accepted. The source gate rejects raw protected literals outside the
registry, and the binary gate checks registered values of at least four bytes, since shorter byte
sequences can occur incidentally in machine code. The cipher and stream use volatile reads to prevent
LTO from reconstructing plaintext constants. Protocol constants, numeric formats and the hex alphabet
remain explicitly allowlisted. This is static-analysis friction, not protection against runtime extraction.

## White-box crypto & SecureStore (§8)

`aes.py` is a FIPS-197 AES-128 reference used only to expand the key and validate output. `whitebox.py`
generates table-driven AES, optionally with seeded affine byte encodings (T-boxes ∘ Tyi MixColumns, and a final table) so the native evaluator
(`wbaes.c`) encrypts AES-128 without the key appearing as a contiguous literal, and provides AES-CMAC
(RFC 4493) over the same block. `securestore.c` uses both for authenticated data at rest: CTR for
confidentiality + AES-CMAC for integrity (encrypt-then-MAC), framed `nonce(12) || ciphertext || tag(16)`;
`open` verifies the tag in constant time before decrypting.

**Security caveat.** `gen-wbkey` enables affine byte mixing bijections at nine state boundaries. The
plain reference mode remains available in Python. These encodings preserve the existing C ABI and
AES/CTR/CMAC known-answer tests, but do not implement full nonlinear encoded-XOR networks or establish
DCA/DFA resistance. Treat embedded keys as extractable by a determined analyst. The authenticated asset
loader derives independent encryption/authentication keys from a guard root and refuses changed live
regions before exposing plaintext; see [Deeper hardening](DEEP_HARDENING.md).

`build_config.h` includes `build_generated.h` when present (via `__has_include`) and otherwise falls back to
the committed dev defaults, so an unhardened build and the host tests keep compiling.

**Keep generated build artifacts private.** The manifest carries the plaintext build key, and
`build_seed.h` carries its reversible encoding and decoder stream. `build_names.h` and `symbols.map`
reveal symbol identities; `build_generated.h` contains only the public ID. All are gitignored. Deliver
the manifest to the trust service through a trusted channel and retain maps only in private build storage.

## Tests

```bash
cd hardener && python3 -m unittest discover -s tests -t .
```

Coverage:

- seed determinism, output independence, and build diversity;
- every protected registry entry round-trips through C, with no registered plaintext in hardened artifacts;
- robust source scan, static/global symbol coverage, release JNI export checks and optimized LTO hygiene;
- dev/hardened JSON and full sealed-envelope parity, independently checked with Python HMAC;
- guard-mesh known answers, order and tamper sensitivity, and key folding;
- manifest contents and JSON round trip, and the CLI (including that `show`/`gen-build` never print the seed);
- AES-128 against FIPS-197, white-box AES vs the reference, AES-CMAC against RFC 4493, and SecureStore
  round trips with tamper rejection;
- ELF `.so` section selection and the integrity root (native runtime root == build-time root, tamper flips both).

Cross-language tests compile the generated headers and the native primitives with a C compiler and assert the
C side agrees byte-for-byte with the Python reference (string decode, guard root, white-box block, SecureStore
seal/open). One more drives a hardener manifest through the trust service's `BuildRegistry` and verifies a
report sealed with the derived build key — the same bar as the verifier's native-seal interop test.
