# rasp-hardener

Build-time hardening toolchain for `flutter_rasp` (design §6), run in CI around the app build.

A single random **build seed** produces everything that must differ build-to-build: keys, ids, opcode
orderings, detector layout, encrypted literals, guard hashes. Change the seed and a bypass developed against
one build does not carry to the next — and the trust service accepts exactly the build it registered.

This is the Python-implemented portion of the design's build-time hardening. The native LLVM/O-LLVM
obfuscation passes, the DEX/ASM Gradle plugin, and code virtualization are **not** implemented yet (see the
repo `TODO.md`); what is here is fully covered by tests that run in this repo.

## What does the hardener do?

| Piece | Module | Design |
| :--- | :--- | :--- |
| Per-build polymorphism: seed → build key, build id, string key, VM opcode permutation, detector order | `seed.py` | §6 per-build polymorphism |
| Compile-time encryption of the JNI class/method/signature literals (kept out of `.rodata`) | `strenc.py` ↔ `strobf.c` | §6 obfuscation, §2 consteval strings |
| Guard mesh: mutually-hashing integrity guards; result feeds data (keys/offsets), not branches | `guardmesh.py` ↔ `guard.c` | §6 guard network, check weaving |
| Code-tamper hashing folded into an integrity root | `codehash.py` | §6 check weaving, §8 code-tamper hashing |
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
# registration manifest to hand to the trust service.
rasp-hardener gen-build \
    --cpp-dir flutter_rasp/android/src/main/cpp \
    --package dev.ostorlab.rasp.demo_bank \
    --cert <app-signing-cert-sha256> \
    --manifest build_manifest.json

# Echo the seed's derived, non-secret layout (build id, seed fingerprint, opcode map, detector order).
# The seed itself is secret — `show` never prints it, but treat its output as sensitive on shared runners.
rasp-hardener show --seed 000102030405060708090a0b0c0d0e0f

# Re-emit only the manifest for a known seed.
rasp-hardener register --seed <hex> --cert <sha256>

# Generate white-box AES-128 tables for SecureStore (key derived from the build seed, or --key <hex>).
rasp-hardener gen-wbkey --seed <hex> --out flutter_rasp/android/src/main/cpp/wbaes_tables.h
```

## White-box crypto & SecureStore (§8)

`aes.py` is a FIPS-197 AES-128 reference used only to expand the key and validate output. `whitebox.py`
generates plain Chow white-box tables (T-boxes ∘ Tyi MixColumns, and a final table) so the native evaluator
(`wbaes.c`) encrypts AES-128 without the key appearing as a contiguous literal. `securestore.c` uses it in
CTR mode to seal local data at rest (`nonce(12) || ciphertext`) for devices with no hardware keystore.

**Security caveat.** These are the *plain* Chow tables — no internal encodings or mixing bijections yet — so
they do **not** resist key extraction on their own (an analyst can invert Tyi and the S-box to recover the
round key). What this slice delivers is the correct, KAT-verified table architecture and the removal of the
contiguous key literal; the encodings that make white-box AES key-hiding, plus a SecureStore integrity tag
(AEAD/AES-CMAC) and key wipe-on-critical, are the next steps (see the repo `TODO.md` §8).

`build_config.h` includes `build_generated.h` when present (via `__has_include`) and otherwise falls back to
the committed dev defaults, so an unhardened build and the host tests keep compiling.

**The generated headers and the manifest are secret** — `build_generated.h` and the manifest carry the build
key. They are git-ignored; deliver the manifest to the trust service over a trusted channel (a CI secret),
never commit it.

## Tests

```bash
cd hardener && python3 -m unittest discover -s tests -t .
```

Coverage:

- seed determinism, output independence, and build diversity;
- string-encryption round trip with no cleartext leakage;
- guard-mesh known answers, order and tamper sensitivity, and key folding;
- manifest contents and JSON round trip, and the CLI (including that `show`/`gen-build` never print the seed);
- AES-128 against FIPS-197, white-box AES vs the reference, and CTR/SecureStore round trips.

Cross-language tests compile the generated headers and the native primitives with a C compiler and assert the
C side agrees byte-for-byte with the Python reference (string decode, guard root, white-box block, SecureStore
seal/open). One more drives a hardener manifest through the trust service's `BuildRegistry` and verifies a
report sealed with the derived build key — the same bar as the verifier's native-seal interop test.
