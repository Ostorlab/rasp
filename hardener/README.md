# rasp-hardener

Build-time hardening toolchain for `flutter_rasp` (design §6). It runs in CI before/around the app build and
turns a single random **build seed** into everything that must differ build-to-build, so a bypass developed
against one build does not carry to the next, and so the trust service can recognise exactly what it accepts.

This is the Python-implemented portion of the design's build-time hardening. The native LLVM/O-LLVM
obfuscation passes, the DEX/ASM Gradle plugin, and code virtualization are **not** implemented yet (see the
repo `TODO.md`); what is here is fully covered by tests that run in this repo.

## What it does

| Piece | Module | Design |
| :--- | :--- | :--- |
| Per-build polymorphism: seed → build key, build id, string key, VM opcode permutation, detector order | `seed.py` | §6 per-build polymorphism |
| Compile-time string/constant encryption (no cleartext literals in `.rodata`) | `strenc.py` ↔ `strobf.c` | §6 obfuscation, §2 consteval strings |
| Guard mesh: mutually-hashing integrity guards; result feeds data (keys/offsets), not branches | `guardmesh.py` ↔ `guard.c` | §6 guard network, check weaving |
| Code-tamper hashing folded into an integrity root | `codehash.py` | §6 check weaving, §8 code-tamper hashing |
| Header generation the native build consumes | `emit.py` → `build_generated.h`, `build_seed.h` | §6 pre-build generator |
| Build-registration manifest the trust service loads | `manifest.py` → `BuildRegistry.from_manifest` | §6 build registration, §7 build registry |
| CLI (`gen-build` / `show` / `register`) | `cli.py` | §6 post-build CLI, SDK-only mode |

The derivation is deterministic in the seed (HMAC-SHA256 as a PRF with distinct labels per output), so a build
is reproducible for debugging and re-registration, while the outputs stay independent — leaking the public
`build_id` does not reveal the secret `build_key`.

## Usage

```bash
# Derive a build from a fresh random seed: write build_generated.h + build_seed.h into the native dir and the
# registration manifest to hand to the trust service.
python3 -m rasp_hardener.cli gen-build \
    --cpp-dir flutter_rasp/android/src/main/cpp \
    --package dev.ostorlab.rasp.demo_bank \
    --cert <app-signing-cert-sha256> \
    --manifest build_manifest.json

# Inspect (non-secret) what a seed produces, without writing anything.
python3 -m rasp_hardener.cli show --seed 000102030405060708090a0b0c0d0e0f

# Re-emit only the manifest for a known seed.
python3 -m rasp_hardener.cli register --seed <hex> --cert <sha256>
```

`build_config.h` includes `build_generated.h` when present (via `__has_include`) and otherwise falls back to
the committed dev defaults, so an unhardened build and the host tests keep compiling.

**The generated headers and the manifest are secret** — `build_generated.h` and the manifest carry the build
key. They are git-ignored; deliver the manifest to the trust service over a trusted channel (a CI secret),
never commit it.

## Tests

```bash
cd hardener && python3 -m unittest discover -s tests -t .
```

Coverage: seed determinism/independence/diversity; string-encryption round trip and no cleartext leakage;
guard-mesh known answers, order/tamper sensitivity and key folding; manifest contents and JSON round trip; the
CLI. Two cross-language tests compile the generated header and the native primitives with a C compiler and
assert the C side agrees byte-for-byte with the Python reference (string decode, guard root), and one drives
a hardener manifest through the trust service's `BuildRegistry` and verifies a report sealed with the derived
build key — the same bar as the verifier's native-seal interop test.
