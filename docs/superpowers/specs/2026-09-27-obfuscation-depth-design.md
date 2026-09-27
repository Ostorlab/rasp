# Build-time hardening: obfuscation depth (full binary hygiene)

Date: 2026-09-27 · Branch: `feat/obfuscation-depth` · Design: §6 (build-time hardening), touches §8 only to
stop the build key sitting in `.rodata`.

## Problem

Today only the five JNI registration literals are kept out of `.rodata` (`strenc.py` ↔ `strobf.c`). The rest of
the native core hands a reverse engineer a complete map of the checks: detector IDs (`"native.su_binary"`),
report JSON keys (`"risk"`, `"signals"`), file paths (`"/system/bin/su"`), match needles (`"magisk"`,
`"frida"`), search tokens (`"TracerPid:"`) and evidence strings are plain string literals, and every internal
function name (`rasp_detect_root`, …) is a readable symbol. Two further leaks make it worse:

1. **Build key in `.rodata`.** `RASP_BUILD_KEY_HEX` is emitted as a 64-char hex literal. A repackager can read
   it and forge sealed reports — the exact thing the trust model says a repackaged build cannot do.
2. **Detector order in cleartext.** `build_seed.h` emits `RASP_DETECTOR_ORDER[]` as plaintext detector-ID
   strings, undoing the point of encrypting the IDs.

## Goal and acceptance bar

Static analysis of the hardened binary yields **no protected plaintext and no meaningful symbol names**.
Concretely, a `strings`-style byte scan of the compiled core finds none of the registry plaintexts, and
`.symtab` / `.strtab` / `.dynstr` contain no `rasp_` / `Java_` / registry-derived names. This is enforced by
tests that run on the host in this repo (no device, no Android SDK).

Non-goals: Kotlin/DEX literals (the Gradle-plugin item), managed-code name obfuscation, LLVM/O-LLVM passes,
white-box internal encodings (the real answer for the one key that matters — see Caveats), CI wiring, wire or
trust-service changes.

## Decisions

- **D1 — X-macro literal registry (`literals.def`) as the single source of truth.** Rejected: named-slot dict
  with a second dev fallback list (drift risk), source-rewriting pass (second build graph, overlaps the future
  O-LLVM item).
- **D2 — per-build symbol renaming via generated macros + hidden visibility + stripped release + private
  symbol map.** Rejected: strip-only (names identical across builds), `objcopy --redefine-syms` (second tool,
  coarser control).

## Design

### 1. Literal registry

`flutter_rasp/android/src/main/cpp/literals.def`, checked in, one entry per protected literal:

```c
RASP_LITERAL(SU_BIN_1,      "/system/bin/su")
RASP_LITERAL(SIG_SU_BIN,    "native.su_binary")
RASP_LITERAL(JSON_RISK,     "risk")
RASP_LITERAL(BUILD_KEY_HEX, "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
```

Rules: entry names are stable C identifiers; plaintexts are plain UTF-8 with **no C escape sequences** (the
generator rejects them; a future need grows the parser deliberately). Registry content, by category:

- detector IDs, and the threat label strings `rasp_threat_name` returns (`"root"`, `"emulator"`,
  `"debugger"`, `"hooking"`);
- report JSON keys and version strings;
- file/proc paths and mount needles;
- thread/library/port match needles and search tokens (`"TracerPid:"`);
- evidence and format strings (`"enforce=0"`, `"TracerPid=%d"`);
- the five existing JNI literals (moved from `emit.DEFAULT_STRINGS`);
- **`BUILD_KEY_HEX`** — the build key moves here (leak #1). `RASP_BUILD_ID` deliberately stays a plaintext
  macro: it is public identity.

The registry drives three consumers:

| Consumer | Output |
| :--- | :--- |
| X-macro include in `literals.h` | slot enum `RASP_SLOT_<NAME>` in declaration order; dev-mode plaintext arrays |
| `rasp-hardener gen-build` (`literals.py` parser → `emit.py`) | hardened cipher table in `build_seed.h` (`RASP_STR_<NAME>[]`, `_LEN`, `_IDX`, existing `strenc` transform) |
| source-scan gate | the set of legal literals in the C sources |

### 2. Decode API and call sites

A new umbrella header `hardening.h` is included **first** by every core `.c` file. It pulls in `literals.h`,
and — via `__has_include`, exactly like today's `build_config.h` pattern — the generated `build_seed.h` and
`build_names.h` when present.

`RASP_LIT(NAME, var)` is a **two-statement macro**, usable at block scope only (not in `for` init or
expressions):

- dev/unhardened: `char var[sizeof(DEV_LIT_<NAME>)]; rasp_lit_copy(DEV_LIT_<NAME>, sizeof(DEV_LIT_<NAME>), var);`
  where `literals.h`'s X-macro pass over `literals.def` declares `static const char DEV_LIT_<NAME>[] = "…";`
  (size comes from `sizeof`, so no length macro is needed preprocessor-side);
- hardened: `char var[RASP_STR_<NAME>_LEN + 1]; rasp_strobf_decode(RASP_STR_<NAME>, …, RASP_STRING_KEY, var);`
  (`_LEN` / `_IDX` are generator-emitted, as today).

Loop tables (path arrays, needle arrays) use `rasp_lit_decode(int slot, char *out)` with `RASP_SLOT_*` slot
constants against a reused scratch buffer of `RASP_LIT_MAXLEN + 1` bytes. `RASP_LIT_MAXLEN` is
generator-computed in `build_seed.h`; the dev default is 256 and a unit test asserts every registry entry
fits it, so drift fails loudly. Decoding is a per-byte XOR: decode once per iteration/call into the buffer,
never accumulate.

Helpers that return string literals today — `rasp_threat_name` is the only one — become fill-buffer
signatures (`void rasp_threat_name(rasp_threat_t threat, char *out)`); a decoded stack buffer cannot outlive
its call. Call sites (`report.c`'s `snprintf`) adapt accordingly.

### 3. Leak fixes

- **Leak #1:** `emit.render_build_generated_h` stops emitting `RASP_BUILD_KEY_HEX`, and the
  `RASP_BUILD_KEY_HEX` fallback is removed from `build_config.h`. Both build modes read the `BUILD_KEY_HEX`
  registry slot; `rasp_jni.c` decodes it into a stack buffer and then parses the hex when sealing
  (`RASP_BUILD_ID` stays a plaintext macro in `build_config.h`). The committed dev default
  (`0011…ff`, non-secret) is simply the dev-mode value of that slot.
- **Leak #2:** `build_seed.h` replaces the cleartext `RASP_DETECTOR_ORDER[]` strings with a slot-reference
  array (`RASP_DETECTOR_SLOTS[]` of `RASP_SLOT_*`), decoded at use.

### 4. Symbol renaming (D2)

- Renamable set: every internal C symbol of the core (functions and file-scope data), tracked in a
  checked-in `flutter_rasp/android/src/main/cpp/symbols.def` (`RASP_SYMBOL(rasp_detect_root)`, …);
  `JNI_OnLoad` / `JNI_OnUnload` stay (the JNI natives are bound via `RegisterNatives`, so their C names are
  internal too and get renamed).
- `gen-build` emits `build_names.h`: `#define rasp_detect_root r7f3a91c` … Pseudonyms are PRF-derived from
  the seed — `HMAC(string_key, "raxp/names/v1" || symbol)` truncated to 8 hex chars with an `r` prefix (valid
  C identifier, no libc collision). The generator fails on pseudonym collision.
- Internals keep hidden visibility (already `-fvisibility=hidden`); release links strip `.symtab`.
- `gen-build` writes `symbols.map` (`{"r7f3a91c": "rasp_detect_root", …}`) as a build artifact for crash
  mapping; it is gitignored with the other generated output.
- Without `build_names.h` the names compile unchanged (dev builds keep readable symbols).

### 5. Build pipeline

Unchanged shape, two passes: `rasp-hardener gen-build` (seed → `build_generated.h`, `build_seed.h`,
`build_names.h`, `symbols.map`) → compile → `rasp-hardener gen-build --so` (integrity root →
`integrity_regions.h`, `build_manifest.json`). All generated files stay gitignored. The manifest and trust
flow are unchanged.

## Error handling

- Slots, names and lengths are compile-time; the runtime decode cannot fail and buffers are sized `LEN + 1`.
- `gen-build` fails fast with a clear message on: duplicate registry names, empty plaintexts, C escapes in
  plaintexts, pseudonym collisions, registry entries longer than `RASP_LIT_MAXLEN`'s dev bound.

## Testing and the acceptance gate

1. **Hygiene gate (new):** build the core as a host shared library with test-generated hardened headers from
   a fixed seed and assert: (a) no registry plaintext of ≥ 4 chars in any section; (b) no `rasp_`, `Java_`,
   `RASP_` or renamed-original names in `.symtab` / `.strtab` / `.dynstr`; (c) after `strip`, only the allowed
   export set (`JNI_OnLoad`, `JNI_OnUnload`) survives in `.dynsym`.
2. **Hardened interop smoke (new):** the gate binary also builds and seals a report under hardened headers;
   Python parses it with `rasp_verifier.report` — proving the decrypted JSON keys are wire-valid and the seal
   still verifies.
3. **Source-scan gate (new):** every string literal ≥ 4 chars in the core `.c`/`.h` files is either a registry
   entry or in an explicit allowlist (format strings like `"%d"`, file modes like `"re"`, `"\n"`, and
   cross-language protocol constants kept deliberately identical on both sides — the guard-mesh
   `"raxp/guard-mesh/v1"` seed string, which `guardmesh.py` must byte-match).
4. **Cross-language:** every registry entry decrypts byte-exact C ↔ Python (extends `test_emit_native`);
   existing KATs (strenc, guard mesh, white-box, SecureStore, integrity root) stay green and byte-exact.
5. **Dev path:** the unhardened build compiles and the existing native host tests pass unchanged.
6. Full suites stay green: verifier 73, hardener 71, native host.

First commit on the branch is housekeeping: fix the stale `TODO.md` entries (the codehash item contradicts the
completed integrity-derived-keys item; the header names the wrong branch; the Flutter-wrapper line ignores
`flutter_rasp/`) and the `verifier/rasp_verifier/trust.py` `SigningKey` type reference (missing import).

## Caveats (documented, deliberately not solved here)

- Rolling-XOR string encryption removes contiguous literals but is **not** key hiding: anyone who recovers the
  table can recover `BUILD_KEY_HEX`. The white-box internal-encodings slice is the real fix; this slice makes
  static reconnaissance useless for *finding* the checks.
- Two-statement `RASP_LIT` keeps C99 portability at the cost of macro rigidity; call sites in expression
  position must be adjusted.
- Macro renaming renames tokens textually; same-named locals would collide. The compile runs with
  `-Wall -Wextra -Werror` and the hygiene gate makes any miss loud.
- Crash stacks from hardened builds are unreadable without `symbols.map`; the crash-mapping upload (a
  separate TODO item) consumes it.
