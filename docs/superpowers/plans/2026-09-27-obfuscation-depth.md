# Obfuscation Depth (Full Binary Hygiene) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove every protected plaintext and meaningful symbol name from the hardened native RASP binary, close the build-key and detector-order leaks, and enforce both with compile-and-scan gates that run on the host.

**Architecture:** A checked-in X-macro registry (`literals.def`) is the single source of truth for protected literals. Dev builds expand it to plaintext; hardened builds encrypt it per-build into `build_seed.h` and decode at use via `rasp_lit_decode(slot, out)`. Symbols are renamed per-build through generated macros (`build_names.h`), with a private `symbols.map` kept for crash mapping. Two gates compile the core and prove the binary is clean.

**Tech Stack:** C99 (NDK core, compiled on host with gcc for tests), Python 3.12 stdlib (`rasp_hardener`, `unittest`), existing `strenc.py`/`strobf.c` XOR transform.

**Spec:** `docs/superpowers/specs/2026-09-27-obfuscation-depth-design.md` (branch `feat/obfuscation-depth`).

Conventions used below:
- All paths relative to the repo root.
- Python tests run as: `cd hardener && python3 -m unittest discover -s tests -t .` (targeted: `python3 -m unittest tests.test_X -v`).
- Verifier tests run as: `cd verifier && python3 -m unittest discover -s tests -t .`.
- Native host tests: `gcc -Wall -Wextra -Werror -I flutter_rasp/android/src/main/cpp flutter_rasp/android/src/test/cpp/native_test.c flutter_rasp/android/src/main/cpp/{detectors,signals,sha256,report,guard,strobf,literals}.c -o /tmp/native_test && /tmp/native_test`
- The C sources use `-Wall -Wextra -Werror`; generated code must be warning-free.

---

## Execution record (2026-09-28)

Tasks 1–11 are implemented and locally verified. The original snippets below remain the reviewed plan,
not an exact copy of the final code. Publishing the PR is reserved for the coordinating agent.

- Task 1: `5d5b951`, reviewed independently before this implementation.
- Tasks 2–10: `546cb54`, registry/parser, encrypted C decoding, all call-site migrations, private symbol
  renaming, source/binary gates and complete sealed-envelope parity.
- Task 11: documentation and verification recorded in the following documentation commit.
- Correctness refinements: signal records copy decoded detector IDs; comments are stripped without
  corrupting quoted text; renaming precedes declarations; generated slot order/count is compile-checked;
  decoder volatile reads prevent LTO constant folding; symbol coverage is checked in unoptimized objects.
- Android NDK exposed linker-generated global boundary symbols despite hidden visibility. `exports.map`
  enforces JNI-only exports, and release builds strip local symbols.
- Verified: 108 hardener tests, 74 verifier tests, native host tests, and NDK r21 arm64/armv7/x86_64
  hardened libraries with the integrity-enabled JNI path, no registered plaintext and `JNI_OnLoad` only.
- No device execution claimed. Reversible literal encoding is not key hiding; managed obfuscation and
  heavier compiler/white-box protections remain separately tracked in `TODO.md`.

---

## File structure

| File | Responsibility | Task |
| :--- | :--- | :--- |
| `verifier/rasp_verifier/trust.py` | Fix `SigningKey` annotation import | 1 |
| `TODO.md` | Fix stale entries | 1 |
| `flutter_rasp/android/src/main/cpp/literals.def` | Registry: every protected literal (name + C source text) | 2 |
| `hardener/rasp_hardener/literals.py` | Parse registry, unescape C literals, validate | 2 |
| `hardener/tests/test_literals.py` | Parser/unescape/validation tests | 2 |
| `hardener/rasp_hardener/strenc.py` | Accept `bytes` plaintext | 3 |
| `hardener/rasp_hardener/emit.py` | Registry-driven `build_seed.h` (opaque names, key slot, no detector-order strings), `build_names.h`, `symbols.map` | 3, 7, 9 |
| `hardener/tests/test_emit_native.py` | Cross-language: every entry decrypts C == Python | 3 |
| `flutter_rasp/android/src/main/cpp/literals.h` | Slot enum, `RASP_LIT`, `rasp_lit_decode` decl | 4 |
| `flutter_rasp/android/src/main/cpp/literals.c` | Decode impl (hardened table / dev X-macro table) | 4 |
| `flutter_rasp/android/src/main/cpp/hardening.h` | Umbrella: literals + optional `build_names.h` | 4 |
| `flutter_rasp/android/src/main/cpp/CMakeLists.txt` | Build `literals.c` | 4 |
| `flutter_rasp/android/src/main/cpp/rasp_jni.c` | JNI literals via `RASP_LIT`; build key from `BUILD_KEY_HEX` slot | 4, 7 |
| `flutter_rasp/android/src/main/cpp/{detectors,signals,report,guard,integrity,sha256,strobf,wbaes,securestore}.h` | Include `hardening.h` first | 4 |
| `flutter_rasp/android/src/main/cpp/signals.c`, `report.c` | Migrate JSON/threat literals; `rasp_threat_name` fill-buffer | 5 |
| `flutter_rasp/android/src/main/cpp/signals.h` | `rasp_threat_name` signature | 5 |
| `flutter_rasp/android/src/main/cpp/detectors.c` | Migrate all literals | 6 |
| `flutter_rasp/android/src/main/cpp/build_config.h` | Drop `RASP_BUILD_KEY_HEX` | 7 |
| `flutter_rasp/android/src/main/cpp/symbols.def` | Registry: every renamable symbol | 9 |
| `hardener/rasp_hardener/names.py` | Pseudonym derivation + collision check | 9 |
| `hardener/tests/test_names.py` | Naming tests | 9 |
| `hardener/tests/test_source_scan.py` | Gate: no unregistered literals in sources | 10 |
| `hardener/tests/test_hygiene_gate.py` | Gate: clean binary + hardened interop smoke | 11 |
| `README.md`, `hardener/README.md` | Docs, test commands, known-limits | 12 |

---

## Task 1: Housekeeping

**Files:**
- Modify: `verifier/rasp_verifier/trust.py:26-33` (imports)
- Modify: `TODO.md`

- [ ] **Step 1: Write the failing check**

Add to `verifier/tests/test_trust.py` at the end of the file:

```python
class TrustServiceAnnotationTest(unittest.TestCase):
    def testSigningKeyAnnotation_resolves_noNameError(self):
        hints = typing.get_type_hints(rasp_verifier.trust.TrustService.__init__)
        self.assertIn("signing_key", hints)
        self.assertIs(hints["signing_key"], rasp_verifier.jose.SigningKey)
```

At the top of `verifier/tests/test_trust.py`, add `import typing` and make sure `rasp_verifier` and `rasp_verifier.jose` are imported (the file already imports `rasp_verifier`; add `from rasp_verifier import jose` if `jose` is not reachable).

- [ ] **Step 2: Run test to verify it fails**

Run: `cd verifier && python3 -m unittest tests.test_trust.TrustServiceAnnotationTest -v`
Expected: `NameError: name 'SigningKey' is not defined` (from `get_type_hints`) — FAIL.

- [ ] **Step 3: Fix the import**

In `verifier/rasp_verifier/trust.py`, the import block already has `from . import jose`. Add after the `from .report import ...` line:

```python
from .jose import SigningKey
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd verifier && python3 -m unittest tests.test_trust.TrustServiceAnnotationTest -v`
Expected: PASS. Then run the whole verifier suite: `cd verifier && python3 -m unittest discover -s tests -t .` → `Ran 74 tests ... OK`.

- [ ] **Step 5: Fix stale TODO.md entries**

Three edits in `TODO.md`:
1. Header line `## Done (this branch: \`feat/trust-service\`)` → `## Done (merged on \`main\`)`.
2. In the `Code-tamper hashing folded into keys` bullet, replace the trailing sentence `hashing \`.so\` \`.text\`/resources/\`libapp.so\` regions and folding the root into the live report/data keys at runtime is not wired yet.` with `the \`.so\` region hash is folded into the live report key end-to-end (see the integrity-derived-keys bullet above).`
3. In `### Platform`, change `- [ ] React Native, Flutter (pub.dev packaging), KMP, MAUI, Cordova/Capacitor, Unity wrappers.` to `- [ ] pub.dev packaging for \`flutter_rasp\`, plus React Native, KMP, MAUI, Cordova/Capacitor, Unity wrappers.` (the Flutter plugin itself exists).

- [ ] **Step 6: Commit**

```bash
git add verifier/rasp_verifier/trust.py verifier/tests/test_trust.py TODO.md
git commit -m "fix: SigningKey annotation import and stale TODO entries"
```

---

## Task 2: The literal registry and its parser

**Files:**
- Create: `flutter_rasp/android/src/main/cpp/literals.def`
- Create: `hardener/rasp_hardener/literals.py`
- Test: `hardener/tests/test_literals.py`

- [ ] **Step 1: Write the failing tests**

Create `hardener/tests/test_literals.py`:

```python
"""Tests for the literal registry (literals.def) and its parser (rasp_hardener.literals)."""

import pathlib
import tempfile
import unittest

from rasp_hardener.literals import (
    MAX_TEXT_LEN,
    Literal,
    literals_by_name,
    parse_literals,
    unescape_c,
)

CPP = pathlib.Path(__file__).resolve().parents[2] / "flutter_rasp" / "android" / "src" / "main" / "cpp"
REGISTRY = CPP / "literals.def"


class UnescapeCTest(unittest.TestCase):
    def testPlain_ascii_staysBytes(self):
        self.assertEqual(unescape_c("native.su_binary"), b"native.su_binary")

    def testEscapes_decodeToBytes(self):
        self.assertEqual(unescape_c('{\\"threat\\":\\"%s\\"'), b'{"threat":"%s"')
        self.assertEqual(unescape_c("\\\\%c"), b"\\%c")
        self.assertEqual(unescape_c("a\\nb\\tc\\rd"), b"a\nb\tc\rd")

    def testUnsupportedEscape_raises(self):
        with self.assertRaises(ValueError):
            unescape_c("\\x41")
        with self.assertRaises(ValueError):
            unescape_c("\\u0041")
        with self.assertRaises(ValueError):
            unescape_c("trailing\\")

    def testQuoteEscape_keepsQuote(self):
        self.assertEqual(unescape_c('a\\"b'), b'a"b')


class ParseRegistryTest(unittest.TestCase):
    def testRealRegistry_parsesUniqueNames(self):
        lits = parse_literals(REGISTRY)
        self.assertGreater(len(lits), 80)
        names = [lit.name for lit in lits]
        self.assertEqual(len(names), len(set(names)))

    def testRealRegistry_containsKnownEntries(self):
        by_name = literals_by_name(parse_literals(REGISTRY))
        self.assertEqual(by_name["TRACER_LABEL"].text, b"TracerPid:")
        self.assertEqual(by_name["SIG_SU_BIN"].text, b"native.su_binary")
        self.assertEqual(by_name["BUILD_KEY_HEX"].text,
                         b"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")

    def testRealRegistry_everyTextFitsDevBound(self):
        for lit in parse_literals(REGISTRY):
            self.assertLessEqual(len(lit.text), MAX_TEXT_LEN, lit.name)

    def testRealRegistry_allTextsAreAscii(self):
        for lit in parse_literals(REGISTRY):
            lit.text.decode("ascii")

    def testParse_duplicateName_raises(self):
        with tempfile.NamedTemporaryFile("w", suffix=".def", delete=False) as f:
            f.write('RASP_LITERAL(A, "x")\nRASP_LITERAL(A, "y")\n')
            path = f.name
        with self.assertRaises(ValueError):
            parse_literals(path)

    def testParse_emptyText_raises(self):
        with tempfile.NamedTemporaryFile("w", suffix=".def", delete=False) as f:
            f.write('RASP_LITERAL(A, "")\n')
            path = f.name
        with self.assertRaises(ValueError):
            parse_literals(path)

    def testParse_ignoresCommentsAndBlankLines(self):
        with tempfile.NamedTemporaryFile("w", suffix=".def", delete=False) as f:
            f.write('/* header */\n\nRASP_LITERAL(A, "x")  /* trailing */\n')
            path = f.name
        self.assertEqual(parse_literals(path), [Literal(name="A", raw="x", text=b"x")])

    def testParse_wrongShape_raises(self):
        with tempfile.NamedTemporaryFile("w", suffix=".def", delete=False) as f:
            f.write("RASP_LITERAL(A, 'x')\n")
            path = f.name
        with self.assertRaises(ValueError):
            parse_literals(path)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd hardener && python3 -m unittest tests.test_literals -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'rasp_hardener.literals'`.

- [ ] **Step 3: Write the registry**

Create `flutter_rasp/android/src/main/cpp/literals.def` with exactly these lines (order is the slot order; shared plaintexts use one entry at several call sites):

```c
/* Protected string literals (design §6 obfuscation). Entries are C string source text; escapes are
 * limited to \\ \" \n \t \r. Single source of truth for the dev build, the hardened table and the
 * source-scan gate. Order fixes each entry's slot index. */

/* --- detectors.c: search tokens and formats --- */
RASP_LITERAL(TRACER_LABEL, "TracerPid:")
RASP_LITERAL(FMT_TRACER, "TracerPid=%d")
RASP_LITERAL(FMT_COMM, "/proc/self/task/%s/comm")
RASP_LITERAL(FMT_WCHAN, "/proc/self/task/%s/wchan")

/* --- detectors.c: su binary paths --- */
RASP_LITERAL(SU_PATH_1, "/system/bin/su")
RASP_LITERAL(SU_PATH_2, "/system/xbin/su")
RASP_LITERAL(SU_PATH_3, "/sbin/su")
RASP_LITERAL(SU_PATH_4, "/su/bin/su")
RASP_LITERAL(SU_PATH_5, "/data/local/su")
RASP_LITERAL(SU_PATH_6, "/data/local/bin/su")
RASP_LITERAL(SU_PATH_7, "/data/local/xbin/su")
RASP_LITERAL(SU_PATH_8, "/system/sd/xbin/su")
RASP_LITERAL(SU_PATH_9, "/vendor/bin/su")
RASP_LITERAL(SU_PATH_10, "/system/app/Superuser.apk")

/* --- detectors.c: root manager dirs --- */
RASP_LITERAL(ROOT_DIR_1, "/data/adb/magisk")
RASP_LITERAL(ROOT_DIR_2, "/data/adb/ksu")
RASP_LITERAL(ROOT_DIR_3, "/data/adb/ap")
RASP_LITERAL(ROOT_DIR_4, "/debug_ramdisk/.magisk")

/* --- detectors.c: mount needles --- */
RASP_LITERAL(MNT_MAGISK, "magisk")
RASP_LITERAL(MNT_DATA_ADB, "/data/adb")
RASP_LITERAL(MNT_CORE_MIRROR, "core/mirror")
RASP_LITERAL(MNT_KSU, "KSU")
RASP_LITERAL(MNT_APATCH, "APatch")
RASP_LITERAL(NEEDLE_ZYGISK, "zygisk")

/* --- detectors.c: emulator device files --- */
RASP_LITERAL(EMU_PATH_1, "/dev/qemu_pipe")
RASP_LITERAL(EMU_PATH_2, "/dev/goldfish_pipe")
RASP_LITERAL(EMU_PATH_3, "/dev/socket/qemud")
RASP_LITERAL(EMU_PATH_4, "/system/bin/qemu-props")
RASP_LITERAL(EMU_PATH_5, "/sys/qemu_trace")
RASP_LITERAL(EMU_PATH_6, "/system/lib/libc_malloc_debug_qemu.so")
RASP_LITERAL(EMU_PATH_7, "/dev/goldfish_address_space")

/* --- detectors.c: hooking needles --- */
RASP_LITERAL(HOOK_FRIDA, "frida")
RASP_LITERAL(HOOK_GADGET, "gadget")
RASP_LITERAL(HOOK_LIBGUM, "libgum")
RASP_LITERAL(HOOK_XPOSED, "xposed")
RASP_LITERAL(HOOK_LSPOSED, "lsposed")
RASP_LITERAL(HOOK_SUBSTRATE, "substrate")
RASP_LITERAL(HOOK_LIBRIRU, "libriru")

/* --- detectors.c: Frida thread names --- */
RASP_LITERAL(THREAD_GUM, "gum-js-loop")
RASP_LITERAL(THREAD_GMAIN, "gmain")
RASP_LITERAL(THREAD_GDBUS, "gdbus")
RASP_LITERAL(THREAD_POOL, "pool-frida")

/* --- detectors.c: exec-mapping needles --- */
RASP_LITERAL(EXEC_TMP, "/data/local/tmp")
RASP_LITERAL(EXEC_MEMFD, "memfd:")
RASP_LITERAL(EXEC_DELETED, "(deleted)")

/* --- detectors.c: emulator build needles --- */
RASP_LITERAL(EMUW_GOLDFISH, "goldfish")
RASP_LITERAL(EMUW_RANCHU, "ranchu")
RASP_LITERAL(EMUW_GENY, "genymotion")
RASP_LITERAL(EMUW_VBOX86, "vbox86")
RASP_LITERAL(EMUW_VBOX, "virtualbox")

/* --- detectors.c: wchan needles --- */
RASP_LITERAL(WCH_KSU, "kernelsu")
RASP_LITERAL(WCH_KSUD, "ksud")
RASP_LITERAL(WCH_APATCH, "apatch")
RASP_LITERAL(WCH_APD, "apd_")

/* --- detectors.c: proc/sys paths --- */
RASP_LITERAL(PATH_MOUNTS, "/proc/self/mounts")
RASP_LITERAL(PATH_SELINUX, "/sys/fs/selinux/enforce")
RASP_LITERAL(PATH_STATUS, "/proc/self/status")
RASP_LITERAL(PATH_MAPS, "/proc/self/maps")
RASP_LITERAL(PATH_TASK, "/proc/self/task")
RASP_LITERAL(PATH_CPUINFO, "/proc/cpuinfo")
RASP_LITERAL(PATH_TTY, "/proc/tty/drivers")

/* --- detectors.c: detector ids --- */
RASP_LITERAL(SIG_SU_BIN, "native.su_binary")
RASP_LITERAL(SIG_ROOT_DIR, "native.root_manager_dir")
RASP_LITERAL(SIG_ROOT_MOUNTS, "native.root_mounts")
RASP_LITERAL(SIG_SELINUX, "native.selinux_permissive")
RASP_LITERAL(SIG_EMU_FILES, "native.emulator_files")
RASP_LITERAL(SIG_TRACER, "native.tracer_pid")
RASP_LITERAL(SIG_MAPS, "native.instrumentation_maps")
RASP_LITERAL(SIG_THREADS, "native.instrumentation_threads")
RASP_LITERAL(SIG_PORT, "native.instrumentation_port")
RASP_LITERAL(SIG_EXEC, "native.maps_exec_suspicious")
RASP_LITERAL(SIG_CPUINFO, "native.cpuinfo_emulator")
RASP_LITERAL(SIG_TTY, "native.ttydrivers_emulator")
RASP_LITERAL(SIG_WCHAN, "native.ksu_wchan")
RASP_LITERAL(SIG_PTRACE, "native.self_ptrace")

/* --- detectors.c: evidence strings --- */
RASP_LITERAL(EV_SELINUX, "enforce=0")
RASP_LITERAL(EV_PORT, "127.0.0.1:27042 open")
RASP_LITERAL(EV_CPUINFO, "cpuinfo hardware")
RASP_LITERAL(EV_TTY, "goldfish tty")
RASP_LITERAL(EV_PTRACE, "PTRACE_TRACEME denied")

/* --- signals.c: threat labels (rasp_threat_name) --- */
RASP_LITERAL(THREAT_ROOT, "root")
RASP_LITERAL(THREAT_EMU, "emulator")
RASP_LITERAL(THREAT_DBG, "debugger")
RASP_LITERAL(THREAT_HOOK, "hooking")
RASP_LITERAL(THREAT_UNKNOWN, "unknown")

/* --- signals.c / report.c: report JSON wire format --- */
RASP_LITERAL(FMT_SIGNAL_NUM, "{\"threat\":%d,\"confidence\":%d,")
RASP_LITERAL(JSON_SIG_FMT, "{\"threat\":\"%s\",\"confidence\":%d,\"detector\":\"")
RASP_LITERAL(JSON_HDR_FMT, "{\"v\":\"%s\",\"buildId\":\"")
RASP_LITERAL(JSON_NONCE, "\",\"nonce\":\"")
RASP_LITERAL(JSON_TS, "\",\"ts\":")
RASP_LITERAL(JSON_SIGNALS, ",\"signals\":[")
RASP_LITERAL(JSON_ENVELOPE, "{\"report\":\"")
RASP_LITERAL(JSON_MAC, "\",\"mac\":\"")
RASP_LITERAL(JSON_DET_KEY, "\"detector\":\"")
RASP_LITERAL(JSON_EV_KEY, "\",\"evidence\":\"")

/* --- rasp_jni.c: JNI registration literals --- */
RASP_LITERAL(JNI_CLASS, "dev/ostorlab/rasp/flutter_rasp/NativeDetectors")
RASP_LITERAL(JNI_M_SCAN, "nativeScan")
RASP_LITERAL(JNI_M_SEAL, "nativeSeal")
RASP_LITERAL(JNI_SIG_SCAN, "()Ljava/lang/String;")
RASP_LITERAL(JNI_SIG_SEAL, "(Ljava/lang/String;Ljava/lang/String;J)Ljava/lang/String;")

/* --- build key (design §8; gen-build replaces this value with the per-build key) --- */
RASP_LITERAL(BUILD_KEY_HEX, "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
```

- [ ] **Step 4: Write the parser**

Create `hardener/rasp_hardener/literals.py`:

```python
"""The protected-literal registry (``literals.def``) and its parser (design §6 obfuscation).

``literals.def`` is the single source of truth for every string literal the hardened binary must not
contain: detector ids, report JSON keys, file paths, match needles, evidence strings, the JNI
registration literals and the build key. Each entry is ``RASP_LITERAL(NAME, "C source text")``; the
text is C string source, and escapes are limited to ``\\\\ \\" \\n \\t \\r`` so the Python decode below
and the C compiler cannot disagree.

Consumers: :mod:`rasp_hardener.emit` (encrypted table in ``build_seed.h``), the X-macro passes in the
C ``literals.h`` / ``literals.c`` (slot enum and dev table), and the source-scan gate
(``tests.test_source_scan``). Entry order fixes each slot's index and therefore its key stream.
"""

from __future__ import annotations

import pathlib
import re
from dataclasses import dataclass

# Scratch-buffer bound for rasp_lit_decode (RASP_LIT_MAXLEN). A test asserts every entry fits.
MAX_TEXT_LEN = 256

_ENTRY_RE = re.compile(r'^RASP_LITERAL\(\s*([A-Z][A-Z0-9_]*)\s*,\s*"((?:[^"\\]|\\.)*)"\s*\)$')

_ESCAPES = {"\\": 0x5C, '"': 0x22, "n": 0x0A, "t": 0x09, "r": 0x0D}


@dataclass(frozen=True)
class Literal:
    name: str    # C identifier suffix: slot RASP_SLOT_<NAME>, macro RASP_STR_<NAME>
    raw: str     # C string source text between the quotes
    text: bytes  # decoded plaintext as it must appear in memory and on the wire


def unescape_c(raw: str) -> bytes:
    """Decode C string source text to bytes. Only ``\\\\ \\" \\n \\t \\r`` escapes are allowed."""
    out = bytearray()
    i = 0
    while i < len(raw):
        ch = raw[i]
        if ch == "\\":
            i += 1
            if i >= len(raw):
                raise ValueError("trailing backslash in literal")
            esc = raw[i]
            if esc not in _ESCAPES:
                raise ValueError(f"unsupported escape \\{esc} (allowed: \\\\ \\\" \\n \\t \\r)")
            out.append(_ESCAPES[esc])
        else:
            out.extend(ch.encode("utf-8"))
        i += 1
    return bytes(out)


def parse_literals(path: str | pathlib.Path) -> list[Literal]:
    """Parse ``literals.def`` in order. Raises ValueError on duplicate names, empty or oversized text."""
    out: list[Literal] = []
    seen: set[str] = set()
    for lineno, line in enumerate(pathlib.Path(path).read_text().splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("/*") or line.startswith("*"):
            continue
        m = _ENTRY_RE.match(line)
        if m is None:
            raise ValueError(f"{path}:{lineno}: not a RASP_LITERAL(NAME, \"text\") entry: {line}")
        name, raw = m.group(1), m.group(2)
        if name in seen:
            raise ValueError(f"{path}:{lineno}: duplicate literal name {name}")
        text = unescape_c(raw)
        if not text:
            raise ValueError(f"{path}:{lineno}: empty literal {name}")
        if len(text) > MAX_TEXT_LEN:
            raise ValueError(f"{path}:{lineno}: {name} is {len(text)} bytes, bound is {MAX_TEXT_LEN}")
        seen.add(name)
        out.append(Literal(name=name, raw=raw, text=text))
    return out


def literals_by_name(lits: list[Literal]) -> dict[str, Literal]:
    return {lit.name: lit for lit in lits}


def with_build_key(lits: list[Literal], build_key_hex: str) -> list[Literal]:
    """Replace BUILD_KEY_HEX's value with the per-build key (gen-build); the dev default is only a default."""
    key = build_key_hex.encode("ascii")
    if len(key) != 64 or any(c not in "0123456789abcdef" for c in build_key_hex):
        raise ValueError("build key must be 64 lowercase hex chars")
    return [Literal(name="BUILD_KEY_HEX", raw=build_key_hex, text=key) if lit.name == "BUILD_KEY_HEX" else lit
            for lit in lits]
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd hardener && python3 -m unittest tests.test_literals -v`
Expected: all PASS.

- [ ] **Step 6: Commit**

```bash
git add flutter_rasp/android/src/main/cpp/literals.def hardener/rasp_hardener/literals.py hardener/tests/test_literals.py
git commit -m "feat: protected-literal registry and parser (design §6 obfuscation)"
```

---

## Task 3: Registry-driven encrypted table in build_seed.h

**Files:**
- Modify: `hardener/rasp_hardener/strenc.py:33-38` (`obfuscate`), `:54-59` (`encrypt_table`)
- Modify: `hardener/rasp_hardener/emit.py` (`DEFAULT_STRINGS` removed, `render_build_seed_h`, `emit_headers`)
- Modify: `hardener/rasp_hardener/cli.py` (pass the registry through)
- Test: `hardener/tests/test_emit_native.py` (rewrite), `hardener/tests/test_cli.py` (adjust if it references `DEFAULT_STRINGS`)

- [ ] **Step 1: Write the failing tests**

Replace the harness body of `hardener/tests/test_emit_native.py`. The file keeps its docstring and imports but now round-trips **every** registry entry and checks the header hides plaintext:

```python
import os
import pathlib
import shutil
import subprocess
import tempfile
import unittest

from rasp_hardener import emit, guardmesh, strenc
from rasp_hardener.literals import parse_literals, with_build_key
from rasp_hardener.seed import SEED_LEN, BuildProfile

CPP = pathlib.Path(__file__).resolve().parents[2] / "flutter_rasp" / "android" / "src" / "main" / "cpp"

HARNESS = r"""
#include <stdio.h>
#include "literals.h"

int main(void) {
    for (int slot = 0; slot < RASP_SLOT_COUNT; slot++) {
        char buf[RASP_LIT_MAXLEN + 1];
        rasp_lit_decode(slot, buf);
        printf("%s\n", buf);
    }
    return 0;
}
"""

GUARD_HARNESS = r"""
#include <stdio.h>
#include "guard.h"
#include "sha256.h"

int main(void) {
    rasp_region_t regions[2] = {{0, 16}, {32, 8}};
    uint8_t root[RASP_SHA256_DIGEST_LEN];
    rasp_guard_root(regions, 2, root);
    for (int i = 0; i < RASP_SHA256_DIGEST_LEN; i++) printf("%02x", root[i]);
    printf("\n");
    return 0;
}
"""


class EmitNativeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if shutil.which("cc") is None and shutil.which("gcc") is None:
            raise unittest.SkipTest("no C compiler")
        cls.tmp = tempfile.mkdtemp()
        cls.profile = BuildProfile.from_seed(bytes(range(SEED_LEN)))
        cls.lits = with_build_key(parse_literals(CPP / "literals.def"), cls.profile.build_key_hex)
        written = emit.emit_headers(cls.profile, cls.tmp, cls.lits)
        for path in written:
            assert path.exists()
        if not (CPP / "strobf.c").exists():
            raise unittest.SkipTest("native sources unavailable")

    def _run(self, harness_c: str, sources: list[str]) -> str:
        cc = os.environ.get("CC") or ("gcc" if shutil.which("gcc") else "cc")
        harness = pathlib.Path(self.tmp) / "harness.c"
        harness.write_text(harness_c)
        out = pathlib.Path(self.tmp) / "harness_bin"
        subprocess.run(
            [cc, "-Wall", "-Wextra", "-Werror", "-I", self.tmp, "-I", str(CPP), str(harness)]
            + [str(CPP / s) for s in sources] + ["-o", str(out)],
            check=True,
        )
        return subprocess.run([str(out)], check=True, capture_output=True, text=True).stdout

    def testEveryRegistryEntry_decryptsOnTheCside(self):
        lines = self._run(HARNESS, ["strobf.c", "literals.c"]).splitlines()
        self.assertEqual(len(lines), len(self.lits))
        for line, lit in zip(lines, self.lits):
            self.assertEqual(line, lit.text.decode("ascii"), lit.name)

    def testGeneratedHeader_containsNoPlaintext(self):
        header = (pathlib.Path(self.tmp) / "build_seed.h").read_bytes()
        for lit in self.lits:
            if len(lit.text) >= 4:
                self.assertNotIn(lit.text, header, lit.name)
        self.assertNotIn(b"native.", header)

    def testPythonDecoder_stillAgreesWithC(self):
        for idx, lit in enumerate(self.lits):
            cipher = strenc.obfuscate(lit.text, self.profile.string_key, idx)
            self.assertEqual(strenc.deobfuscate(cipher, self.profile.string_key, idx), lit.text)

    def testGuardRoot_cMatchesPython(self):
        out = self._run(GUARD_HARNESS, ["sha256.c", "guard.c"]).strip()
        expected = guardmesh.guard_root([(0, 16), (32, 8)])
        self.assertEqual(out, expected)
```

Also in `hardener/tests/test_cli.py`, any import or use of `emit.DEFAULT_STRINGS` is replaced with the registry:

```python
from rasp_hardener.literals import parse_literals
LITERALS = parse_literals(pathlib.Path(__file__).resolve().parents[2] /
                          "flutter_rasp" / "android" / "src" / "main" / "cpp" / "literals.def")
```

and any call `emit.render_build_seed_h(profile, strings)` becomes `emit.render_build_seed_h(profile, LITERALS)`.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd hardener && python3 -m unittest tests.test_emit_native -v`
Expected: FAIL — `render_build_seed_h` still expects a `dict[str, str]`, and the generated header has no `r_lits` / `r_lit_lens` tables behind `RASP_LITERALS_IMPL` (the harness compile fails).

- [ ] **Step 3: Implement strenc bytes support**

In `hardener/rasp_hardener/strenc.py`, change `obfuscate`'s first lines:

```python
def obfuscate(plaintext: str | bytes, string_key: bytes, idx: int) -> bytes:
    """Encrypt one string for table slot `idx`. Returns the ciphertext bytes (no NUL terminator)."""
    if len(string_key) != KEY_LEN:
        raise ValueError(f"string_key must be {KEY_LEN} bytes")
    raw = plaintext if isinstance(plaintext, bytes) else plaintext.encode("utf-8")
    return bytes(b ^ _keybyte(string_key, idx, i) for i, b in enumerate(raw))
```

and `encrypt_table` accepts `dict[str, str | bytes]` unchanged in behavior (its type annotation becomes
`entries: dict[str, str | bytes]`).

- [ ] **Step 4: Implement the new emit**

In `hardener/rasp_hardener/emit.py`:

1. Delete `DEFAULT_STRINGS` and its comment. Add `from rasp_hardener.literals import Literal` to the module's
   imports (top-level only, matching the file's import style).
2. Replace `render_build_seed_h` entirely with:

```python
def render_build_seed_h(profile: BuildProfile, raw_literals: list[Literal]) -> str:
    """Render build_seed.h from the parsed literal registry (rasp_hardener.literals).

    The generated table is deliberately anonymous (``r_g<N>`` arrays behind ``RASP_STR_<NAME>`` macro
    aliases), so no registry name or plaintext reaches the binary's symbol tables. literals.c includes
    this header with RASP_LITERALS_IMPL defined, so the static tables live in exactly one TU.
    """
    table = strenc.encrypt_table({lit.name: lit.text for lit in raw_literals}, profile.string_key)

    lines = [
        _AUTOGEN,
        "#ifndef RASP_BUILD_SEED_H",
        "#define RASP_BUILD_SEED_H",
        "",
        "#include <stddef.h>",
        "#include <stdint.h>",
        "",
        "/* Per-build VM opcode assignments (design Subsystem 3: the ISA is permuted per build). */",
    ]
    for name in BASE_OPCODES:
        lines.append(f"#define RASP_OP_{name} 0x{profile.opcode_map[name]:02x}")
    lines += [
        "",
        "#ifdef RASP_LITERALS_IMPL",
        "/* Per-build key stream for rasp_strobf_decode (see strobf.c / strenc.py). */",
        f"static const uint8_t r_lkey[{strenc.KEY_LEN}] = {{ {_c_bytes(profile.string_key)} }};",
        "",
        "/* Encrypted string table: literals kept out of .rodata, decrypted on use. */",
    ]
    for idx, entry in enumerate(table):
        lines += [
            f"/* [{idx}] hidden */",
            f"static const uint8_t r_g{idx}[] = {{ {_c_bytes(entry.cipher)} }};",
        ]
    lines.append(f"static const uint8_t *const r_lits[{len(table)}] = {{")
    lines.append("    " + ", ".join(f"r_g{i}" for i in range(len(table))) + ",")
    lines.append("};")
    lines.append(f"static const unsigned short r_lit_lens[{len(table)}] = {{")
    lines.append("    " + ", ".join(str(len(e.cipher)) for e in table) + ",")
    lines.append("};")
    lines += ["#endif /* RASP_LITERALS_IMPL */", ""]
    for idx, entry in enumerate(table):
        ident = f"RASP_STR_{entry.name}"
        # The plaintext is deliberately not written into the header — that would defeat the encryption.
        # The r_g<N> alias only resolves where RASP_LITERALS_IMPL is set (literals.c), by design.
        lines += [
            f"#define {ident} r_g{idx}",
            f"#define {ident}_LEN {len(entry.cipher)}",
            f"#define {ident}_IDX {idx}",
        ]
    lines += ["", "#endif", ""]
    return "\n".join(lines)
```

3. Change `emit_headers` to `def emit_headers(profile, out_dir, raw_literals: list[Literal]) -> list[pathlib.Path]`
   and pass `raw_literals` through to `render_build_seed_h`. (The old `strings: dict[str, str] | None`
   parameter is gone.)

- [ ] **Step 5: Wire gen-build in cli.py**

In `hardener/rasp_hardener/cli.py`, add `from rasp_hardener.literals import parse_literals, with_build_key`
to the module's import block, then in `cmd_gen_build` replace the `emit_headers` call with:

```python
    lits = with_build_key(parse_literals(cpp_dir / "literals.def"), profile.build_key_hex)
    written = emit.emit_headers(profile, cpp_dir, lits)
```

The registry path is `cpp_dir / "literals.def"` — the CLI consumes the registry that lives next to the
sources it hardens.

Update `hardener/tests/test_cli.py::test_gen_build_emits_headers_and_manifest` for the new behavior (the
build key must NOT be in `build_generated.h` any more, and the temp cpp dir needs the registry). Replace
the setup and the `generated` assertions with:

```python
            cpp = d / "cpp"
            cpp.mkdir()
            real_cpp = (pathlib.Path(__file__).resolve().parents[2] / "flutter_rasp" / "android" /
                        "src" / "main" / "cpp")
            shutil.copy(real_cpp / "literals.def", cpp / "literals.def")
            shutil.copy(real_cpp / "symbols.def", cpp / "symbols.def")  # needed from Task 8 on
            (cpp / "report.c").write_text("int x;\n")  # something to hash
            manifest_path = d / "build_manifest.json"
            rc = cli.main(
                ["gen-build", "--seed", SEED_HEX, "--cpp-dir", str(cpp),
                 "--cert", "aa" * 32, "--manifest", str(manifest_path)]
            )
            self.assertEqual(rc, 0)
            self.assertTrue((cpp / "build_generated.h").exists())
            self.assertTrue((cpp / "build_seed.h").exists())

            profile = BuildProfile.derive(bytes.fromhex(SEED_HEX))
            generated = (cpp / "build_generated.h").read_text()
            self.assertIn(profile.build_id, generated)
            self.assertNotIn(profile.build_key_hex, generated)
```

(Task 7 extends this test with the `build_seed.h` key assertion.)

- [ ] **Step 6: Run tests to verify they pass**

Run: `cd hardener && python3 -m unittest tests.test_emit_native tests.test_cli tests.test_literals -v`
Expected: all PASS. Then the whole suite: `cd hardener && python3 -m unittest discover -s tests -t .` → `Ran 71+N tests ... OK` (existing tests stay green; `test_strenc` still passes since `str` input remains supported).

- [ ] **Step 7: Commit**

```bash
git add hardener/rasp_hardener/strenc.py hardener/rasp_hardener/emit.py hardener/rasp_hardener/cli.py hardener/tests/test_emit_native.py hardener/tests/test_cli.py
git commit -m "feat: registry-driven encrypted string table with anonymous symbols"
```

---

## Task 4: The C literal API (dev path) and hardening umbrella

**Files:**
- Create: `flutter_rasp/android/src/main/cpp/literals.h`, `literals.c`, `hardening.h`
- Modify: `flutter_rasp/android/src/main/cpp/CMakeLists.txt`
- Modify: `flutter_rasp/android/src/main/cpp/{detectors,signals,report,guard,integrity,sha256,strobf,wbaes,securestore}.h` (one line each)
- Modify: `flutter_rasp/android/src/main/cpp/rasp_jni.c` (JNI literals via `RASP_LIT`)
- Modify: build commands in `README.md:166-167` and `verifier/tests/test_native_seal.py`, `hardener/tests/test_emit_native.py` (link `literals.c`)

- [ ] **Step 1: Write the failing tests**

Append to `flutter_rasp/android/src/test/cpp/native_test.c` a test function `test_literal_decode` (the file
uses plain `assert()` from `<assert.h>` and one call per test in `main`):

```c
static void test_literal_decode(void) {
    char buf[RASP_LIT_MAXLEN + 1];
    rasp_lit_decode(RASP_SLOT_TRACER_LABEL, buf);
    assert(strcmp(buf, "TracerPid:") == 0);
    rasp_lit_decode(RASP_SLOT_SIG_SU_BIN, buf);
    assert(strcmp(buf, "native.su_binary") == 0);
    rasp_lit_decode(RASP_SLOT_JSON_EV_KEY, buf);
    assert(strcmp(buf, "\",\"evidence\":\"") == 0);
    rasp_lit_decode(RASP_SLOT_BUILD_KEY_HEX, buf);
    assert(strlen(buf) == 64);
}
```

Register it in `main` by adding `test_literal_decode();` after the `test_strobf_decode();` line.

- [ ] **Step 2: Run test to verify it fails**

Run the native host build (see conventions).
Expected: compile FAIL — `literals.h: No such file or directory` (via `signals.h` → `hardening.h` once added;
at this point simply `literals.h` unknown) or `rasp_lit_decode` undefined.

- [ ] **Step 3: Write literals.h**

Create `flutter_rasp/android/src/main/cpp/literals.h`:

```c
#ifndef RASP_LITERALS_H
#define RASP_LITERALS_H

/* Protected literals (design §6 obfuscation). literals.def is the single source of truth; in a dev build
 * it expands to plaintext, in a hardened build rasp_lit_decode decrypts the per-build table emitted in
 * build_seed.h (see hardener/rasp_hardener/literals.py and the RASP_LIT call sites). */

enum {
#define RASP_LITERAL(name, text) RASP_SLOT_##name,
#include "literals.def"
#undef RASP_LITERAL
    RASP_SLOT_COUNT
};

#ifndef RASP_LIT_MAXLEN
#define RASP_LIT_MAXLEN 256
#endif

/* Decodes slot into `out`, which must hold at least RASP_LIT_MAXLEN + 1 bytes; `out` is NUL-terminated. */
void rasp_lit_decode(int slot, char *out);

/* Declares `var` as a stack buffer holding literal `name`, decoded. Block scope only (two statements). */
#define RASP_LIT(name, var) \
    char var[RASP_LIT_MAXLEN + 1]; \
    rasp_lit_decode(RASP_SLOT_##name, var)

#endif
```

- [ ] **Step 4: Write literals.c**

Create `flutter_rasp/android/src/main/cpp/literals.c`:

```c
#define RASP_LITERALS_IMPL 1

#include "literals.h"

#include <string.h>

#include "strobf.h"

/* Hardened build: the encrypted table and key come from build_seed.h (included above with the impl macro
 * set, so the static tables live only in this translation unit). Dev build: the registry expands to a
 * plaintext table; dev binaries are not the artifact the gates protect. */
#if defined(__has_include)
#if __has_include("build_seed.h")
#include "build_seed.h"
#define RASP_LITERALS_HARDENED 1
#endif
#endif

#ifndef RASP_LITERALS_HARDENED
#define RASP_LITERAL(name, text) text,
static const char *const r_lits[RASP_SLOT_COUNT] = {
#include "literals.def"
};
#undef RASP_LITERAL
#endif

void rasp_lit_decode(int slot, char *out) {
#ifdef RASP_LITERALS_HARDENED
    rasp_strobf_decode(r_lits[slot], r_lit_lens[slot], slot, r_lkey, out);
#else
    strncpy(out, r_lits[slot], RASP_LIT_MAXLEN);
    out[RASP_LIT_MAXLEN] = '\0';
#endif
}
```

- [ ] **Step 5: Write hardening.h and wire it into every core header**

Create `flutter_rasp/android/src/main/cpp/hardening.h`:

```c
#ifndef RASP_HARDENING_H
#define RASP_HARDENING_H

/* Umbrella for build-time hardening; included first by every core header so all translation units see the
 * same macro renames and literal API (mismatched renames would fail to link). */
#include "literals.h"

#if defined(__has_include)
#if __has_include("build_names.h")
#include "build_names.h"
#endif
#endif

#endif
```

In each of `detectors.h`, `signals.h`, `report.h`, `guard.h`, `integrity.h`, `sha256.h`, `strobf.h`, `wbaes.h`,
`securestore.h`, insert `#include "hardening.h"` as the first include (after that file's own include guard).

- [ ] **Step 6: Migrate rasp_jni.c's JNI literals and update build wiring**

In `flutter_rasp/android/src/main/cpp/rasp_jni.c`, delete the whole `#if __has_include("build_seed.h") ...
#define RASP_HARDENED 1 #endif` block near the top (the string table now lives behind `rasp_lit_decode`, so
this file no longer includes `build_seed.h`/`strobf.h` directly) and delete the cleartext `#else` branch in
`JNI_OnLoad`. Keep the `integrity_regions.h` block exactly as it is. The registration block becomes:

```c
    RASP_LIT(JNI_CLASS, cls);
    RASP_LIT(JNI_M_SCAN, m_scan);
    RASP_LIT(JNI_SIG_SCAN, sig_scan);
    RASP_LIT(JNI_M_SEAL, m_seal);
    RASP_LIT(JNI_SIG_SEAL, sig_seal);
    JNINativeMethod methods[] = {
        {m_scan, sig_scan, (void *)native_scan},
        {m_seal, sig_seal, (void *)native_seal},
    };

    jclass clazz = (*env)->FindClass(env, cls);
```

Keep the `integrity_regions.h` block as is. (The build-key change comes in Task 7.)

`CMakeLists.txt`: add `literals.c` to `add_library(rasp_core SHARED ...)`.

Build-command updates (link `literals.c`):
- `README.md` native host gcc line: add `literals` to the brace list: `{detectors,signals,sha256,report,guard,strobf,literals}.c`.
- `verifier/tests/test_native_seal.py` and `hardener/tests/test_emit_native.py`: add `"literals.c"` to each
  `subprocess.run([cc, ...])` source list (the harnesses compile `report.c`/`strobf.c` which now reference
  `rasp_lit_decode` through `RASP_LIT` or, for `test_emit_native`, link it because the harness includes
  `build_seed.h` with `RASP_LITERALS_IMPL`-free code — linking `literals.c` is harmless and uniform).

- [ ] **Step 7: Run tests to verify they pass**

Run the native host build (conventions) → `native tests passed`.
Run: `cd hardener && python3 -m unittest discover -s tests -t .` → OK.
Run: `cd verifier && python3 -m unittest discover -s tests -t .` → OK.
Note: at this point `detectors.c`, `signals.c`, `report.c` still contain raw literals — that is expected
until Tasks 5–6; only compilation and behavior matter here.

- [ ] **Step 8: Commit**

```bash
git add flutter_rasp/android/src/main/cpp/ hardener/tests/test_emit_native.py verifier/tests/test_native_seal.py README.md
git commit -m "feat: literal decode API (RASP_LIT) with dev and hardened paths"
```

---

## Task 5: Migrate signals.c and report.c; rasp_threat_name fill-buffer

**Files:**
- Modify: `flutter_rasp/android/src/main/cpp/signals.c`, `signals.h`
- Modify: `flutter_rasp/android/src/main/cpp/report.c`
- Test: `flutter_rasp/android/src/test/cpp/native_test.c` (existing report tests must stay green; add one)

- [ ] **Step 1: Write the failing test**

Append to `native_test.c` (same style as Task 4):

```c
static void test_threat_name_fills_buffer(void) {
    char buf[RASP_LIT_MAXLEN + 1];
    rasp_threat_name(RASP_THREAT_ROOT, buf);
    assert(strcmp(buf, "root") == 0);
    rasp_threat_name(RASP_THREAT_EMULATOR, buf);
    assert(strcmp(buf, "emulator") == 0);
    rasp_threat_name((rasp_threat_t)99, buf);
    assert(strcmp(buf, "unknown") == 0);
}
```

Register it in `main` after the `test_signals_dedupe_and_json();` line.

- [ ] **Step 2: Run test to verify it fails**

Run the native host build. Expected: compile FAIL — `rasp_threat_name` takes 1 argument.

Also capture the red state for the literal migration (expected: matching lines, i.e. raw wire-format
literals still present):

```bash
grep -n 'threat\\":\|detector\\":\|evidence\\":\|signals\\":\|report\\":\|mac\\":\|buildId\\":\|nonce\\":\|ts\\":' \
  flutter_rasp/android/src/main/cpp/signals.c flutter_rasp/android/src/main/cpp/report.c
```

- [ ] **Step 3: Migrate signals.c / signals.h**

`signals.h` declaration becomes:

```c
/* Writes the threat's report label into `out` (at least RASP_LIT_MAXLEN + 1 bytes). */
void rasp_threat_name(rasp_threat_t threat, char *out);
```

`signals.c` `rasp_threat_name` becomes:

```c
void rasp_threat_name(rasp_threat_t threat, char *out) {
    switch (threat) {
        case RASP_THREAT_ROOT:
            rasp_lit_decode(RASP_SLOT_THREAT_ROOT, out);
            return;
        case RASP_THREAT_EMULATOR:
            rasp_lit_decode(RASP_SLOT_THREAT_EMU, out);
            return;
        case RASP_THREAT_DEBUGGER:
            rasp_lit_decode(RASP_SLOT_THREAT_DBG, out);
            return;
        case RASP_THREAT_HOOKING:
            rasp_lit_decode(RASP_SLOT_THREAT_HOOK, out);
            return;
    }
    rasp_lit_decode(RASP_SLOT_THREAT_UNKNOWN, out);
}
```

`signals.c` `rasp_signals_to_json`'s loop body becomes:

```c
    char number[96];
    RASP_LIT(FMT_SIGNAL_NUM, fmt);
    RASP_LIT(JSON_DET_KEY, det_key);
    RASP_LIT(JSON_EV_KEY, ev_key);
    if (append_raw(out, out_len, &pos, "[") < 0) {
        return -1;
    }
    for (size_t i = 0; i < list->count; i++) {
        const rasp_signal_t *signal = &list->items[i];
        snprintf(number, sizeof(number), fmt, signal->threat, signal->confidence);
        if ((i > 0 && append_raw(out, out_len, &pos, ",") < 0) ||
            append_raw(out, out_len, &pos, number) < 0 ||
            append_raw(out, out_len, &pos, det_key) < 0 ||
            append_escaped(out, out_len, &pos, signal->detector) < 0 ||
            append_raw(out, out_len, &pos, ev_key) < 0 ||
            append_escaped(out, out_len, &pos, signal->evidence) < 0 ||
            append_raw(out, out_len, &pos, "\"}") < 0) {
            return -1;
        }
    }
```

(Declare `number`, `fmt`, `det_key`, `ev_key` at the top of the function, before the first statement that
needs them, keeping C89-style declarations the file already follows. `append_escaped`'s `"\\%c"` and
`"\\u%04x"` format strings stay as literals — allowlisted in Task 9's source-scan gate.)

- [ ] **Step 4: Migrate report.c**

`append_signal` becomes:

```c
static int append_signal(char *out, size_t out_len, size_t *pos, const rasp_signal_t *s) {
    char number[96];
    char threat[RASP_LIT_MAXLEN + 1];
    RASP_LIT(JSON_SIG_FMT, fmt);
    RASP_LIT(JSON_EV_KEY, ev_key);
    rasp_threat_name(s->threat, threat);
    snprintf(number, sizeof(number), fmt, threat, s->confidence);
    return rasp_json_append_raw(out, out_len, pos, number) < 0 ||
                   rasp_json_append_escaped(out, out_len, pos, s->detector) < 0 ||
                   rasp_json_append_raw(out, out_len, pos, ev_key) < 0 ||
                   rasp_json_append_escaped(out, out_len, pos, s->evidence) < 0 ||
                   rasp_json_append_raw(out, out_len, pos, "\"}") < 0
               ? -1
               : 0;
}
```

In `rasp_seal_report`, replace the literal JSON fragments (keep `%lld` as-is):

| New code | Replaces |
| :--- | :--- |
| `RASP_LIT(JSON_HDR_FMT, hdr_fmt);` then `snprintf(header, sizeof(header), hdr_fmt, RASP_REPORT_VERSION);` | replaces `snprintf(header, sizeof(header), "{\"v\":\"%s\",\"buildId\":\"", RASP_REPORT_VERSION);` |
| `rasp_json_append_raw(report, sizeof(report), &pos, hdr_nonce)` where `RASP_LIT(JSON_NONCE, hdr_nonce);` | replaces the `"\",\"nonce\":\""` literal |
| `rasp_json_append_raw(report, sizeof(report), &pos, hdr_ts)` where `RASP_LIT(JSON_TS, hdr_ts);` | replaces the `"\",\"ts\":"` literal |
| `rasp_json_append_raw(report, sizeof(report), &pos, hdr_sig)` where `RASP_LIT(JSON_SIGNALS, hdr_sig);` | replaces `",\"signals\":["` |
| `rasp_json_append_raw(out, out_len, &out_pos, env)` where `RASP_LIT(JSON_ENVELOPE, env);` | replaces `"{\"report\":\""` |
| `rasp_json_append_raw(out, out_len, &out_pos, env_mac)` where `RASP_LIT(JSON_MAC, env_mac);` | replaces `"\",\"mac\":\""` |

- [ ] **Step 5: Run tests to verify they pass**

Run the native host build → `native tests passed` (report/seal tests assert byte-stable JSON, so they prove
the migration changed nothing on the wire).
Run: `cd verifier && python3 -m unittest discover -s tests -t .` → OK (`test_native_seal` compiles the
migrated sources against the Python verifier and byte-compares).
Run the Step 2 grep again → expected: **no output** (no raw wire-format literal left in `signals.c` or
`report.c`).

- [ ] **Step 6: Commit**

```bash
git add flutter_rasp/android/src/main/cpp/signals.c flutter_rasp/android/src/main/cpp/signals.h flutter_rasp/android/src/main/cpp/report.c flutter_rasp/android/src/test/cpp/native_test.c
git commit -m "feat: move report/threat JSON literals into the registry"
```

---

## Task 6: Migrate detectors.c

**Files:**
- Modify: `flutter_rasp/android/src/main/cpp/detectors.c`
- Test: existing `native_test.c` detector tests (must pass unchanged)

The migration rule per pattern:
- **`const char *` needles/paths arrays** → `static const int <name>_slots[] = {RASP_SLOT_..., ...};` plus a
  local decode loop into `char <name>[N][RASP_LIT_MAXLEN + 1]` and a `const char *` array of pointers, so
  `rasp_match_any`, `line_match_ctx_t`, `match_line` and `match_exec_suspicious` stay untouched.
- **single literals at use sites** → `RASP_LIT(NAME, var);` at the top of the block, `var` in place of the
  literal.
- **evidence strings** → `RASP_LIT(NAME, ev);` and pass `ev`.

- [ ] **Step 1: Capture the red state (failing check)**

The migration is a pure refactor — output bytes must not change — so the failing check is a source scan:
after this task it must find nothing, today it finds every literal. Run:

```bash
grep -n '"/\|"\|native\.\|"frida\|"goldfish\|"magisk\|"memfd\|TracerPid\|enforce=0\|PTRACE_TRACEME' \
  flutter_rasp/android/src/main/cpp/detectors.c | grep -v '^\s*\*'
```

Expected: many matching lines (the raw literals). Keep this command; Step 4 re-runs it and expects one
line at most (the `#include` header names, which the scanner exempts).

Add to `native_test.c` a behavior-preservation test (registers in `main` after `test_new_detector_helpers();`):

```c
static void test_detector_ids_are_registry_backed(void) {
    /* The su-binary detector's signal ids still come out of the registry-backed path unchanged. */
    rasp_signal_list_t list = {.count = 0};
    rasp_detect_su_binaries(&list); /* may add 0 or 1 signals on this host */
    for (size_t i = 0; i < list.count; i++) {
        assert(strcmp(list.items[i].detector, "native.su_binary") == 0 ||
               strcmp(list.items[i].detector, "native.root_manager_dir") == 0);
    }
}
```

- [ ] **Step 2: Run test to verify it passes before and fails to prove red elsewhere**

Run the native host build → `native tests passed` (the behavior test passes before the migration — it pins
behavior across the refactor). The red proof is the Step 1 grep; the green proof is Step 4.

- [ ] **Step 3: Apply the migrations (exact edits)**

1. `rasp_parse_tracer_pid`:

```c
int rasp_parse_tracer_pid(const char *status_text) {
    RASP_LIT(TRACER_LABEL, label);
    const char *line = strstr(status_text, label);
    if (line == NULL) {
        return -1;
    }
    return atoi(line + strlen(label));
}
```

2. `rasp_detect_su_binaries`:

```c
void rasp_detect_su_binaries(rasp_signal_list_t *list) {
    static const int paths[] = {
        RASP_SLOT_SU_PATH_1,  RASP_SLOT_SU_PATH_2,  RASP_SLOT_SU_PATH_3, RASP_SLOT_SU_PATH_4,
        RASP_SLOT_SU_PATH_5,  RASP_SLOT_SU_PATH_6,  RASP_SLOT_SU_PATH_7, RASP_SLOT_SU_PATH_8,
        RASP_SLOT_SU_PATH_9,  RASP_SLOT_SU_PATH_10,
    };
    static const int root_dirs[] = {
        RASP_SLOT_ROOT_DIR_1, RASP_SLOT_ROOT_DIR_2, RASP_SLOT_ROOT_DIR_3, RASP_SLOT_ROOT_DIR_4,
    };
    char path[RASP_LIT_MAXLEN + 1];
    for (size_t i = 0; i < ARRAY_LEN(paths); i++) {
        rasp_lit_decode(paths[i], path);
        if (access(path, F_OK) == 0) {
            RASP_LIT(SIG_SU_BIN, sig);
            rasp_signals_add(list, RASP_THREAT_ROOT, sig, 90, path);
            break;
        }
    }
    for (size_t i = 0; i < ARRAY_LEN(root_dirs); i++) {
        rasp_lit_decode(root_dirs[i], path);
        if (access(path, F_OK) == 0) {
            RASP_LIT(SIG_ROOT_DIR, sig);
            rasp_signals_add(list, RASP_THREAT_ROOT, sig, 90, path);
            break;
        }
    }
}
```

3. `rasp_detect_root_mounts` (and every other `line_match_ctx_t` detector) — replace the needle array with
   decoded locals:

```c
void rasp_detect_root_mounts(rasp_signal_list_t *list) {
    static const int needle_slots[] = {
        RASP_SLOT_MNT_MAGISK, RASP_SLOT_MNT_DATA_ADB, RASP_SLOT_MNT_CORE_MIRROR,
        RASP_SLOT_MNT_KSU, RASP_SLOT_MNT_APATCH, RASP_SLOT_NEEDLE_ZYGISK,
    };
    char needle_buf[ARRAY_LEN(needle_slots)][RASP_LIT_MAXLEN + 1];
    const char *needles[ARRAY_LEN(needle_slots)];
    for (size_t i = 0; i < ARRAY_LEN(needle_slots); i++) {
        rasp_lit_decode(needle_slots[i], needle_buf[i]);
        needles[i] = needle_buf[i];
    }
    RASP_LIT(PATH_MOUNTS, mounts_path);
    RASP_LIT(SIG_ROOT_MOUNTS, sig);
    line_match_ctx_t ctx = {list, RASP_THREAT_ROOT, sig, 80, needles, ARRAY_LEN(needles)};
    for_each_line(mounts_path, match_line, &ctx);
}
```

4. `rasp_detect_selinux_permissive`:

```c
void rasp_detect_selinux_permissive(rasp_signal_list_t *list) {
    char buf[16];
    RASP_LIT(PATH_SELINUX, selinux_path);
    if (read_text_file(selinux_path, buf, sizeof(buf)) > 0 && buf[0] == '0') {
        RASP_LIT(SIG_SELINUX, sig);
        RASP_LIT(EV_SELINUX, ev);
        rasp_signals_add(list, RASP_THREAT_ROOT, sig, 60, ev);
    }
}
```

5. `rasp_detect_emulator_files`: same pattern as (2)/(3): `paths` → `static const int` slot array
   (`RASP_SLOT_EMU_PATH_1` … `RASP_SLOT_EMU_PATH_7`), decode into `char path[RASP_LIT_MAXLEN + 1]`, and
   `RASP_LIT(SIG_EMU_FILES, sig);` at the `rasp_signals_add` site.

6. `rasp_detect_tracer`:

```c
    ...
    char status[1024];
    RASP_LIT(PATH_STATUS, status_path);
    if (read_text_file(status_path, status, sizeof(status)) <= 0) {
        return;
    }
    int tracer = rasp_parse_tracer_pid(status);
    if (tracer > 0) {
        char evidence[RASP_EVIDENCE_LEN];
        RASP_LIT(FMT_TRACER, fmt);
        snprintf(evidence, sizeof(evidence), fmt, tracer);
        RASP_LIT(SIG_TRACER, sig);
        rasp_signals_add(list, RASP_THREAT_DEBUGGER, sig, 95, evidence);
    }
```

7. `rasp_detect_instrumentation_maps`: needles `{RASP_SLOT_HOOK_FRIDA, RASP_SLOT_HOOK_GADGET,
   RASP_SLOT_HOOK_LIBGUM, RASP_SLOT_HOOK_XPOSED, RASP_SLOT_HOOK_LSPOSED, RASP_SLOT_HOOK_SUBSTRATE,
   RASP_SLOT_HOOK_LIBRIRU, RASP_SLOT_NEEDLE_ZYGISK}` with the decode loop from (3); `RASP_LIT(PATH_MAPS,
   maps_path); RASP_LIT(SIG_MAPS, sig);`.

8. `rasp_detect_instrumentation_threads`: needles `{RASP_SLOT_THREAD_GUM, RASP_SLOT_THREAD_GMAIN,
   RASP_SLOT_THREAD_GDBUS, RASP_SLOT_THREAD_POOL}` decoded as in (3); `RASP_LIT(PATH_TASK, task_dir);
   RASP_LIT(FMT_COMM, fmt); RASP_LIT(SIG_THREADS, sig);` — `snprintf(path, sizeof(path), fmt, entry->d_name);`
   and `opendir(task_dir)`.

9. `rasp_detect_instrumentation_port`: `RASP_LIT(SIG_PORT, sig); RASP_LIT(EV_PORT, ev);` at the
   `rasp_signals_add` site.

10. `rasp_detect_maps_exec_suspicious`: needles `{RASP_SLOT_EXEC_TMP, RASP_SLOT_EXEC_MEMFD,
    RASP_SLOT_EXEC_DELETED}` decoded as in (3); `RASP_LIT(PATH_MAPS, maps_path); RASP_LIT(SIG_EXEC, sig);`.

11. `rasp_cpuinfo_is_emulator`: needles `{RASP_SLOT_EMUW_GOLDFISH, RASP_SLOT_EMUW_RANCHU, RASP_SLOT_EMUW_GENY,
    RASP_SLOT_EMUW_VBOX86, RASP_SLOT_EMUW_VBOX}` decoded as in (3) (keep `ci_contains`).

12. `rasp_detect_cpuinfo_emulator`: `RASP_LIT(PATH_CPUINFO, cpuinfo_path); RASP_LIT(SIG_CPUINFO, sig);
    RASP_LIT(EV_CPUINFO, ev);`.

13. `rasp_ttydrivers_is_emulator`: `RASP_LIT(EMUW_GOLDFISH, goldfish); return ci_contains(drivers, goldfish);`

14. `rasp_detect_ttydrivers_emulator`: `RASP_LIT(PATH_TTY, tty_path); RASP_LIT(SIG_TTY, sig); RASP_LIT(EV_TTY, ev);`

15. `rasp_wchan_is_suspicious`: needles `{RASP_SLOT_WCH_KSU, RASP_SLOT_WCH_KSUD, RASP_SLOT_WCH_APATCH,
    RASP_SLOT_WCH_APD}` decoded as in (3) (the old `"su"` needle is gone in current source; use exactly the
    four needles the function has today).

16. `rasp_detect_ksu_wchan`: `RASP_LIT(PATH_TASK, task_dir); RASP_LIT(FMT_WCHAN, fmt); RASP_LIT(SIG_WCHAN, sig);` —
    `opendir(task_dir)`, `snprintf(path, sizeof(path), fmt, entry->d_name);`.

17. `rasp_detect_self_ptrace`: `RASP_LIT(SIG_PTRACE, sig); RASP_LIT(EV_PTRACE, ev);` at the
    `rasp_signals_add` site.

- [ ] **Step 4: Run tests to verify they pass**

Run the native host build → `native tests passed` (all parser/detector tests byte-stable).
Run: `cd verifier && python3 -m unittest discover -s tests -t .` → OK.
Re-run the Step 1 grep → expected: no matches beyond `#include` lines (no raw sensitive literal left in
`detectors.c`).

- [ ] **Step 5: Commit**

```bash
git add flutter_rasp/android/src/main/cpp/detectors.c flutter_rasp/android/src/test/cpp/native_test.c
git commit -m "feat: migrate every detectors.c literal to the registry"
```

---

## Task 7: Close the two leaks (build key, detector order)

**Files:**
- Modify: `flutter_rasp/android/src/main/cpp/build_config.h`
- Modify: `flutter_rasp/android/src/main/cpp/rasp_jni.c:79-90`
- Modify: `hardener/rasp_hardener/emit.py` (`render_build_generated_h`, drop `RASP_DETECTOR_ORDER`)
- Test: `hardener/tests/test_literals.py` (add `with_build_key` tests), `hardener/tests/test_emit_native.py` (add assertions)

- [ ] **Step 1: Write the failing tests**

In `hardener/tests/test_literals.py` add (extend the module import to include `with_build_key`):
```python
from rasp_hardener.literals import (
    MAX_TEXT_LEN,
    Literal,
    literals_by_name,
    parse_literals,
    unescape_c,
    with_build_key,
)
```

```python
class WithBuildKeyTest(unittest.TestCase):
    def testOverride_replacesOnlyBuildKey(self):
        lits = parse_literals(REGISTRY)
        key = "ab" * 32
        out = with_build_key(lits, key)
        by_name = literals_by_name(out)
        self.assertEqual(by_name["BUILD_KEY_HEX"].text, key.encode("ascii"))
        others = [a for a, b in zip(lits, out) if a.name != "BUILD_KEY_HEX"]
        self.assertEqual(len(others), len(lits) - 1)

    def testBadKey_raises(self):
        lits = parse_literals(REGISTRY)
        for bad in ("zz" * 32, "ab" * 31, "AB" * 32, ""):
            with self.assertRaises(ValueError):
                with_build_key(lits, bad)
```

In `hardener/tests/test_emit_native.py` add:

```python
    def testGeneratedHeader_hidesBuildKeyAndDetectorOrder(self):
        header = (pathlib.Path(self.tmp) / "build_seed.h").read_text()
        self.assertNotIn(self.profile.build_key_hex, header)
        self.assertNotIn("RASP_DETECTOR_ORDER", header)

    def testBuildGeneratedH_hasBuildIdOnly(self):
        text = (pathlib.Path(self.tmp) / "build_generated.h").read_text()
        self.assertIn(self.profile.build_id, text)
        self.assertNotIn("RASP_BUILD_KEY_HEX", text)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd hardener && python3 -m unittest tests.test_literals tests.test_emit_native -v`
Expected: FAIL — `build_key_hex` appears in `build_seed.h` (as `BUILD_KEY_HEX` plaintext until Task 3's
`with_build_key` is wired; if already wired, the failure is `RASP_BUILD_KEY_HEX` still in `build_generated.h`
and `RASP_DETECTOR_ORDER` still in `build_seed.h`).

- [ ] **Step 3: Implement**

1. `emit.render_build_generated_h`: delete the `#define RASP_BUILD_KEY_HEX ...` line (keep `RASP_BUILD_ID`).
2. `emit.render_build_seed_h`: delete the `RASP_DETECTOR_COUNT` / `RASP_DETECTOR_ORDER[]` block entirely (the
   permutation is recorded in the build manifest; no C consumer exists).
3. `build_config.h`: delete the `#ifndef RASP_BUILD_KEY_HEX ... #endif` block and update the header comment:
   the build key now lives in the literal registry (`BUILD_KEY_HEX`, replaced per-build by `gen-build`).
4. `rasp_jni.c`, around line 79-90: replace

```c
    if (hex_to_bytes(RASP_BUILD_KEY_HEX, build_key, sizeof(build_key)) != 0) {
```

with

```c
    RASP_LIT(BUILD_KEY_HEX, build_key_hex);
    if (hex_to_bytes(build_key_hex, build_key, sizeof(build_key)) != 0) {
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd hardener && python3 -m unittest discover -s tests -t .` → OK.
Run the native host build and the verifier suite → OK.
Run: `cd hardener && python3 -m unittest tests.test_emit_native.EmitNativeTest.testGeneratedHeader_containsNoPlaintext -v` → PASS (the key ciphertext is not the key plaintext).

- [ ] **Step 5: Commit**

```bash
git add flutter_rasp/android/src/main/cpp/build_config.h flutter_rasp/android/src/main/cpp/rasp_jni.c hardener/rasp_hardener/emit.py hardener/tests/test_literals.py hardener/tests/test_emit_native.py
git commit -m "fix: keep the build key and detector order out of cleartext headers (§6, §8)"
```

---

## Task 8: Per-build symbol renaming (names.py, build_names.h, symbols.map)

**Files:**
- Create: `flutter_rasp/android/src/main/cpp/symbols.def`
- Create: `hardener/rasp_hardener/names.py`
- Modify: `hardener/rasp_hardener/emit.py` (add `render_build_names_h`, `render_symbols_map`)
- Modify: `hardener/rasp_hardener/cli.py` (emit `build_names.h` + `symbols.map` in `gen-build`)
- Modify: `hardener/tests/test_cli.py` (assert the new artifacts)
- Test: `hardener/tests/test_names.py`

- [ ] **Step 1: Write the failing tests**

Create `hardener/tests/test_names.py`:

```python
"""Tests for per-build symbol renaming (rasp_hardener.names)."""

import pathlib
import unittest

from rasp_hardener import names
from rasp_hardener.emit import render_build_names_h
from rasp_hardener.seed import SEED_LEN, BuildProfile

CPP = pathlib.Path(__file__).resolve().parents[2] / "flutter_rasp" / "android" / "src" / "main" / "cpp"


class PseudonymTest(unittest.TestCase):
    def testDeterministic_perKey(self):
        key = b"\x01" * 32
        self.assertEqual(names.pseudonym("rasp_seal_report", key), names.pseudonym("rasp_seal_report", key))

    def testDistinctPerNameAndKey(self):
        key = b"\x01" * 32
        self.assertNotEqual(names.pseudonym("rasp_seal_report", key), names.pseudonym("rasp_sha256", key))
        self.assertNotEqual(names.pseudonym("rasp_seal_report", key), names.pseudonym("rasp_seal_report", b"\x02" * 32))

    def testValidCIdentifier_rPrefix(self):
        p = names.pseudonym("rasp_seal_report", b"\x01" * 32)
        self.assertRegex(p, r"^r[0-9a-f]{8}$")

    def testCollision_raises(self):
        def fake(name, key):
            return "r00000000"
        with self.assertRaises(ValueError):
            names.rename_map(["a", "b"], b"\x01" * 32, derive=fake)


class SymbolsDefTest(unittest.TestCase):
    def testSymbolsDef_parsesUniqueNames(self):
        syms = names.parse_symbols(CPP / "symbols.def")
        self.assertGreater(len(syms), 50)
        self.assertEqual(len(syms), len(set(syms)))
        self.assertIn("rasp_seal_report", syms)
        self.assertIn("rasp_lit_decode", syms)
        self.assertNotIn("JNI_OnLoad", syms)

    def testSymbolsDef_coversEveryHeaderFunction(self):
        import re
        syms = set(names.parse_symbols(CPP / "symbols.def"))
        for header in CPP.glob("*.h"):
            if header.name in ("hardening.h", "literals.h", "build_config.h"):
                continue
            for m in re.finditer(r"\b(rasp_[a-z0-9_]+)\s*\(", header.read_text()):
                self.assertIn(m.group(1), syms, f"{header.name}: {m.group(1)}")


class RenameMapTest(unittest.TestCase):
    def testRenderBuildNamesH_definesEverySymbol(self):
        profile = BuildProfile.from_seed(bytes(range(SEED_LEN)))
        syms = names.parse_symbols(CPP / "symbols.def")
        text = render_build_names_h(profile, syms)
        for sym in syms:
            self.assertIn(f"#define {sym} ", text)
        self.assertIn("#ifndef RASP_BUILD_NAMES_H", text)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd hardener && python3 -m unittest tests.test_names -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'rasp_hardener.names'`.

- [ ] **Step 3: Write symbols.def**

Create `flutter_rasp/android/src/main/cpp/symbols.def`:

```c
/* Every internal symbol the hardened build renames (design §6). JNI_OnLoad/JNI_OnUnload stay: the VM finds
 * them by name. X-macro list consumed by hardener/rasp_hardener/names.py; a test proves it covers every
 * function declared in the core headers. */

/* detectors.c */
RASP_SYMBOL(rasp_detect_su_binaries)
RASP_SYMBOL(rasp_detect_root_mounts)
RASP_SYMBOL(rasp_detect_selinux_permissive)
RASP_SYMBOL(rasp_detect_emulator_files)
RASP_SYMBOL(rasp_detect_tracer)
RASP_SYMBOL(rasp_detect_instrumentation_maps)
RASP_SYMBOL(rasp_detect_instrumentation_threads)
RASP_SYMBOL(rasp_detect_instrumentation_port)
RASP_SYMBOL(rasp_detect_maps_exec_suspicious)
RASP_SYMBOL(rasp_detect_cpuinfo_emulator)
RASP_SYMBOL(rasp_detect_ttydrivers_emulator)
RASP_SYMBOL(rasp_detect_ksu_wchan)
RASP_SYMBOL(rasp_detect_self_ptrace)
RASP_SYMBOL(rasp_run_all)
RASP_SYMBOL(rasp_parse_tracer_pid)
RASP_SYMBOL(rasp_match_any)
RASP_SYMBOL(rasp_cpuinfo_is_emulator)
RASP_SYMBOL(rasp_ttydrivers_is_emulator)
RASP_SYMBOL(rasp_wchan_is_suspicious)
RASP_SYMBOL(rasp_selfptrace_is_debugged)
RASP_SYMBOL(read_text_file)
RASP_SYMBOL(for_each_line)
RASP_SYMBOL(match_line)
RASP_SYMBOL(match_exec_suspicious)
RASP_SYMBOL(ci_contains)

/* guard.c / integrity.c */
RASP_SYMBOL(rasp_guard_root)
RASP_SYMBOL(rasp_guard_offset)
RASP_SYMBOL(rasp_guard_fold_key)
RASP_SYMBOL(rasp_integrity_root_from_file)
RASP_SYMBOL(hash_region)
RASP_SYMBOL(MESH_SEED)

/* report.c */
RASP_SYMBOL(rasp_seal_report)
RASP_SYMBOL(rasp_signals_to_report_json)
RASP_SYMBOL(rasp_json_array_inner)
RASP_SYMBOL(append_signal)

/* signals.c */
RASP_SYMBOL(rasp_signals_add)
RASP_SYMBOL(rasp_signals_to_json)
RASP_SYMBOL(rasp_threat_name)
RASP_SYMBOL(rasp_json_append_raw)
RASP_SYMBOL(rasp_json_append_escaped)
RASP_SYMBOL(append_raw)
RASP_SYMBOL(append_escaped)

/* sha256.c */
RASP_SYMBOL(rasp_sha256_init)
RASP_SYMBOL(rasp_sha256_update)
RASP_SYMBOL(rasp_sha256_final)
RASP_SYMBOL(rasp_sha256)
RASP_SYMBOL(rasp_hmac_sha256)
RASP_SYMBOL(rasp_hex_encode)

/* strobf.c / literals.c */
RASP_SYMBOL(rasp_strobf_decode)
RASP_SYMBOL(rasp_lit_decode)

/* wbaes.c / securestore.c */
RASP_SYMBOL(rasp_wbaes_encrypt_block)
RASP_SYMBOL(rasp_wbaes_ctr)
RASP_SYMBOL(rasp_wbaes_cmac)
RASP_SYMBOL(rasp_secure_store_seal)
RASP_SYMBOL(rasp_secure_store_open)
RASP_SYMBOL(wbaes_shl1)
RASP_SYMBOL(wbaes_xor16)
RASP_SYMBOL(ct_equal)

/* rasp_jni.c (statics) */
RASP_SYMBOL(native_scan)
RASP_SYMBOL(native_seal)
RASP_SYMBOL(hex_to_bytes)
```

- [ ] **Step 4: Write names.py**

Create `hardener/rasp_hardener/names.py`:

```python
"""Per-build symbol renaming (design §6 name obfuscation).

Symbols keep their readable names in the repo and in dev builds; ``gen-build`` derives a pseudonym per
symbol from the build seed and emits ``build_names.h`` (``#define rasp_seal_report r7f3a91c``), so every
build's symbols differ and name-keyed bypass scripts rot. The mapping is written to ``symbols.map`` for
crash mapping and must be treated as a build artifact, never published with the app.
"""

from __future__ import annotations

import hashlib
import hmac
import pathlib
import re

NAME_DOMAIN = b"raxp/names/v1"
_SYMBOL_RE = re.compile(r"^RASP_SYMBOL\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)$")


def parse_symbols(path: str | pathlib.Path) -> list[str]:
    """Parse symbols.def into ordered symbol names."""
    out: list[str] = []
    for lineno, line in enumerate(pathlib.Path(path).read_text().splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("/*") or line.startswith("*"):
            continue
        m = _SYMBOL_RE.match(line)
        if m is None:
            raise ValueError(f"{path}:{lineno}: not a RASP_SYMBOL(name) entry: {line}")
        out.append(m.group(1))
    return out


def pseudonym(symbol: str, string_key: bytes) -> str:
    """Seed-derived pseudonym: 'r' + 8 hex chars (valid C identifier, no libc collision)."""
    digest = hmac.new(string_key, NAME_DOMAIN + b"\x00" + symbol.encode("ascii"), hashlib.sha256)
    return "r" + digest.hexdigest()[:8]


def rename_map(symbols: list[str], string_key: bytes, derive=pseudonym) -> dict[str, str]:
    """{symbol: pseudonym}; raises ValueError on pseudonym collision."""
    out: dict[str, str] = {}
    seen: set[str] = set()
    for sym in symbols:
        p = derive(sym, string_key)
        if p in seen:
            raise ValueError(f"pseudonym collision for {sym}: {p}")
        seen.add(p)
        out[sym] = p
    return out
```

- [ ] **Step 5: Emit build_names.h and symbols.map**

Add to `hardener/rasp_hardener/emit.py`:

```python
def render_build_names_h(profile: BuildProfile, symbols: list[str]) -> str:
    """Per-build macro renames; without this header the names compile unchanged (dev builds)."""
    from rasp_hardener.names import rename_map
    renames = rename_map(symbols, profile.string_key)
    lines = [_AUTOGEN, "#ifndef RASP_BUILD_NAMES_H", "#define RASP_BUILD_NAMES_H", ""]
    for sym, pseudo in renames.items():
        lines.append(f"#define {sym} {pseudo}")
    lines += ["", "#endif", ""]
    return "\n".join(lines)


def render_symbols_map(profile: BuildProfile, symbols: list[str]) -> dict[str, str]:
    """{pseudonym: real symbol} for crash mapping. Build artifact; gitignored."""
    from rasp_hardener.names import rename_map
    return {p: sym for sym, p in rename_map(symbols, profile.string_key).items()}
```

In `hardener/rasp_hardener/cli.py` `cmd_gen_build`, after the `emit_headers` call:

```python
    symbols = names.parse_symbols(cpp_dir / "symbols.def")
    names_header = cpp_dir / "build_names.h"
    names_header.write_text(emit.render_build_names_h(profile, symbols))
    written = written + [names_header]
    symbols_map = cpp_dir / "symbols.map"
    symbols_map.write_text(json.dumps(emit.render_symbols_map(profile, symbols), indent=2, sort_keys=True) + "\n")
    written = written + [symbols_map]
```

(add `from rasp_hardener import names` to cli.py's imports). Add `build_names.h` and `symbols.map` to
`.gitignore`'s per-build output block.

In `hardener/tests/test_cli.py`, extend `test_gen_build_emits_headers_and_manifest` after the existing
header assertions (the test's temp `cpp` dir already receives `symbols.def` via the Task 3 setup):

```python
            self.assertTrue((cpp / "build_names.h").exists())
            self.assertTrue((cpp / "symbols.map").exists())
            mapping = json.loads((cpp / "symbols.map").read_text())
            self.assertIn("rasp_seal_report", mapping.values())
            self.assertTrue(all(k.startswith("r") and len(k) == 9 for k in mapping))
            self.assertIn("#define rasp_seal_report ", (cpp / "build_names.h").read_text())
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `cd hardener && python3 -m unittest tests.test_names tests.test_cli -v` → PASS.
Run: `cd hardener && python3 -m unittest discover -s tests -t .` → OK.
Run the native host build → `native tests passed` (no `build_names.h` in the include path → no renames).

- [ ] **Step 7: Commit**

```bash
git add flutter_rasp/android/src/main/cpp/symbols.def hardener/rasp_hardener/names.py hardener/rasp_hardener/emit.py hardener/rasp_hardener/cli.py hardener/tests/test_names.py hardener/tests/test_cli.py .gitignore
git commit -m "feat: per-build symbol renaming with private crash-mapping map (design §6)"
```

---

## Task 9: Source-scan gate

**Files:**
- Test: `hardener/tests/test_source_scan.py`

- [ ] **Step 1: Write the failing test**

Create `hardener/tests/test_source_scan.py`:

```python
"""Gate: every string literal in the native core is either in the registry or explicitly allowlisted.

Strips comments and preprocessor directives (except #define, whose strings land in the binary), extracts
C string literals, decodes them with the registry's own unescape, and asserts each one of >= 4 decoded
bytes is registered. Short literals are out of scope by design: they match by chance in any binary scan.
"""

import pathlib
import re
import unittest

from rasp_hardener.literals import parse_literals, unescape_c

CPP = pathlib.Path(__file__).resolve().parents[2] / "flutter_rasp" / "android" / "src" / "main" / "cpp"

# Deliberately cleartext: cross-language protocol constants byte-matched by the Python side, format
# escapes, the hex alphabet, and the public (non-secret) build id.
ALLOWLIST = {
    b"rasp-report-1",           # report MAC domain, mirrored in rasp_verifier.report
    b"raxp/guard-mesh/v1",      # guard-mesh seed, mirrored in guardmesh.py / integrity.c
    b"0123456789abcdef",        # hex alphabet (sha256.c)
    b"test-build",              # dev RASP_BUILD_ID (public identity)
    b"%lld",                    # integer format
    rb"\u%04x",                 # JSON control-char escape format (signals.c)
}

_LITERAL_RE = re.compile(r'"((?:[^"\\]|\\.)*)"')
_COMMENT_BLOCK_RE = re.compile(r"/\*.*?\*/", re.S)
_COMMENT_LINE_RE = re.compile(r"//[^\n]*")
_DIRECTIVE_RE = re.compile(r"^\s*#\s*(?!define\b)\w+.*$", re.M)


def scan_source(text: str) -> list[str]:
    text = _COMMENT_BLOCK_RE.sub("", text)
    text = _COMMENT_LINE_RE.sub("", text)
    text = _DIRECTIVE_RE.sub("", text)
    return _LITERAL_RE.findall(text)


class SourceScanTest(unittest.TestCase):
    def testCoreSources_everyLiteralIsRegisteredOrAllowlisted(self):
        registered = {lit.raw.encode("ascii") for lit in parse_literals(CPP / "literals.def")}
        offenders = []
        for path in sorted(list(CPP.glob("*.c")) + list(CPP.glob("*.h"))):
            if path.name.startswith("build_"):  # generated / config headers are covered by the hygiene gate
                continue
            for raw in scan_source(path.read_text()):
                try:
                    decoded = unescape_c(raw)
                except ValueError:
                    continue  # exotic escapes would fail unescape_c in the registry; keep scanning
                if len(decoded) >= 4 and decoded not in ALLOWLIST and raw.encode("ascii") not in registered:
                    offenders.append(f"{path.name}: {decoded!r}")
        self.assertEqual(offenders, [])

    def testScanner_findsKnownStrings(self):
        text = 'int x; /* "commented" */\n#include "not_a_literal.h"\nconst char *p = "native.x";\n'
        self.assertEqual(scan_source(text), ["native.x"])
```

Note the `testScanner_findsKnownStrings` expectation: `"not_a_literal.h"` is on a directive line and
`"commented"` is in a comment; only `"native.x"` survives.

- [ ] **Step 2: Run test to verify it fails**

Run: `cd hardener && python3 -m unittest tests.test_source_scan -v`
Expected: FAIL listing remaining offenders (any literal Tasks 5–6 missed — the migration rule says zero).
Fix any offender by moving it into `literals.def` (or the allowlist with a comment, only if it is a
protocol/format constant).

- [ ] **Step 3: Make it pass by fixing offenders**

There is no implementation step: the implementation is Tasks 5–6. If the scan reports an offender, add the
literal to `literals.def` with a name and migrate the call site via `RASP_LIT`, then re-run the native host
tests and the verifier suite before committing.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd hardener && python3 -m unittest tests.test_source_scan -v` → PASS.

- [ ] **Step 5: Commit**

```bash
git add hardener/tests/test_source_scan.py flutter_rasp/android/src/main/cpp/
git commit -m "test: source-scan gate for unregistered literals"
```

---

## Task 10: Hygiene gate and hardened interop smoke

**Files:**
- Test: `hardener/tests/test_hygiene_gate.py`

- [ ] **Step 1: Write the failing test**

Create `hardener/tests/test_hygiene_gate.py`:

```python
"""Acceptance gate: the hardened binary yields no protected plaintext and no meaningful symbol names.

Builds the core as a host shared library from a fixed seed's generated headers, then:
  a) byte-scans the library for registry plaintexts (>= 4 decoded bytes) and forbidden name patterns;
  b) byte-scans for every original symbol name from symbols.def (covers .symtab/.strtab/.dynstr);
  c) after strip, asserts the dynamic export set is a subset of JNI_OnLoad/JNI_OnUnload;
  d) smoke-runs the report builder under hardened headers and byte-compares its JSON with the dev build,
     proving the decrypted keys are wire-valid and encryption is invisible on the wire.

rasp_jni.c is excluded: it needs jni.h (NDK only). Its literals are covered by the table round-trip.
"""

import json
import os
import pathlib
import shutil
import subprocess
import tempfile
import unittest

from rasp_hardener import emit, names
from rasp_hardener.literals import parse_literals, with_build_key
from rasp_hardener.seed import SEED_LEN, BuildProfile

CPP = pathlib.Path(__file__).resolve().parents[2] / "flutter_rasp" / "android" / "src" / "main" / "cpp"
SOURCES = ["detectors.c", "signals.c", "sha256.c", "report.c", "guard.c", "strobf.c", "literals.c",
           "integrity.c", "wbaes.c", "securestore.c"]

SMOKE = r"""
#include <stdio.h>
#include "report.h"
#include "signals.h"

int main(void) {
    rasp_signal_list_t list = {.count = 0};
    rasp_signals_add(&list, RASP_THREAT_ROOT, "native.su_binary", 90, "/system/bin/su");
    char out[4096];
    if (rasp_signals_to_report_json(&list, out, sizeof(out)) < 0) return 1;
    printf("%s\n", out);
    return 0;
}
"""

# The one signal in SMOKE uses a raw detector id/evidence on purpose: the smoke measures the JSON wire
# format produced by the registry-backed builder, not the detectors' own literals.
FORBIDDEN_PATTERNS = [b"rasp_", b"RASP_", b"Java_", b"DEV_LIT"]


class HygieneGateTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if shutil.which("cc") is None and shutil.which("gcc") is None:
            raise unittest.SkipTest("no C compiler")
        cls.cc = os.environ.get("CC") or ("gcc" if shutil.which("gcc") else "cc")
        cls.tmp = pathlib.Path(tempfile.mkdtemp())
        cls.profile = BuildProfile.from_seed(bytes(range(SEED_LEN)))
        cls.lits = with_build_key(parse_literals(CPP / "literals.def"), cls.profile.build_key_hex)
        cls.symbols = names.parse_symbols(CPP / "symbols.def")
        emit.emit_headers(cls.profile, cls.tmp, cls.lits)
        (cls.tmp / "build_names.h").write_text(emit.render_build_names_h(cls.profile, cls.symbols))
        cls.so = cls.tmp / "librasp_core.so"
        subprocess.run(
            [cls.cc, "-shared", "-fPIC", "-fvisibility=hidden", "-O2", "-Wall", "-Wextra", "-Werror",
             "-I", str(cls.tmp), "-I", str(CPP), "-o", str(cls.so)] + [str(CPP / s) for s in SOURCES],
            check=True,
        )
        cls.data = cls.so.read_bytes()

    def testNoRegistryPlaintext_survives(self):
        for lit in self.lits:
            if len(lit.text) >= 4:
                self.assertNotIn(lit.text, self.data, lit.name)

    def testNoForbiddenNamePatterns(self):
        for pattern in FORBIDDEN_PATTERNS:
            self.assertNotIn(pattern, self.data)

    def testNoOriginalSymbolNames_survive(self):
        for sym in self.symbols:
            self.assertNotIn(sym.encode("ascii"), self.data, sym)

    def testStrippedExportSet_isJniOnly(self):
        stripped = self.tmp / "librasp_core_stripped.so"
        subprocess.run(["strip", "--strip-all", "-o", str(stripped), str(self.so)], check=True)
        out = subprocess.run(["nm", "-D", "--defined-only", str(stripped)],
                             capture_output=True, text=True, check=True).stdout
        exported = {line.split()[-1] for line in out.splitlines() if line.strip()}
        self.assertLessEqual(exported, {"JNI_OnLoad", "JNI_OnUnload"})

    def testHardenedJson_matchesDevByteForByte(self):
        harness = self.tmp / "smoke.c"
        harness.write_text(SMOKE)
        hardened_bin = self.tmp / "smoke_hardened"
        subprocess.run([self.cc, "-I", str(self.tmp), "-I", str(CPP), str(harness)]
                       + [str(CPP / s) for s in SOURCES] + ["-o", str(hardened_bin)], check=True)
        dev_bin = self.tmp / "smoke_dev"
        subprocess.run([self.cc, "-I", str(CPP), str(harness)]
                       + [str(CPP / s) for s in SOURCES] + ["-o", str(dev_bin)], check=True)
        run = lambda b: subprocess.run([str(b)], check=True, capture_output=True, text=True).stdout
        hardened_out = run(hardened_bin)
        self.assertEqual(hardened_out, run(dev_bin))
        self.assertIn('"detector":"native.su_binary"', hardened_out)

    def testSymbolsMap_roundTrips(self):
        mapping = emit.render_symbols_map(self.profile, self.symbols)
        self.assertEqual(set(mapping.values()), set(self.symbols))
        self.assertTrue(all(k.startswith("r") and len(k) == 9 for k in mapping))
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd hardener && python3 -m unittest tests.test_hygiene_gate -v`
Expected: FAIL on `testNoRegistryPlaintext_survives` or `testNoForbiddenNamePatterns` if anything leaked,
or a compile error if `build_names.h` renames broke a translation unit (fix `symbols.def` coverage). With
Tasks 1–8 done it should be close to green — a failure here is a real leak; fix it at the source.

- [ ] **Step 3: Fix any failure at the source**

No gate-side loosening: if a plaintext survives, its call site is not migrated (Task 5–6 pattern); if a
name survives, it is missing from `symbols.def` (add it — the `testSymbolsDef_coversEveryHeaderFunction`
test in Task 8 keeps that honest).

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd hardener && python3 -m unittest tests.test_hygiene_gate -v` → PASS.
Run: `cd hardener && python3 -m unittest discover -s tests -t .` → OK.

- [ ] **Step 5: Commit**

```bash
git add hardener/tests/test_hygiene_gate.py
git commit -m "test: binary hygiene gate and hardened interop smoke"
```

---

## Task 11: Docs and full verification

**Files:**
- Modify: `README.md` (Tests + Known limits), `hardener/README.md`, `TODO.md`
- Modify: `hardener/rasp_hardener/__init__.py` (module docstring mentions the new pieces)

- [ ] **Step 1: Update TODO.md**

In `### Build-time hardening (design §6)`:
- Change the `Obfuscation` bullet from `[~]` to `[x]` for string/constant encryption, with the text updated
  to: all registry literals (detector ids, report JSON keys, file paths, needles, evidence, formats, JNI
  literals, the build key) are encrypted per-build and decoded at use; per-build symbol renaming plus
  hidden visibility and stripped release symbols is done (`symbols.def` → `build_names.h`, private
  `symbols.map`); the hygiene and source-scan gates enforce it. Name obfuscation for managed code,
  control-flow flattening, MBA, code virtualization, class/asset encryption and anti-disassembly remain.
- In `### Crypto and storage`, add to the white-box bullet: the build key is no longer a contiguous
  literal (registry slot `BUILD_KEY_HEX`), but XOR is not key hiding — the white-box encodings remain the
  real fix.

In `### Tests`, add: hygiene gate (no plaintext, no symbol names, JNI-only exports), source-scan gate,
hardened-vs-dev byte-identical report JSON.

- [ ] **Step 2: Update README.md**

- `## Tests` block: the native host gcc line now includes `literals.c` (done in Task 4) — verify it reads
  `{detectors,signals,sha256,report,guard,strobf,literals}.c`.
- `## What is verified`: add a bullet: the hardened binary carries no registered plaintext and no original
  symbol names (hygiene gate), the sources carry no unregistered literal (source-scan gate), and the
  hardened build's report JSON is byte-identical to the dev build's.
- `## Known limits`: replace the string-encryption sentence in the hardening bullet with: detector ids,
  JSON keys, paths, needles and the build key are encrypted per build and internal symbols are renamed
  per build, so static strings/symbol analysis no longer maps the checks; the heavy native obfuscation
  (CFF, MBA, virtualization, class/asset encryption, anti-disassembly) is still to come. Keep the
  white-box caveat sentence (XOR ≠ key hiding) in the crypto bullet.

- [ ] **Step 3: Update hardener/README.md**

- Add a row to the module table: `Protected-literal registry + parser | literals.def, literals.py | §6
  obfuscation` and `Per-build symbol renaming | names.py, symbols.def → build_names.h / symbols.map | §6
  name obfuscation`.
- In `## Usage`, document that `gen-build` now also writes `build_names.h` and `symbols.map` (gitignored;
  the map is a secret-ish artifact used for crash symbolication only).
- Update the string-encryption paragraph to point at `literals.def` as the single source of truth and note
  the gates.

- [ ] **Step 4: Full verification**

```bash
cd verifier && python3 -m unittest discover -s tests -t .
cd hardener && python3 -m unittest discover -s tests -t .
gcc -Wall -Wextra -Werror -I flutter_rasp/android/src/main/cpp \
  flutter_rasp/android/src/test/cpp/native_test.c \
  flutter_rasp/android/src/main/cpp/{detectors,signals,sha256,report,guard,strobf,literals}.c \
  -o /tmp/native_test && /tmp/native_test
```

Expected: verifier OK, hardener OK (now including `test_literals`, `test_names`, `test_source_scan`,
`test_hygiene_gate`), `native tests passed`.

- [ ] **Step 5: Commit and open the PR**

```bash
git add README.md hardener/README.md TODO.md hardener/rasp_hardener/__init__.py
git commit -m "docs: obfuscation depth — registry, renaming, and the binary hygiene gates"
git push -u origin feat/obfuscation-depth
gh pr create --base main --head feat/obfuscation-depth \
  --title "feat: obfuscation depth — literal registry, per-build symbol renaming, binary hygiene gates" \
  --body "## Summary
- All protected native literals (detector ids, report JSON keys, file paths, needles, evidence, formats,
  JNI literals, the build key) move into a checked-in X-macro registry (\`literals.def\`) and are encrypted
  per build; the two leaks (build key hex, cleartext detector order) are closed.
- Internal symbols are renamed per build (\`symbols.def\` -> \`build_names.h\`, private \`symbols.map\`).
- New gates: binary hygiene (no plaintext, no symbol names, JNI-only exports), source scan (no
  unregistered literals), hardened-vs-dev byte-identical report JSON.

## Motivation & Context
Design §6 obfuscation depth (spec: docs/superpowers/specs/2026-09-27-obfuscation-depth-design.md). Until
now only 5 JNI literals were encrypted and every detector id / path / symbol name was a free map of the
checks in a strings dump.

## Test Plan & Verification
- [x] hardener suite incl. test_literals / test_names / test_source_scan / test_hygiene_gate
- [x] verifier suite (73+1)
- [x] native host tests
- [x] cross-language KATs unchanged (strenc, guard mesh, white-box, SecureStore, integrity root)

## Checklist
- [x] Spec reviewed and approved
- [x] TODO.md and README updated
- [x] No secrets committed (generated headers/symbols.map gitignored)"
```

Then trigger the bot review per the repo's PR convention and address findings.

---

## Self-review notes (already applied)

- Spec coverage: registry (Task 2–3), decode API + `rasp_threat_name` (Task 4–5), migrations (Task 5–6),
  leak #1/#2 (Task 7), renaming + map (Task 8), gates (Task 9–10), housekeeping + docs (Task 1, 11). The
  spec's "no C escape sequences" rule is refined here: escapes `\\ \" \n \t \r` are supported because the
  report JSON format strings require them; `literals.unescape_c` keeps Python and C in lockstep and rejects
  everything else. The spec's detector-order "slot references" refinement: since no C consumer exists, the
  table is removed from `build_seed.h` entirely (permutation stays in the build manifest).
- Type consistency: `Literal(name, raw, text)`, `parse_literals`, `literals_by_name`, `with_build_key`,
  `unescape_c`, `MAX_TEXT_LEN`; `strenc.obfuscate(str | bytes, ...)`; `emit.emit_headers(profile, out_dir,
  raw_literals)`, `render_build_seed_h(profile, raw_literals)`, `render_build_names_h(profile, symbols)`,
  `render_symbols_map(profile, symbols)`; `names.parse_symbols`, `pseudonym`, `rename_map`; C:
  `rasp_lit_decode(int, char *)`, `RASP_LIT(name, var)`, `RASP_SLOT_<NAME>`, `RASP_LIT_MAXLEN`,
  `RASP_LIT_MAXLEN`, `RASP_SLOT_COUNT`, `r_lits`/`r_lit_lens`/`r_lkey`, `rasp_threat_name(rasp_threat_t, char *)`.
