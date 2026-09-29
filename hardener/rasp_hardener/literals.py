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
import dataclasses

# Scratch-buffer bound for rasp_lit_decode (RASP_LIT_MAXLEN). A test asserts every entry fits.
MAX_TEXT_LEN = 256

_ENTRY_RE = re.compile(r'^RASP_LITERAL\(\s*([A-Z][A-Z0-9_]*)\s*,\s*"((?:[^"\\]|\\.)*)"\s*\)$')

_ESCAPES = {"\\": 0x5C, '"': 0x22, "n": 0x0A, "t": 0x09, "r": 0x0D}


@dataclasses.dataclass(frozen=True, slots=True)
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
            if ord(ch) < 32 or ord(ch) > 126:
                raise ValueError("literal must use printable ASCII or an allowed escape")
            out.append(ord(ch))
        i += 1
    return bytes(out)


def parse_literals(path: str | pathlib.Path) -> list[Literal]:
    """Parse ``literals.def`` in order. Raises ValueError on duplicate names, empty or oversized text."""
    out: list[Literal] = []
    seen: set[str] = set()
    for lineno, line in enumerate(strip_comments(pathlib.Path(path).read_text()).splitlines(), 1):
        line = line.strip()
        if line == "":
            continue
        m = _ENTRY_RE.match(line)
        if m is None:
            raise ValueError(f"{path}:{lineno}: not a RASP_LITERAL(NAME, \"text\") entry: {line}")
        name, raw = m.group(1), m.group(2)
        if name in seen:
            raise ValueError(f"{path}:{lineno}: duplicate literal name {name}")
        text = unescape_c(raw)
        if len(text) == 0:
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
    if sum(lit.name == "BUILD_KEY_HEX" for lit in lits) != 1:
        raise ValueError("registry must contain exactly one BUILD_KEY_HEX slot")
    key = build_key_hex.encode("ascii")
    if len(key) != 64 or any(c not in "0123456789abcdef" for c in build_key_hex):
        raise ValueError("build key must be 64 lowercase hex chars")
    return [Literal(name="BUILD_KEY_HEX", raw=build_key_hex, text=key) if lit.name == "BUILD_KEY_HEX" else lit
            for lit in lits]


def strip_comments(source: str) -> str:
    """Remove C comments without touching quoted text; preserve lines for diagnostics."""
    tokens = re.compile(r'"(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)*\'|/\*.*?\*/|//[^\n]*', re.S)
    return tokens.sub(
        lambda match: "".join("\n" if char == "\n" else " " for char in match.group())
        if match.group().startswith(("/*", "//")) else match.group(), source
    )
