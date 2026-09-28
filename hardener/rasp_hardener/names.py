"""Per-build symbol renaming (design §6 name obfuscation).

Symbols keep their readable names in the repo and in dev builds; ``gen-build`` derives a pseudonym per
symbol from the build seed and emits ``build_names.h`` (``#define rasp_seal_report r7f3a91c``), so every
build's symbols differ and name-keyed bypass scripts rot. The mapping is written to ``symbols.map`` for
crash mapping and must be treated as a build artifact, never published with the app.
"""

from __future__ import annotations

import collections.abc
import hashlib
import hmac
import pathlib
import re

from rasp_hardener import literals

NAME_DOMAIN = b"raxp/names/v1"
_SYMBOL_RE = re.compile(r"^RASP_SYMBOL\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)$")


def parse_symbols(path: str | pathlib.Path) -> list[str]:
    """Parse symbols.def into ordered symbol names."""
    out: list[str] = []
    for lineno, line in enumerate(literals.strip_comments(pathlib.Path(path).read_text()).splitlines(), 1):
        line = line.strip()
        if line == "":
            continue
        m = _SYMBOL_RE.match(line)
        if m is None:
            raise ValueError(f"{path}:{lineno}: not a RASP_SYMBOL(name) entry: {line}")
        if m.group(1) in out:
            raise ValueError(f"duplicate symbol: {m.group(1)}")
        out.append(m.group(1))
    return out


def pseudonym(symbol: str, string_key: bytes) -> str:
    """Seed-derived pseudonym: 'r' + 8 hex chars (valid C identifier, no libc collision)."""
    digest = hmac.new(string_key, NAME_DOMAIN + b"\x00" + symbol.encode("ascii"), hashlib.sha256)
    return "r" + digest.hexdigest()[:8]


def rename_map(symbols: list[str], string_key: bytes, derive: collections.abc.Callable[[str, bytes], str] = pseudonym) -> dict[str, str]:
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
