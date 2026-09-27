"""Code-tamper hashing (design §6 "check weaving ... results feeding data"; §8 code-tamper hashing).

Hashes the artifacts that define a build — the native sources or the compiled ``.so``, and the app's signing
certificate — and folds them into a single *integrity root* via the guard mesh. The root is recorded in the
build-registration manifest so the trust service knows the exact code identity behind a ``build_id``. On
device the same regions feed the guard mesh at runtime (see :mod:`guardmesh`), so a patched binary derives a
different root and fails closed rather than branching.

Hashes are over file bytes here (reproducible in CI without a device). On a real ``.so`` the relevant regions
are the ``.text`` and ``.rodata`` pages; that refinement is noted in the design and left for the native build.
"""

from __future__ import annotations

import hashlib
import pathlib

from rasp_hardener import elf
from rasp_hardener import guardmesh


def hash_file(path: str | pathlib.Path) -> str:
    """SHA-256 of a file's bytes, hex."""
    data = pathlib.Path(path).read_bytes()
    return hashlib.sha256(data).hexdigest()


def hash_paths(paths: list[str | pathlib.Path]) -> dict[str, str]:
    """``{basename: sha256hex}`` for each path, sorted by basename for a stable manifest."""
    out: dict[str, str] = {}
    for p in paths:
        p = pathlib.Path(p)
        out[p.name] = hash_file(p)
    return dict(sorted(out.items()))


def integrity_root(code_hashes: dict[str, str], signer_digests: list[str]) -> str:
    """Fold the code hashes and signing-cert digests into one 32-byte root (hex) via the guard mesh.

    Regions are the raw digest bytes, code hashes first (in the dict's order — keep it sorted), then the
    sorted signer digests. Any change to any input changes the root.
    """
    regions = [bytes.fromhex(h) for h in code_hashes.values()]
    regions += [bytes.fromhex(d) for d in sorted(signer_digests)]
    return guardmesh.guard_root(regions).hex()


def so_regions(path: str | pathlib.Path) -> list[tuple[int, int]]:
    """The (file offset, length) ranges of a `.so`'s code/read-only sections — what the device hashes."""
    data = pathlib.Path(path).read_bytes()
    return [(s.offset, s.size) for s in elf.integrity_sections(data)]


def so_integrity_root(path: str | pathlib.Path) -> tuple[str, list[tuple[int, int]]]:
    """Compute the integrity root over a `.so`'s code/read-only region bytes.

    Returns ``(root_hex, regions)`` where the root is ``guard_root`` over the bytes of each region in offset
    order — exactly what the native `rasp_integrity_root_from_file` computes on device over the same file and
    regions, so build-time and runtime roots agree (verified by the cross-language test).
    """
    data = pathlib.Path(path).read_bytes()
    regions = [(s.offset, s.size) for s in elf.integrity_sections(data)]
    region_bytes = [data[off : off + size] for (off, size) in regions]
    return guardmesh.guard_root(region_bytes).hex(), regions
