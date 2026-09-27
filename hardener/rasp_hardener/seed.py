"""Per-build polymorphism engine (design §6).

Every hardened build is driven by a single random *seed*. From that seed the hardener derives, by a
documented key-derivation, everything that must differ build-to-build so that a bypass developed against one
build does not transfer to the next:

- ``build_key``      the 32-byte HMAC key that seals the RASP report (see ``verifier`` / ``report.c``);
- ``build_id``       the identifier the trust service's build registry keys on;
- ``string_key``     the key stream for compile-time string/constant encryption (see :mod:`strenc`);
- ``opcode_map``     a per-build permutation of the bytecode VM opcodes (design Subsystem 3: opcode ``0x1F``
                     may mean ``ADD`` in one build and ``XOR`` in the next);
- ``detector_order`` a per-build permutation of the native detectors ("detector placement").

The derivation is deterministic: the same seed reproduces the same build, which is what makes a build
reproducible for debugging and re-registration. It is a *pseudo-random* function of the seed only — HMAC-
SHA256 used as a PRF with distinct ASCII labels per output — so the outputs are independent and a leak of one
(e.g. the public ``build_id``) does not reveal another (the secret ``build_key``).

This module has no third-party dependencies; it uses :mod:`hashlib` / :mod:`hmac` from the standard library
so the hardener can run in a minimal CI image.
"""

from __future__ import annotations

import hashlib
import hmac
import os
from dataclasses import dataclass

SEED_LEN = 16

# Base opcodes of the design's bytecode VM. The names are stable across builds; the *byte* each maps to is
# permuted per build by :meth:`BuildProfile.derive`.
BASE_OPCODES: tuple[str, ...] = (
    "NOP", "ADD", "SUB", "XOR", "AND", "OR", "LOAD", "STORE",
    "CMP", "JMP", "HASH", "SVC", "MOV", "SHL", "SHR", "RET",
)

# The native detectors, in their source declaration order (see detectors.h / rasp_run_all). The hardener
# emits a per-build permutation of these so their placement in the binary differs build-to-build.
DETECTOR_IDS: tuple[str, ...] = (
    "su_binaries", "root_mounts", "selinux_permissive", "emulator_files", "tracer",
    "instrumentation_maps", "instrumentation_threads", "instrumentation_port", "maps_exec_suspicious",
)


class SeedError(ValueError):
    pass


def _prf(seed: bytes, label: bytes, counter: int = 0) -> bytes:
    """HMAC-SHA256 PRF block: independent 32 bytes per (label, counter)."""
    return hmac.new(seed, label + counter.to_bytes(4, "big"), hashlib.sha256).digest()


def _stream(seed: bytes, label: bytes, nbytes: int) -> bytes:
    """A pseudo-random byte stream of length `nbytes` for `label`, by counter-mode HMAC over the seed."""
    out = bytearray()
    counter = 0
    while len(out) < nbytes:
        out += _prf(seed, label, counter)
        counter += 1
    return bytes(out[:nbytes])


def _permutation(seed: bytes, label: bytes, n: int) -> list[int]:
    """A deterministic permutation of ``range(n)`` via Fisher-Yates over the PRF stream for `label`.

    Draws 2 bytes of randomness per swap and reduces them modulo the shrinking range; with a 2-byte draw and
    n <= 256 the modulo bias is negligible for this use (build-to-build diversity, not a cryptographic
    shuffle of secret data).
    """
    stream = _stream(seed, label, max(1, n) * 2)
    order = list(range(n))
    for i in range(n - 1, 0, -1):
        r = (stream[(n - 1 - i) * 2] << 8) | stream[(n - 1 - i) * 2 + 1]
        j = r % (i + 1)
        order[i], order[j] = order[j], order[i]
    return order


@dataclass(frozen=True)
class BuildProfile:
    """The per-build secrets and layout derived from a seed. See the module docstring."""

    seed: bytes
    build_id: str
    build_key: bytes
    string_key: bytes
    opcode_map: dict[str, int]
    detector_order: tuple[str, ...]

    @classmethod
    def derive(cls, seed: bytes | None = None) -> "BuildProfile":
        """Derive a profile from `seed` (16 bytes). With no seed, a fresh random one is drawn."""
        if seed is None:
            seed = os.urandom(SEED_LEN)
        if not isinstance(seed, (bytes, bytearray)):
            raise SeedError("seed must be bytes")
        seed = bytes(seed)
        if len(seed) != SEED_LEN:
            raise SeedError(f"seed must be {SEED_LEN} bytes, got {len(seed)}")

        build_key = _prf(seed, b"raxp/build-key")
        build_id = "b-" + _prf(seed, b"raxp/build-id").hex()[:12]
        string_key = _prf(seed, b"raxp/string-key")

        op_perm = _permutation(seed, b"raxp/opcodes", len(BASE_OPCODES))
        # Assign each base opcode a distinct byte in 0x10..0x10+N-1, permuted per build.
        opcode_map = {name: 0x10 + op_perm[i] for i, name in enumerate(BASE_OPCODES)}

        det_perm = _permutation(seed, b"raxp/detectors", len(DETECTOR_IDS))
        detector_order = tuple(DETECTOR_IDS[i] for i in det_perm)

        return cls(
            seed=seed,
            build_id=build_id,
            build_key=build_key,
            string_key=string_key,
            opcode_map=opcode_map,
            detector_order=detector_order,
        )

    @property
    def seed_hex(self) -> str:
        return self.seed.hex()

    @property
    def build_key_hex(self) -> str:
        return self.build_key.hex()

    def summary(self) -> dict:
        """A JSON-safe summary for logs and the ``show`` CLI (never includes the secret key material)."""
        return {
            "build_id": self.build_id,
            "seed": self.seed_hex,
            "opcode_map": self.opcode_map,
            "detector_order": list(self.detector_order),
        }
