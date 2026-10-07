"""Guard mesh: mutually-hashing integrity guards (design §6).

The design calls for a network of guards that hash regions of the binary and cross-check one another, so that
patching any guarded region (an inline hook, a NOP'd check) is detected. Crucially the design specifies the
guards feed *data, not branches*: the combined guard output is an integrity value folded into keys/offsets,
so a tampered binary silently derives the wrong value (a broken key, a wrong jump offset) instead of hitting
an ``if (tampered) { … }`` an attacker can find and flip.

This module is the reference derivation. It is mirrored byte-for-byte by ``guard.c`` on the device; the
cross-language test (:mod:`tests.test_emit_native`) compiles the C mesh and asserts it agrees with this on
identical regions, exactly as the sealed-report interop test does for the report MAC.

- :func:`guard_root`   chains each region's digest into the previous accumulator (the "mutual" hashing), so
                       the result depends on every region and on their order.
- :func:`guard_offset` derives an integer offset from the root — the "results feeding data" primitive; a
                       single flipped byte anywhere in the guarded regions changes it.
- :func:`fold_key`     folds the root into a key (HMAC), the intended path for integrity-derived keys (§8):
                       tamper → wrong key → the operation fails closed with no branch to bypass.
"""

from __future__ import annotations

import hashlib
import hmac

MESH_SEED = b"raxp/guard-mesh/v1"


def guard_root(regions: list[bytes]) -> bytes:
    """The 32-byte integrity root over an ordered list of guarded regions.

    ``acc = SHA256(SEED)``; for each region ``acc = SHA256(acc || SHA256(region))``. Order-sensitive and
    avalanche: any single-byte change in any region changes the root.
    """
    acc = hashlib.sha256(MESH_SEED).digest()
    for region in regions:
        digest = hashlib.sha256(region).digest()
        acc = hashlib.sha256(acc + digest).digest()
    return acc


def guard_offset(regions: list[bytes], modulus: int) -> int:
    """A derived offset in ``[0, modulus)`` from the guard root — data, not a branch."""
    if modulus <= 0:
        raise ValueError("modulus must be positive")
    root = guard_root(regions)
    return int.from_bytes(root[:8], "big") % modulus


def fold_key(base_key: bytes, regions: list[bytes]) -> bytes:
    """Fold the guard root into `base_key` (HMAC-SHA256). Tampered regions -> a different, useless key."""
    return hmac.new(base_key, guard_root(regions), hashlib.sha256).digest()
