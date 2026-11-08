"""The key schedule that protects the payload: no key ships in the app.

The schedule replaces the single clear key the packer once shipped as an APK
entry. Nothing in the package is "the key": the runtime rebuilds the payload's
root key by combining, with XOR, five 32-byte values that come from five
different places, so no one of them, and no proper subset, is enough:

- ``share_lib`` — the last 32 bytes of the ``.rasp_config`` section of
  ``librasp.so``, a share the packer writes per ABI (runtime_library).
- ``share_asset`` — the stored APK entry ``assets/rasp/s.bin``, random bytes.
- ``bind_config`` — SHA-256 of the rest of the ``.rasp_config`` section (the
  config JSON and its zero padding), so the section cannot be swapped
  unnoticed.
- ``bind_text`` — SHA-256 of the ``.text`` section of ``librasp.so`` as
  shipped, so a patched library breaks decryption silently: the tag of every
  frame then fails, with no branch anywhere that says why.
- ``gates`` — environment facts that hold on a clean device: a JNI environment
  reporting JNI 1.x, ``TracerPid`` 0 in ``/proc/self/status``, and the library
  loaded from under ``/data``. An emulation without a real Android runtime
  derives a wrong key, and the failure looks like a corrupt frame, not like a
  detection.

The root key itself never decrypts a frame. Every frame's key is
HKDF-SHA256 over its stage's master, with the frame's nonce as salt and
``rasp.v1.frame/<entry>`` as info, so every frame has its own key and renaming
an entry breaks its decryption. There are two stages: the class map is sealed
under a key derived from the root, and every business dex under a key derived
from the dex master — the root XOR the SHA-256 of the encrypted map frame
itself, so the map as shipped is part of every dex key.

The packer picks the root at random and derives each ABI's ``share_lib`` so
that the ABI's bindings cancel out (share_for), and every ABI recovers the
same root. The runtime mirrors this module in
``runtime/android/src/payload/key_schedule.cpp``, and the tests of both sides
check the same fixed vectors.
"""

import hashlib
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from rasp_packer.android import cipher

KEY_SIZE = 32

# The APK entry that holds the asset share, stored: 32 random bytes that are
# one input of the fold, not the key.
SHARE_ENTRY = "assets/rasp/s.bin"

# The HKDF info every frame key starts with, followed by the frame's full APK
# entry name.
FRAME_INFO_PREFIX = b"rasp.v1.frame/"

# The gate block of a clean device: a JNI environment, no tracer, the library
# under /data. The packer folds this in; the runtime folds in what it observes.
CLEAN_GATES = bytes((1, 1, 1)) + bytes(KEY_SIZE - 3)


def new_root() -> bytes:
    """Returns a fresh random root key, the master of the payload's first stage."""
    return os.urandom(KEY_SIZE)


def new_share() -> bytes:
    """Returns a fresh random share, one input of the fold."""
    return os.urandom(KEY_SIZE)


def fold(*parts: bytes) -> bytes:
    """Returns the bytewise XOR of the parts.

    Args:
        parts: The 32-byte values to combine. At least one.

    Returns:
        Their XOR, 32 bytes.

    Raises:
        ValueError: A part is not 32 bytes, or there is no part.
    """
    if len(parts) == 0 or any(len(part) != KEY_SIZE for part in parts):
        raise ValueError(f"every part must be {KEY_SIZE} bytes")
    folded = bytearray(KEY_SIZE)
    for part in parts:
        for index in range(KEY_SIZE):
            folded[index] ^= part[index]
    return bytes(folded)


def bind_config(config_region: bytes) -> bytes:
    """Returns the binding of the config region: SHA-256 of its bytes.

    Args:
        config_region: The ``.rasp_config`` section without its trailing
            keystore share, as shipped.

    Returns:
        The binding, 32 bytes.
    """
    return _digest(config_region)


def bind_text(text: bytes) -> bytes:
    """Returns the binding of the library's code: SHA-256 of its ``.text`` bytes.

    Args:
        text: The ``.text`` section of ``librasp.so``, as shipped.

    Returns:
        The binding, 32 bytes.
    """
    return _digest(text)


def gate_block(
    *, java_environment: bool, no_tracer: bool, installed_under_data: bool
) -> bytes:
    """Returns the gate block of an environment.

    Args:
        java_environment: A JNI environment exists and reports a JNI 1.x version.
        no_tracer: ``TracerPid`` in ``/proc/self/status`` is 0.
        installed_under_data: The library is loaded from a path under ``/data``.

    Returns:
        The block, 32 bytes: one fact per byte at the start, then zeros.
    """
    block = bytearray(KEY_SIZE)
    block[0] = 1 if java_environment else 0
    block[1] = 1 if no_tracer else 0
    block[2] = 1 if installed_under_data else 0
    return bytes(block)


def share_for(
    root: bytes,
    share_asset: bytes,
    config_binding: bytes,
    text_binding: bytes,
    gates: bytes,
) -> bytes:
    """Returns the keystore share that makes one ABI recover `root`.

    The runtime folds the share with the asset share, both bindings and the
    gates; the share returned here is the root XOR all of those, so that fold
    gives back the root for this ABI's library.

    Args:
        root: The root key.
        share_asset: The asset share, shipped as the s.bin entry.
        config_binding: bind_config of this ABI's library.
        text_binding: bind_text of this ABI's library.
        gates: The gate block folded in, CLEAN_GATES at pack time.

    Returns:
        The share to write into this ABI's ``.rasp_config`` section.

    Raises:
        ValueError: An argument is not 32 bytes.
    """
    return fold(root, share_asset, config_binding, text_binding, gates)


def root_key(
    share_lib: bytes,
    share_asset: bytes,
    config_binding: bytes,
    text_binding: bytes,
    gates: bytes,
) -> bytes:
    """Returns the root key recovered from the shipped parts.

    This is the recovery the runtime performs; the packer's tests use it to
    prove both sides agree.

    Args:
        share_lib: The keystore share read from the library's section.
        share_asset: The asset share read from the s.bin entry.
        config_binding: bind_config of the library as shipped.
        text_binding: bind_text of the library as shipped.
        gates: The gate block of the environment the runtime observed.

    Returns:
        The root key.

    Raises:
        ValueError: An argument is not 32 bytes.
    """
    return fold(share_lib, share_asset, config_binding, text_binding, gates)


def frame_key(master: bytes, nonce: bytes, entry: str) -> bytes:
    """Returns the key of one frame: HKDF-SHA256 of its stage's master.

    The nonce is the frame's own, the salt of the derivation, and the entry
    name is part of the info, so two frames of one stage never share a key and
    a renamed entry no longer decrypts.

    Args:
        master: The stage's master key: the root for the class map, the dex
            master for a business dex.
        nonce: The frame's nonce, 12 bytes.
        entry: The frame's full APK entry name, such as ``assets/rasp/map.bin``.

    Returns:
        The frame key, 32 bytes.

    Raises:
        ValueError: The master is not 32 bytes, or the nonce is not 12 bytes.
    """
    if len(master) != KEY_SIZE:
        raise ValueError(f"the master must be {KEY_SIZE} bytes")
    if len(nonce) != cipher.NONCE_SIZE:
        raise ValueError(f"the nonce must be {cipher.NONCE_SIZE} bytes")
    return HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=nonce,
        info=FRAME_INFO_PREFIX + entry.encode("utf-8"),
    ).derive(master)


def dex_master(root: bytes, map_frame: bytes) -> bytes:
    """Returns the master of the business dexes: the root bound to the map frame.

    The map frame as shipped — its nonce, ciphertext and tag — is hashed and
    folded with the root, so replacing the map breaks every dex key too.

    Args:
        root: The root key.
        map_frame: The encrypted class map, the whole frame as shipped.

    Returns:
        The dex master, 32 bytes.

    Raises:
        ValueError: The root is not 32 bytes.
    """
    return fold(root, _digest(map_frame))


def _digest(data: bytes) -> bytes:
    """Returns the SHA-256 of `data`."""
    return hashlib.sha256(data).digest()
