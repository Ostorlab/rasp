"""The build id: the deterministic id of a protected build, which the packer writes into the app."""

import collections.abc
import hashlib
import uuid

from rasp_packer import platforms

_SCHEME = "rasp-build/v1"


def compute_id(
    *,
    application_id: uuid.UUID,
    app_digest: str,
    platform: platforms.Platform,
    protection_version: int,
) -> str:
    """Computes the build id of an app from its inputs.

    The build id names one version of an app protected at one protection version of its
    platform, so anyone can recompute it from the same inputs and those inputs only ever give
    one build.

    The id is the scheme ``rasp-build/v1`` followed by ``:`` and the hex SHA-256 over these
    parts, each prefixed with its 8-byte big-endian length so they cannot run together:

    1. the scheme ``rasp-build/v1``, so a later formula uses a new scheme and never collides
       with this one;
    2. the application id, as its 16 raw bytes;
    3. the lowercase hex SHA-256 of the unprotected input app file, as ASCII;
    4. the platform name, as UTF-8;
    5. the platform's protection version, in decimal, as ASCII.

    Args:
        application_id: Id of the application in the RASP registry.
        app_digest: The lowercase hex SHA-256 of the unprotected input app file.
        platform: The platform of the app.
        protection_version: The protection version of the platform.

    Returns:
        The build id, such as ``rasp-build/v1:<hex>``.
    """
    build_hash = _digest_parts(
        [
            _SCHEME.encode("utf-8"),
            application_id.bytes,
            app_digest.encode("ascii"),
            platform.value.encode("utf-8"),
            str(protection_version).encode("ascii"),
        ]
    )
    return f"{_SCHEME}:{build_hash}"


def _digest_parts(parts: collections.abc.Iterable[bytes]) -> str:
    """Returns the hex SHA-256 over the parts, each prefixed with its 8-byte big-endian length."""
    hasher = hashlib.sha256()
    for part in parts:
        hasher.update(len(part).to_bytes(8, "big"))
        hasher.update(part)
    return hasher.hexdigest()
