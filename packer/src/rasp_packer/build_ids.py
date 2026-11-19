"""The build id the packer generates when the caller gives none."""

import collections.abc
import hashlib
import pathlib
from importlib import metadata

from rasp_packer import checks as check_groups
from rasp_packer import errors
from rasp_packer import platforms

_CHUNK_SIZE = 1024 * 1024


def default_build_id(
    *,
    app: pathlib.Path,
    platform: platforms.Platform,
    checks: collections.abc.Iterable[str],
) -> str:
    """Derives the build id of a protected app from what goes into it.

    The id is the hex SHA-256 of the SHA-256 of the app's bytes, the platform, the installed packer's version and the
    resolved check ids (sorted, comma-separated), joined with newlines. The same app, platform, packer version and
    checks always give the same id.

    Args:
        app: The built app, read in chunks.
        platform: The platform of the app.
        checks: The ids of the check groups the caller chose.

    Returns:
        The id, 64 hexadecimal characters.

    Raises:
        InvalidAppError: The app cannot be read.
    """
    digest = hashlib.sha256()
    try:
        with app.open("rb") as stream:
            while len(chunk := stream.read(_CHUNK_SIZE)) > 0:
                digest.update(chunk)
    except OSError as error:
        raise errors.InvalidAppError(f"cannot read {app}: {error}") from error
    resolved = check_groups.resolve_checks(platform, checks).checks
    canonical = "\n".join(
        [
            digest.hexdigest(),
            str(platform),
            metadata.version("rasp-packer"),
            ",".join(sorted(resolved)),
        ]
    )
    return hashlib.sha256(canonical.encode()).hexdigest()
