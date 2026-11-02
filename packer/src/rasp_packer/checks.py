"""The check groups the runtime runs on each platform, and the ones every protected app runs.

A check group is one function of the runtime's checks, run by its thread (runtime/<platform>/src/monitoring.cpp), and
its id is the name of that function. The caller of the packer chooses the groups a protected app runs. The packer
writes them into the runtime's config, and the runtime runs only those.
"""

import collections.abc

from rasp_packer import errors
from rasp_packer import platforms

CHECKS: collections.abc.Mapping[platforms.Platform, tuple[str, ...]] = {
    platforms.Platform.ANDROID: (
        "root",
        "debugger",
        "hooks",
        "integrity",
        "mitm",
        "identity",
        "emulator",
    ),
    platforms.Platform.IOS: (
        "jailbreak",
        "debugger",
        "hooks",
        "identity",
        "emulator",
        "virtualizer",
        "mitm",
    ),
}
"""The ids of the check groups of each platform, in the order the runtime runs them."""

REQUIRED_CHECKS: frozenset[str] = frozenset({"identity"})
"""The ids of the check groups every protected app runs, whatever the caller chooses, on every platform."""


def resolve_checks(
    platform: platforms.Platform, checks: collections.abc.Iterable[str]
) -> tuple[str, ...]:
    """Turns the check groups a caller chose into those the runtime's config lists.

    Args:
        platform: The platform of the app.
        checks: The ids of the groups the caller chose. A repeated id counts once.

    Returns:
        The chosen ids and the required ones, each once, sorted.

    Raises:
        UnknownCheckError: An id is not one of the platform's check groups.
    """
    resolved = set(REQUIRED_CHECKS)
    for check in checks:
        if check not in CHECKS[platform]:
            raise errors.UnknownCheckError(
                f"the check {check!r} does not exist for {platform}"
            )
        resolved.add(check)
    return tuple(sorted(resolved))
