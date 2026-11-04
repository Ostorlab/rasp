"""The check groups the runtime runs on each platform, and the ones every protected app runs.

A check group is one function of the runtime's checks, run by its thread (runtime/<platform>/src/monitoring.cpp), and
its id is the name of that function. The caller of the packer chooses the groups a protected app runs. The packer
writes them into the runtime's config, and the runtime runs only those.
"""

import collections.abc
import dataclasses

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


@dataclasses.dataclass(frozen=True, slots=True, kw_only=True)
class ResolvedChecks:
    """The check groups the runtime's config lists, and the ids the packer skipped.

    Attributes:
        checks: The chosen ids that are check groups of the platform, and the required ones, each
            once, sorted.
        skipped: The chosen ids that are not check groups of the platform, each once, in the order
            the caller gave them. The packer skips them, so that a caller still packs when it
            passes a check group that was renamed or removed.
    """

    checks: tuple[str, ...]
    skipped: tuple[str, ...]


def resolve_checks(
    platform: platforms.Platform, checks: collections.abc.Iterable[str]
) -> ResolvedChecks:
    """Turns the check groups a caller chose into those the runtime's config lists.

    Args:
        platform: The platform of the app.
        checks: The ids of the groups the caller chose. A repeated id counts once.

    Returns:
        The chosen ids that are check groups of the platform with the required ones, and the
        skipped ids that are not.
    """
    resolved = set(REQUIRED_CHECKS)
    skipped: dict[str, None] = {}
    for check in checks:
        if check in CHECKS[platform]:
            resolved.add(check)
        else:
            skipped[check] = None
    return ResolvedChecks(checks=tuple(sorted(resolved)), skipped=tuple(skipped))
