"""The check groups the runtime runs on each platform, and the ones every protected app runs.

A check group is one function of the runtime's checks, dispatched by runtime/<platform>/src/builtin.cpp
and run by its monitoring thread, and its id is the name of that function. The caller of the packer chooses the
groups a protected app runs. The packer writes them into the runtime's config, and the runtime runs only those.
"""

import collections.abc
import dataclasses

from rasp_packer import capabilities
from rasp_packer import platforms

CHECKS: collections.abc.Mapping[platforms.Platform, tuple[str, ...]] = {
    platform: tuple(
        group["name"]
        for group in capabilities.catalogue()["platforms"][platform.value]["groups"]
    )
    for platform in platforms.Platform
}
"""Current built-in groups; legacy artifacts use these only for config, without capability claims."""

# Independent RT10 implementation; fold into the canonical manifest on the approved combined parent.
CHECKS = {
    platform: groups + (("overlay",) if platform is platforms.Platform.ANDROID else ())
    for platform, groups in CHECKS.items()
}

REQUIRED_CHECKS_BY_PLATFORM: collections.abc.Mapping[
    platforms.Platform, frozenset[str]
] = {
    platform: frozenset(
        group["name"]
        for group in capabilities.catalogue()["platforms"][platform.value]["groups"]
        if group["required"]
    )
    for platform in platforms.Platform
}
"""Required groups of each platform, used by config resolution."""

REQUIRED_CHECKS: frozenset[str] = frozenset.intersection(
    *REQUIRED_CHECKS_BY_PLATFORM.values()
)
"""Compatibility view of groups required on every platform; use the platform mapping for selection."""


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
    resolved = set(REQUIRED_CHECKS_BY_PLATFORM[platform])
    skipped: dict[str, None] = {}
    for check in checks:
        if check in CHECKS[platform]:
            resolved.add(check)
        else:
            skipped[check] = None
    return ResolvedChecks(checks=tuple(sorted(resolved)), skipped=tuple(skipped))
