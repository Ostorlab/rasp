"""Tests of pack-time actions and the mask read by the runtime."""

import pytest

from rasp_packer import checks
from rasp_packer import errors
from rasp_packer import platforms


@pytest.mark.parametrize("platform", list(platforms.Platform))
def testResolveChecks_whenActionsAreOmitted_usesTheDefaultOfEveryEnabledGroup(
    platform: platforms.Platform,
) -> None:
    """Every enabled group gets the single table's default."""
    resolved = checks.resolve_checks(platform, checks.CHECKS[platform])

    assert resolved.actions == {
        group: checks.DEFAULT_ACTIONS[group] for group in resolved.checks
    }
    assert {
        group for group, action in checks.DEFAULT_ACTIONS.items() if action == "report"
    } == {"root", "jailbreak", "emulator", "mitm"}


def testResolveChecks_whenActionsOverrideDefaults_keepsUnknownIdsForWarnings() -> None:
    """Overrides select actions without enabling groups or losing unknown ids."""
    resolved = checks.resolve_checks(
        platforms.Platform.ANDROID,
        ["root", "debugger"],
        report_only=["debugger", "jailbreak"],
        block=["root"],
    )

    assert resolved.actions == {
        "debugger": "report",
        "identity": "block",
        "root": "block",
    }
    assert resolved.skipped == ("jailbreak",)


@pytest.mark.parametrize(
    ("report_only", "block"), [(["root"], ["root"]), (["hooks"], []), ([], ["hooks"])]
)
def testResolveChecks_whenActionsConflictOrNameADisabledGroup_refusesTheChoice(
    report_only: list[str],
    block: list[str],
) -> None:
    """An override cannot contradict another or silently enable a disabled group."""
    with pytest.raises(errors.InvalidCheckActionError):
        checks.resolve_checks(
            platforms.Platform.ANDROID, ["root"], report_only=report_only, block=block
        )


def testResolveChecks_whenUnknownActionsAreRepeated_reportsThemOnceInInputOrder() -> (
    None
):
    """Override warnings keep the same order and duplicate handling as check warnings."""
    resolved = checks.resolve_checks(
        platforms.Platform.ANDROID,
        ["first"],
        report_only=["zeta", "alpha", "zeta"],
        block=["last", "alpha"],
    )

    assert resolved.skipped == ("first", "zeta", "alpha", "last")
