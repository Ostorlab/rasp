"""Tests of pack-time actions and the mask read by the runtime."""

import json

import pytest

from rasp_packer import checks
from rasp_packer import errors
from rasp_packer import inspection
from rasp_packer import platforms
from rasp_packer import runtime_config


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


@pytest.mark.parametrize("platform", list(platforms.Platform))
def testConfig_whenReportMaskIsWritten_inspectionReadsEachGroupsAction(
    platform: platforms.Platform,
) -> None:
    """The report mask uses the platform's checks order, including required groups."""
    enabled = checks.CHECKS[platform]
    config = runtime_config.RuntimeConfig(
        build_id="actions",
        checks=enabled,
        checks_mask=checks.checks_mask(platform, enabled),
        report_only_mask=checks.checks_mask(platform, ["mitm", "identity"]),
    )

    fields = inspection._parse_config(config.to_json(), platform)

    assert json.loads(config.to_json())["r"] == checks.checks_mask(
        platform, ["mitm", "identity"]
    )
    assert fields is not None
    assert fields.actions == {
        group: "report" if group in {"mitm", "identity"} else "block"
        for group in sorted(enabled)
    }


def testInspect_whenReportMaskIsMissing_reportsNoActions() -> None:
    """Inspection cannot infer the behavior of runtimes released before actions."""
    config = inspection._parse_config(
        b'{"build_id":"old","m":127}', platforms.Platform.ANDROID
    )

    assert config is not None
    assert config.actions == {}


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
