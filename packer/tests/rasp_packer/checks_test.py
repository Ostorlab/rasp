"""Tests of the check groups of each platform."""

import pathlib
import re

import pytest

from rasp_packer import capabilities
from rasp_packer import checks
from rasp_packer import platforms

_RUNTIME = pathlib.Path(__file__).resolve().parents[3] / "runtime"


@pytest.mark.parametrize("platform", list(platforms.Platform))
def testChecks_whenComparedWithTheRuntime_listsTheGroupsItRunsInItsOrder(
    platform: platforms.Platform,
) -> None:
    dispatch_file = "builtin.cpp"
    monitoring = (_RUNTIME / platform / "src" / dispatch_file).read_text()

    runtime_groups = re.findall(r'is_check_enabled\(config, "(\w+)"\)', monitoring)

    assert checks.CHECKS[platform] == tuple(runtime_groups)


@pytest.mark.parametrize("platform", list(platforms.Platform))
def testRequiredChecks_whenRead_areChecksOfEveryPlatform(
    platform: platforms.Platform,
) -> None:
    assert checks.REQUIRED_CHECKS.issubset(checks.CHECKS[platform])


def testResolveChecks_whenGivenChecksOfThePlatform_returnsThemSorted() -> None:
    resolved = checks.resolve_checks(
        platforms.Platform.IOS, ["jailbreak", "identity", "debugger"]
    )

    assert resolved.checks == ("debugger", "identity", "jailbreak")
    assert resolved.skipped == ()


def testResolveChecks_whenARequiredCheckIsMissing_addsIt() -> None:
    resolved = checks.resolve_checks(platforms.Platform.ANDROID, ["root"])

    assert resolved.checks == ("identity", "root")


def testResolveChecks_whenGivenNoCheck_returnsTheRequiredOnes() -> None:
    resolved = checks.resolve_checks(platforms.Platform.ANDROID, [])

    assert resolved.checks == ("identity",)
    assert resolved.skipped == ()


def testResolveChecks_whenACheckIsRepeated_returnsItOnce() -> None:
    resolved = checks.resolve_checks(
        platforms.Platform.IOS, ["hooks", "identity", "hooks"]
    )

    assert resolved.checks == ("hooks", "identity")


def testResolveChecks_whenACheckIsUnknown_skipsAndReportsIt() -> None:
    resolved = checks.resolve_checks(platforms.Platform.IOS, ["hooks", "telepathy"])

    assert resolved.checks == ("hooks", "identity")
    assert resolved.skipped == ("telepathy",)


def testResolveChecks_whenACheckIsOfTheOtherPlatform_skipsAndReportsIt() -> None:
    resolved = checks.resolve_checks(platforms.Platform.ANDROID, ["jailbreak"])

    assert resolved.checks == ("identity",)
    assert resolved.skipped == ("jailbreak",)


def testResolveChecks_whenUnknownChecksRepeat_reportsEachOnceInOrder() -> None:
    resolved = checks.resolve_checks(
        platforms.Platform.ANDROID, ["zeta", "root", "alpha", "zeta"]
    )

    assert resolved.checks == ("identity", "root")
    assert resolved.skipped == ("zeta", "alpha")


def testResolveChecks_whenIosIntegritySelected_preservesRuntimeCheck() -> None:
    resolved = checks.resolve_checks(platforms.Platform.IOS, ["integrity"])

    assert resolved.checks == ("identity", "integrity")
    assert resolved.skipped == ()


@pytest.mark.parametrize(
    ("platform", "other_required", "expected"),
    [
        (platforms.Platform.ANDROID, "jailbreak", ("identity", "root")),
        (platforms.Platform.IOS, "root", ("identity", "jailbreak")),
    ],
)
def testResolveChecks_whenPlatformRequirementsDiffer_keepsSelectionsSeparate(
    monkeypatch: pytest.MonkeyPatch,
    platform: platforms.Platform,
    other_required: str,
    expected: tuple[str, ...],
) -> None:
    monkeypatch.setattr(
        checks,
        "REQUIRED_CHECKS_BY_PLATFORM",
        {
            platforms.Platform.ANDROID: frozenset({"identity", "root"}),
            platforms.Platform.IOS: frozenset({"identity", "jailbreak"}),
        },
        raising=False,
    )
    resolved = checks.resolve_checks(platform, [other_required])
    assert resolved.checks == expected
    assert resolved.skipped == (other_required,)


@pytest.mark.parametrize("platform", list(platforms.Platform))
def testRequiredChecks_whenCatalogueRead_matchesSelectedPlatform(
    platform: platforms.Platform,
) -> None:
    groups = capabilities.catalogue()["platforms"][platform.value]["groups"]
    assert checks.REQUIRED_CHECKS_BY_PLATFORM[platform] == frozenset(
        group["name"] for group in groups if group["required"]
    )
    assert checks.resolve_checks(platform, []).checks == ("identity",)
    assert frozenset({"identity"}) == checks.REQUIRED_CHECKS
