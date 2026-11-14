"""Tests of the check groups of each platform."""

import pathlib
import re

import pytest

from rasp_packer import checks
from rasp_packer import platforms

_RUNTIME = pathlib.Path(__file__).resolve().parents[3] / "runtime"


@pytest.mark.parametrize("platform", list(platforms.Platform))
def testChecks_whenComparedWithTheRuntime_listsTheGroupsItRunsInItsOrder(
    platform: platforms.Platform,
) -> None:
    monitoring = (_RUNTIME / platform / "src" / "monitoring.cpp").read_text()

    # The dispatch names each group with the bit its mask carries, so the order it runs them in and the
    # bit each one sits at are both the packer's CHECKS order.
    runtime_groups = re.findall(r'enabled\((\d+), "(\w+)"\)', monitoring)

    assert [(int(bit), group) for bit, group in runtime_groups] == list(
        enumerate(checks.CHECKS[platform])
    )


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
