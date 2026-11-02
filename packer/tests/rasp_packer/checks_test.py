"""Tests of the check groups of each platform."""

import pathlib
import re

import pytest

from rasp_packer import checks
from rasp_packer import errors
from rasp_packer import platforms

_RUNTIME = pathlib.Path(__file__).resolve().parents[3] / "runtime"


@pytest.mark.parametrize("platform", list(platforms.Platform))
def testChecks_whenComparedWithTheRuntime_listsTheGroupsItRunsInItsOrder(
    platform: platforms.Platform,
) -> None:
    monitoring = (_RUNTIME / platform / "src" / "monitoring.cpp").read_text()

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

    assert resolved == ("debugger", "identity", "jailbreak")


def testResolveChecks_whenARequiredCheckIsMissing_addsIt() -> None:
    resolved = checks.resolve_checks(platforms.Platform.ANDROID, ["root"])

    assert resolved == ("identity", "root")


def testResolveChecks_whenGivenNoCheck_returnsTheRequiredOnes() -> None:
    resolved = checks.resolve_checks(platforms.Platform.ANDROID, [])

    assert resolved == ("identity",)


def testResolveChecks_whenACheckIsRepeated_returnsItOnce() -> None:
    resolved = checks.resolve_checks(
        platforms.Platform.IOS, ["hooks", "identity", "hooks"]
    )

    assert resolved == ("hooks", "identity")


def testResolveChecks_whenACheckIsUnknown_raisesUnknownCheckError() -> None:
    with pytest.raises(errors.UnknownCheckError, match="'telepathy'"):
        checks.resolve_checks(platforms.Platform.IOS, ["telepathy"])


def testResolveChecks_whenACheckIsOfTheOtherPlatform_raisesUnknownCheckError() -> None:
    with pytest.raises(errors.UnknownCheckError, match="'jailbreak'"):
        checks.resolve_checks(platforms.Platform.ANDROID, ["jailbreak"])
