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


@pytest.mark.parametrize("platform", list(platforms.Platform))
def testDescriptions_whenRead_coverEveryCheckOfThePlatform(
    platform: platforms.Platform,
) -> None:
    """Every check group of the platform has a non-empty description."""
    for check in checks.CHECKS[platform]:
        assert checks.DESCRIPTIONS[check].strip() != ""


def testDescribeChecks_whenIosIsListed_givesOneLinePerGroupInRunOrderAndMarksTheRequiredOne() -> (
    None
):
    """The listing has one line per group, led by its id, and only the required group is marked."""
    lines = checks.describe_checks(platforms.Platform.IOS)

    assert [line.split()[0] for line in lines] == list(
        checks.CHECKS[platforms.Platform.IOS]
    )
    assert [line.endswith("(always on)") for line in lines] == [
        check in checks.REQUIRED_CHECKS
        for check in checks.CHECKS[platforms.Platform.IOS]
    ]


def testSuggestCheck_whenTheIdIsATypo_returnsTheClosestCheck() -> None:
    """Checks that a typo of a check id gets that check as the suggestion."""

    suggestion = checks.suggest_check(platforms.Platform.ANDROID, "debuger")

    assert suggestion == "debugger"


def testSuggestCheck_whenNoCheckIsClose_returnsNone() -> None:
    """Checks that an id unlike every check gets no suggestion."""

    suggestion = checks.suggest_check(platforms.Platform.ANDROID, "telepathy")

    assert suggestion is None


def testSuggestCheck_whenTheCloseCheckIsOfTheOtherPlatform_returnsNone() -> None:
    """Checks that the suggestion comes from the platform's own checks only."""

    suggestion = checks.suggest_check(platforms.Platform.ANDROID, "jailbrek")

    assert suggestion is None


@pytest.mark.parametrize("platform", list(platforms.Platform))
def testActionMask_whenComparedWithTheRuntime_usesTheDispatchOrder(
    platform: platforms.Platform,
) -> None:
    """The action filter and enabled-check mask assign the same bit to each group."""
    panic = (_RUNTIME / "core" / "src" / "panic.cpp").read_text()
    name = "kAndroidGroups" if platform == platforms.Platform.ANDROID else "kIosGroups"
    declaration = panic.split(name + " =", 1)[1].split(";", 1)[0]

    assert tuple(re.findall(r'"(\w+)"', declaration)) == checks.CHECKS[platform]
    assert set(checks.DEFAULT_ACTIONS) == set().union(*checks.CHECKS.values())


def testVerdicts_whenComparedWithBuiltInChecks_coverEverySignalConstant() -> None:
    """Every built-in signal, including those produced outside checks, has an explicit group."""
    panic = (_RUNTIME / "core" / "src" / "panic.cpp").read_text()
    verdicts = set(re.findall(r'\.signal = "([a-z]+\.[a-z0-9_]+)"', panic))
    signals = {"integ.monitor_alive", "id.debuggable", "hook.inline", "hw.machine"}
    for platform in platforms.Platform:
        for source in (_RUNTIME / platform / "src" / "checks").glob("*.cpp"):
            signals.update(
                re.findall(
                    r'constexpr\s+std::string_view\s+k\w*Signal\s*=\s*"([^"]+)"',
                    source.read_text(),
                )
            )

    assert signals <= verdicts, (
        f"built-in signals without a verdict: {sorted(signals - verdicts)}"
    )
