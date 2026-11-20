"""Tests of the RASP banner."""

import collections.abc

import pytest

from rasp_packer import banner


class _Stream:
    """A stream that is, or is not, a terminal."""

    def __init__(self, tty: bool) -> None:
        """Stores whether the stream is a terminal."""
        self._tty = tty

    def isatty(self) -> bool:
        """Returns whether the stream is a terminal."""
        return self._tty


_TERMINAL_ENV = {"TERM": "xterm-256color"}


def testIsEnabled_whenTerminalAndNothingTurnsItOff_returnsTrue() -> None:
    """A terminal with no opt-out shows the banner."""

    assert banner.is_enabled(_Stream(True), _TERMINAL_ENV) is True


def testIsEnabled_whenStreamIsNotATerminal_returnsFalse() -> None:
    """A stream that is not a terminal does not show the banner."""

    assert banner.is_enabled(_Stream(False), _TERMINAL_ENV) is False


def testIsEnabled_whenNoColorIsSet_returnsFalse() -> None:
    """A set NO_COLOR turns the banner off."""

    assert banner.is_enabled(_Stream(True), {**_TERMINAL_ENV, "NO_COLOR": "1"}) is False


def testIsEnabled_whenNoColorIsEmpty_returnsTrue() -> None:
    """An empty NO_COLOR does not turn the banner off."""

    assert banner.is_enabled(_Stream(True), {**_TERMINAL_ENV, "NO_COLOR": ""}) is True


def testIsEnabled_whenTermIsDumb_returnsFalse() -> None:
    """A dumb TERM turns the banner off."""

    assert banner.is_enabled(_Stream(True), {"TERM": "dumb"}) is False


def testIsEnabled_whenTermIsUnset_returnsTrue() -> None:
    """An unset TERM does not turn the banner off."""

    assert banner.is_enabled(_Stream(True), {}) is True


@pytest.mark.parametrize("colorterm", ["truecolor", "24bit"])
def testRender_whenColorTermIsTrueColor_usesTheShadesIn24Bit(colorterm: str) -> None:
    """Each row gets its own 24-bit color and a reset."""

    lines = banner.render("1.2.3", {"COLORTERM": colorterm}).splitlines()

    assert lines[0].startswith("\x1b[38;2;211;225;255m██████╗")
    assert lines[5].startswith("\x1b[38;2;63;83;138m╚═╝")
    assert all(line.endswith("\x1b[0m") for line in lines)


def testRender_whenNoTrueColor_usesTheNearest256Colors() -> None:
    """Without true color the rows use xterm-256 colors."""

    lines = banner.render("1.2.3", {}).splitlines()

    assert lines[0].startswith("\x1b[38;5;189m")
    assert lines[5].startswith("\x1b[38;5;60m")
    assert "38;2;" not in "".join(lines)


def testRender_always_endsWithTheDimTaglineAndTheVersion() -> None:
    """The last line is the dim tagline with the version."""

    lines = banner.render("1.2.3", {}).splitlines()

    assert len(lines) == 7
    assert lines[6] == (
        "\x1b[2mruntime protection for Android and iOS apps · 1.2.3\x1b[0m"
    )


def testRender_always_keepsTheArtOfEachRowAt32Columns() -> None:
    """Each art row is 32 characters wide."""

    rows: collections.abc.Sequence[str] = banner.render("1", {}).splitlines()[:6]

    assert [
        len(row.removeprefix(row[: row.index("m") + 1]).removesuffix("\x1b[0m"))
        for row in rows
    ] == [32] * 6
