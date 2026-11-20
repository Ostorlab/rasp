"""The shaded RASP banner that `rasp` prints for people at a terminal."""

import collections.abc
import typing

_ART = (
    "██████╗  █████╗ ███████╗██████╗ ",
    "██╔══██╗██╔══██╗██╔════╝██╔══██╗",
    "██████╔╝███████║███████╗██████╔╝",
    "██╔══██╗██╔══██║╚════██║██╔═══╝ ",
    "██║  ██║██║  ██║███████║██║     ",
    "╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝     ",
)
_SHADES = (
    (0xD3, 0xE1, 0xFF),
    (0xB2, 0xCA, 0xFF),
    (0x8F, 0xB0, 0xFF),
    (0x6D, 0x8F, 0xE0),
    (0x54, 0x70, 0xB8),
    (0x3F, 0x53, 0x8A),
)
_CUBE_LEVELS = (0, 95, 135, 175, 215, 255)
_TRUE_COLOR_VALUES = ("truecolor", "24bit")
_RESET = "\x1b[0m"
_DIM = "\x1b[2m"


class _Stream(typing.Protocol):
    """A text stream that can tell whether it is a terminal."""

    def isatty(self) -> bool:
        """Returns whether the stream is a terminal."""
        ...


def is_enabled(stream: _Stream, env: collections.abc.Mapping[str, str]) -> bool:
    """Returns whether the banner shows on the stream.

    It shows when the stream is a terminal, `NO_COLOR` is unset or empty, and `TERM` is not `dumb`.
    """
    if stream.isatty() is not True:
        return False
    if env.get("NO_COLOR", "") != "":
        return False
    return env.get("TERM") != "dumb"


def _nearest_level(value: int) -> int:
    """Returns the index of the xterm color cube level closest to the channel value."""
    return min(range(len(_CUBE_LEVELS)), key=lambda i: abs(_CUBE_LEVELS[i] - value))


def _color(rgb: tuple[int, int, int], env: collections.abc.Mapping[str, str]) -> str:
    """Returns the escape sequence that sets the foreground to the color.

    It is 24-bit when `COLORTERM` is `truecolor` or `24bit`, and the nearest xterm-256 color otherwise.
    """
    red, green, blue = rgb
    if env.get("COLORTERM", "") in _TRUE_COLOR_VALUES:
        return f"\x1b[38;2;{red};{green};{blue}m"
    index = (
        16 + 36 * _nearest_level(red) + 6 * _nearest_level(green) + _nearest_level(blue)
    )
    return f"\x1b[38;5;{index}m"


def render(version: str, env: collections.abc.Mapping[str, str]) -> str:
    """Returns the banner: the art, one shade per row from light to dark, and the dim tagline with the version.

    The text ends with a newline.
    """
    rows = [
        f"{_color(shade, env)}{row}{_RESET}"
        for row, shade in zip(_ART, _SHADES, strict=True)
    ]
    tagline = f"{_DIM}runtime protection for Android and iOS apps · {version}{_RESET}"
    return "\n".join([*rows, tagline]) + "\n"
