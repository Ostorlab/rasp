"""The runtime's config in the iOS runtime binary, `RaspRuntime` in `RaspRuntime.framework`.

Every slice of the binary keeps a space for the config in a section of its own, `__rasp_config` of the `__DATA`
segment, which this module finds; see runtime_config for what is written into it.
"""

import io

import lief

from rasp_packer import errors
from rasp_packer import runtime_config

MACHO_SEGMENT = "__DATA"
MACHO_SECTION = "__rasp_config"


def verify_policy_exports(binary: bytes) -> None:
    """Require the six preserved capture functions and two policy functions in every slice."""
    fat = lief.MachO.parse(io.BytesIO(binary))
    expected = {"_rasp_local_policy_gate_v1", "_rasp_local_policy_info_v1"} | {
        "_rasp_ios_capture_" + suffix
        for suffix in (
            "start",
            "stop",
            "refresh",
            "select_scene",
            "select_legacy_window",
            "clear_selection",
        )
    }
    if (
        fat is None
        or len(fat) == 0
        or any(
            {symbol.name for symbol in macho.exported_symbols} != expected
            for macho in fat
        )
    ):
        raise errors.InvalidRuntimeError(
            "runtime local policy/capture exports do not match the supported ABI"
        )


def write_config(binary: bytes, config: runtime_config.RuntimeConfig) -> bytes:
    """Writes the config into the runtime binary, in every slice of a universal binary.

    Args:
        binary: The content of the `RaspRuntime` binary.
        config: The config.

    Returns:
        The binary with the config written into the `__DATA,__rasp_config` section of each slice. Its size does not
        change.

    Raises:
        InvalidRuntimeError: The binary is not a Mach-O file, or a slice has no `__DATA,__rasp_config` section.
        ConfigTooLargeError: The config does not fit in the section.
    """
    written = binary
    for space in _spaces(binary):
        written = runtime_config.write_config(written, space, config)
    return written


def read_config(binary: bytes) -> list[bytes]:
    """Reads the config written into the runtime binary.

    Args:
        binary: The content of the `RaspRuntime` binary.

    Returns:
        The config's JSON in each slice, in the order of the slices: up to the first zero byte of the slice's
        `__DATA,__rasp_config` section.

    Raises:
        InvalidRuntimeError: The binary is not a Mach-O file, or a slice has no `__DATA,__rasp_config` section.
    """
    return [runtime_config.read_config(binary, space) for space in _spaces(binary)]


def _spaces(binary: bytes) -> list[runtime_config.ConfigSpace]:
    """Finds the `__DATA,__rasp_config` section of every slice of the binary."""
    fat = lief.MachO.parse(io.BytesIO(binary))
    if fat is None:
        raise errors.InvalidRuntimeError("the runtime binary is not a Mach-O file")
    spaces: list[runtime_config.ConfigSpace] = []
    for macho in fat:
        section = macho.get_section(MACHO_SEGMENT, MACHO_SECTION)
        if section is None:
            raise errors.InvalidRuntimeError(
                f"the runtime binary has no {MACHO_SEGMENT},{MACHO_SECTION} section"
            )
        spaces.append(
            runtime_config.ConfigSpace(
                offset=macho.fat_offset + section.offset, size=section.size
            )
        )
    return spaces
