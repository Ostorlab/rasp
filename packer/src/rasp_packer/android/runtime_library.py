"""The runtime's config in the Android runtime library, `librasp.so`.

The library keeps a space for the config in a section of its own, `.rasp_config`, which this module finds; see
runtime_config for what is written into it.
"""

import io

import lief

from rasp_packer import errors
from rasp_packer import runtime_config

ELF_SECTION = ".rasp_config"


def write_config(library: bytes, config: runtime_config.RuntimeConfig) -> bytes:
    """Writes the config into a runtime library.

    Args:
        library: The content of a `librasp.so`.
        config: The config.

    Returns:
        The library with the config written into its `.rasp_config` section. Its size does not change.

    Raises:
        InvalidRuntimeError: The library is not an ELF file, or has no `.rasp_config` section.
        ConfigTooLargeError: The config does not fit in the section.
    """
    return runtime_config.write_config(library, _space(library), config)


def read_config(library: bytes) -> bytes:
    """Reads the config written into a runtime library.

    Args:
        library: The content of a `librasp.so`.

    Returns:
        The config's JSON, up to the first zero byte of the `.rasp_config` section.

    Raises:
        InvalidRuntimeError: The library is not an ELF file, or has no `.rasp_config` section.
    """
    return runtime_config.read_config(library, _space(library))


def _space(library: bytes) -> runtime_config.ConfigSpace:
    """Finds the `.rasp_config` section of the library."""
    elf = lief.ELF.parse(io.BytesIO(library))
    if elf is None:
        raise errors.InvalidRuntimeError("the runtime library is not an ELF file")
    section = elf.get_section(ELF_SECTION)
    if section is None:
        raise errors.InvalidRuntimeError(
            f"the runtime library has no {ELF_SECTION} section"
        )
    return runtime_config.ConfigSpace(offset=section.offset, size=section.size)
