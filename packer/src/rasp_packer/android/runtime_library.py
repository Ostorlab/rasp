"""The runtime's config and key schedule share in the Android runtime library, `librasp.so`.

The library keeps a space for the config in a section of its own, `.rasp_config`, which this module finds; see
runtime_config for what is written into it. The key schedule (key_schedule) adds a 32-byte keystore share after the
config, in the last 32 bytes of the same section: the config's JSON and its zero padding first, then the share, so
the JSON plus its terminating zero must leave those 32 bytes free.
"""

import io

import lief

from rasp_packer import errors
from rasp_packer import runtime_config
from rasp_packer.android import key_schedule

ELF_SECTION = ".rasp_config"

# The name of the library's executable code section, which the key schedule binds the payload to.
TEXT_SECTION = ".text"


def write_config(library: bytes, config: runtime_config.RuntimeConfig) -> bytes:
    """Writes the config into a runtime library, leaving room for the keystore share.

    Args:
        library: The content of a `librasp.so`.
        config: The config.

    Returns:
        The library with the config written into its `.rasp_config` section, and the trailing keystore bytes
        zeroed. Its size does not change.

    Raises:
        InvalidRuntimeError: The library is not an ELF file, or has no `.rasp_config` section.
        ConfigTooLargeError: The config does not fit in the section with the keystore share.
    """
    space = _space(library)
    region = runtime_config.ConfigSpace(
        offset=space.offset, size=space.size - key_schedule.KEY_SIZE
    )
    written = bytearray(runtime_config.write_config(library, region, config))
    start = space.offset + region.size
    written[start : start + key_schedule.KEY_SIZE] = bytes(key_schedule.KEY_SIZE)
    return bytes(written)


def write_keystore(library: bytes, share: bytes) -> bytes:
    """Writes the keystore share into a runtime library, after the config.

    Args:
        library: The content of a `librasp.so`, with its config already written.
        share: The 32-byte share (key_schedule.share_for).

    Returns:
        The library with the share in the last 32 bytes of its `.rasp_config` section. Its size does not change.

    Raises:
        InvalidRuntimeError: The library is not an ELF file, or has no `.rasp_config` section.
        ValueError: The share is not 32 bytes, or the section is too small to hold a config and a share.
    """
    space = _space(library)
    if len(share) != key_schedule.KEY_SIZE:
        raise ValueError(f"the keystore share must be {key_schedule.KEY_SIZE} bytes")
    if space.size < key_schedule.KEY_SIZE + 1:
        raise ValueError(f"the {ELF_SECTION} section is too small for a keystore share")
    written = bytearray(library)
    start = space.offset + space.size - key_schedule.KEY_SIZE
    written[start : start + key_schedule.KEY_SIZE] = share
    return bytes(written)


def config_region(library: bytes) -> bytes:
    """Reads the config region of a runtime library: the section without the keystore share.

    Args:
        library: The content of a `librasp.so`.

    Returns:
        The section's bytes before the trailing 32, the config JSON and its zero padding.

    Raises:
        InvalidRuntimeError: The library is not an ELF file, or has no `.rasp_config` section.
        ValueError: The section is too small to hold a config and a share.
    """
    space = _space(library)
    if space.size < key_schedule.KEY_SIZE + 1:
        raise ValueError(f"the {ELF_SECTION} section is too small for a keystore share")
    return library[space.offset : space.offset + space.size - key_schedule.KEY_SIZE]


def keystore(library: bytes) -> bytes:
    """Reads the keystore share of a runtime library: the section's trailing 32 bytes.

    Args:
        library: The content of a `librasp.so`.

    Returns:
        The share the packer wrote, 32 bytes.

    Raises:
        InvalidRuntimeError: The library is not an ELF file, or has no `.rasp_config` section.
        ValueError: The section is too small to hold a config and a share.
    """
    space = _space(library)
    if space.size < key_schedule.KEY_SIZE + 1:
        raise ValueError(f"the {ELF_SECTION} section is too small for a keystore share")
    return library[
        space.offset + space.size - key_schedule.KEY_SIZE : space.offset + space.size
    ]


def text_region(library: bytes) -> bytes:
    """Reads the executable code of a runtime library: its `.text` section.

    The key schedule binds the payload to these bytes, so patching the library's code breaks decryption.

    Args:
        library: The content of a `librasp.so`.

    Returns:
        The `.text` section's bytes.

    Raises:
        InvalidRuntimeError: The library is not an ELF file, or has no `.text` section.
    """
    section = _elf_section(library, TEXT_SECTION)
    return bytes(section.content)


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
    section = _elf_section(library, ELF_SECTION)
    return runtime_config.ConfigSpace(offset=section.offset, size=section.size)


def _elf_section(library: bytes, name: str) -> lief.ELF.Section:
    """Returns the section of the library named `name`.

    Args:
        library: The content of a `librasp.so`.
        name: The section's name, such as `.rasp_config`.

    Returns:
        The section.

    Raises:
        InvalidRuntimeError: The library is not an ELF file, or has no such section.
    """
    elf = lief.ELF.parse(io.BytesIO(library))
    if elf is None:
        raise errors.InvalidRuntimeError("the runtime library is not an ELF file")
    section = elf.get_section(name)
    if section is None:
        raise errors.InvalidRuntimeError(f"the runtime library has no {name} section")
    return section
