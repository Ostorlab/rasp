"""The runtime's config and key schedule share in the Android runtime library, `librasp.so`.

The library keeps a space for the config in a section of its own, `.rasp_config`, which this module finds; see
runtime_config for what is written into it. The key schedule (key_schedule) fills the rest of the section with its
own material, in this order: the config's JSON and its zero padding, then the fold program — the per-app recipe of
the schedule's chains — then the 32-byte keystore share, in the section's last bytes. The config's JSON plus its
terminating zero must leave those bytes free.

The config region, the section's bytes before the keystore share, holds the JSON, the padding and the fold program:
the schedule folds its digest into the root key, so the program cannot be swapped, altered or dropped without
breaking every key derived after it.
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
    """Writes the config into a runtime library, leaving room for the fold program and the keystore share.

    Args:
        library: The content of a `librasp.so`.
        config: The config.

    Returns:
        The library with the config written into its `.rasp_config` section, and the trailing program and keystore
        bytes zeroed. Its size does not change.

    Raises:
        InvalidRuntimeError: The library is not an ELF file, or has no `.rasp_config` section.
        ConfigTooLargeError: The config does not fit in the section with the program and the share.
    """
    space = _space(library)
    region = runtime_config.ConfigSpace(
        offset=space.offset,
        size=space.size - key_schedule.PROGRAM_SIZE - key_schedule.KEY_SIZE,
    )
    written = bytearray(runtime_config.write_config(library, region, config))
    start = space.offset + region.size
    written[start : start + key_schedule.PROGRAM_SIZE + key_schedule.KEY_SIZE] = bytes(
        key_schedule.PROGRAM_SIZE + key_schedule.KEY_SIZE
    )
    return bytes(written)


def write_program(library: bytes, program: bytes) -> bytes:
    """Writes the fold program into a runtime library, between the config's padding and the keystore share.

    Args:
        library: The content of a `librasp.so`, with its config already written.

    Returns:
        The library with the program in the bytes before the keystore slot. Its size does not change.

    Raises:
        InvalidRuntimeError: The library is not an ELF file, or has no `.rasp_config` section.
        ValueError: The program is not PROGRAM_SIZE bytes, or the section is too small to hold the config, the
            program and the share.
    """
    space = _space(library)
    if len(program) != key_schedule.PROGRAM_SIZE:
        raise ValueError(f"the fold program must be {key_schedule.PROGRAM_SIZE} bytes")
    if space.size < key_schedule.PROGRAM_SIZE + key_schedule.KEY_SIZE + 1:
        raise ValueError(f"the {ELF_SECTION} section is too small for a fold program")
    written = bytearray(library)
    start = (
        space.offset + space.size - key_schedule.PROGRAM_SIZE - key_schedule.KEY_SIZE
    )
    written[start : start + key_schedule.PROGRAM_SIZE] = program
    return bytes(written)


def write_keystore(library: bytes, share: bytes) -> bytes:
    """Writes the keystore share into a runtime library, after the fold program.

    Args:
        library: The content of a `librasp.so`, with its config and fold program already written.
        share: The 32-byte share (key_schedule.root_key's compensating value).

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

    The region holds the config JSON, its zero padding and the fold program, and the key schedule folds its digest
    into the root key.

    Args:
        library: The content of a `librasp.so`.

    Returns:
        The section's bytes before the trailing 32, the config JSON, the padding and the fold program.

    Raises:
        InvalidRuntimeError: The library is not an ELF file, or has no `.rasp_config` section.
        ValueError: The section is too small to hold a config and a share.
    """
    space = _space(library)
    if space.size < key_schedule.KEY_SIZE + 1:
        raise ValueError(f"the {ELF_SECTION} section is too small for a keystore share")
    return library[space.offset : space.offset + space.size - key_schedule.KEY_SIZE]


def program(library: bytes) -> bytes:
    """Reads the fold program of a runtime library: the bytes between the config's padding and the keystore share.

    Args:
        library: The content of a `librasp.so`.

    Returns:
        The program's PROGRAM_SIZE encoded bytes.

    Raises:
        InvalidRuntimeError: The library is not an ELF file, or has no `.rasp_config` section.
        ValueError: The section is too small to hold the config, the program and the share.
    """
    space = _space(library)
    if space.size < key_schedule.PROGRAM_SIZE + key_schedule.KEY_SIZE + 1:
        raise ValueError(f"the {ELF_SECTION} section is too small for a fold program")
    start = (
        space.offset + space.size - key_schedule.PROGRAM_SIZE - key_schedule.KEY_SIZE
    )
    return library[start : start + key_schedule.PROGRAM_SIZE]


def keystore_span(library: bytes) -> tuple[int, int]:
    """Returns where the keystore share lives in the library file: its offset and length.

    The fold program's range decoys must avoid these bytes: they are written after the fold's
    inputs are gathered, so a range over them would digest different bytes at pack time than the
    runtime reads.

    Args:
        library: The content of a `librasp.so`.

    Returns:
        The share's file offset and its length, KEY_SIZE.

    Raises:
        InvalidRuntimeError: The library is not an ELF file, or has no `.rasp_config` section.
        ValueError: The section is too small to hold a config and a share.
    """
    space = _space(library)
    if space.size < key_schedule.KEY_SIZE + 1:
        raise ValueError(f"the {ELF_SECTION} section is too small for a keystore share")
    return space.offset + space.size - key_schedule.KEY_SIZE, key_schedule.KEY_SIZE


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


def section_region(library: bytes, name: str) -> bytes:
    """Reads one named section of a runtime library, a decoy input of the key schedule's fold.

    Args:
        library: The content of a `librasp.so`.
        name: The section's name, such as `.rela.dyn`.

    Returns:
        The section's bytes.

    Raises:
        InvalidRuntimeError: The library is not an ELF file, or has no such section.
    """
    return bytes(_elf_section(library, name).content)


def fold_sections(library: bytes) -> tuple[str, ...]:
    """Returns the library's section names the fold program can name as decoy inputs.

    Args:
        library: The content of a `librasp.so`.

    Returns:
        The library's section names, in the key schedule's table's order.

    Raises:
        InvalidRuntimeError: The library is not an ELF file.
    """
    elf = _elf(library)
    names = {str(section.name) for section in elf.sections}
    return tuple(name for name in key_schedule.SECTION_NAMES if name in names)


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


def _elf(library: bytes) -> lief.ELF.Binary:
    """Returns the parsed ELF of the library, or raises.

    Args:
        library: The content of a `librasp.so`.

    Returns:
        The parsed binary.

    Raises:
        InvalidRuntimeError: The library is not an ELF file.
    """
    elf = lief.ELF.parse(io.BytesIO(library))
    if elf is None:
        raise errors.InvalidRuntimeError("the runtime library is not an ELF file")
    return elf


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
    section = _elf(library).get_section(name)
    if section is None:
        raise errors.InvalidRuntimeError(f"the runtime library has no {name} section")
    return section
