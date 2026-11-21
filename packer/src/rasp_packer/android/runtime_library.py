"""Reads the sections of the Android runtime library, `librasp.so`, that the key schedule digests."""

import io

import lief

from rasp_packer import errors
from rasp_packer.android import key_schedule

# The name of the library's executable code section, which the key schedule binds the payload to.
TEXT_SECTION = ".text"


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
        name: The section's name, such as `.rodata`.

    Returns:
        The section.

    Raises:
        InvalidRuntimeError: The library is not an ELF file, or has no such section.
    """
    section = _elf(library).get_section(name)
    if section is None:
        raise errors.InvalidRuntimeError(f"the runtime library has no {name} section")
    return section
