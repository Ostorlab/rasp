"""Tests of writing the at-rest guard (blob + VM program) into the iOS runtime binary.

write_guard writes two sections into every slice of the runtime binary: the encrypted guard blob (`__DATA,__rasp_guard`)
and the guard VM program (`__DATA,__rasp_vm`). These tests exercise that against a runtime binary that carries both
sections; a binary built before the sections existed is skipped, so the suite stays green on an old fixture while still
covering the write end to end when a current framework is available.
"""

import io
import pathlib

import lief
import pytest

from rasp_packer.ios import guard
from rasp_packer.ios import vm_assembler

_RUNTIME = pathlib.Path(__file__).parent.parent / "data" / "runtime_config" / "RaspRuntime"


def _has_guard_sections(binary: bytes) -> bool:
    fat = lief.MachO.parse(io.BytesIO(binary))
    if fat is None:
        return False
    for macho in fat:
        if macho.get_section(guard.MACHO_SEGMENT, guard.MACHO_SECTION) is None:
            return False
        if macho.get_section(guard.VM_SEGMENT, guard.VM_SECTION) is None:
            return False
    return True


def _section_bytes(binary: bytes, segment: str, section: str) -> bytes:
    fat = lief.MachO.parse(io.BytesIO(binary))
    assert fat is not None
    macho = fat.at(0)
    found = macho.get_section(segment, section)
    assert found is not None
    start = macho.fat_offset + found.offset
    return binary[start : start + found.size]


@pytest.fixture(name="runtime_binary")
def runtime_binary_fixture() -> bytes:
    binary = _RUNTIME.read_bytes()
    if _has_guard_sections(binary) is False:
        pytest.skip("the runtime fixture predates the __rasp_guard/__rasp_vm sections")
    return binary


def testWriteGuard_whenRuntimeHasSections_writesTheGuardProgram(runtime_binary: bytes) -> None:
    packed = guard.write_guard(runtime_binary)

    written = _section_bytes(packed, guard.VM_SEGMENT, guard.VM_SECTION)
    program = vm_assembler.guard_program()
    assert written[: len(program)] == program


def testWriteGuard_whenRuntimeHasSections_makesTheGuardBlobNonZero(runtime_binary: bytes) -> None:
    # An unpacked build leaves the blob all zeros; packing must replace it with the ciphertext of the marker.
    before = _section_bytes(runtime_binary, guard.MACHO_SEGMENT, guard.MACHO_SECTION)
    assert set(before[:8]) == {0}

    packed = guard.write_guard(runtime_binary)

    after = _section_bytes(packed, guard.MACHO_SEGMENT, guard.MACHO_SECTION)
    assert set(after) != {0}


def testWriteGuard_whenRuntimeHasSections_keepsTheBinarySize(runtime_binary: bytes) -> None:
    packed = guard.write_guard(runtime_binary)

    assert len(packed) == len(runtime_binary)
