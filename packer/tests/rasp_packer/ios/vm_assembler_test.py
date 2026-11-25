"""Tests of the guard VM program the packer embeds in the iOS runtime binary.

The program the packer emits (vm_assembler.guard_program) must match, byte for byte, the default program the runtime
links and the interpreter runs (runtime/ios/src/selfdecrypt/guard.cpp and vm_ops.h). This test locks that parity and
checks the program is well-formed, so a change on one side that is not mirrored on the other fails here rather than on a
device.
"""

from rasp_packer.ios import vm_assembler

# The default guard program as the runtime links it in ios/src/selfdecrypt/guard.cpp. Kept here as the ground truth the
# packer must reproduce; if the runtime's program changes, this constant and vm_assembler must change together.
_RUNTIME_GUARD_PROGRAM = bytes([0x23, 0x35, 0x47, 0x7D, 0x08, 0x59, 0x8F, 0x0A, 0x6B, 0x91, 0x11])

# The opcode encoding, mirroring OpCode in vm_ops.h.
_HALT = 0x11
_DERIVE_KEY = 0x23
_DECRYPT_BLOB = 0x35
_CHECK_MARKER = 0x47
_SET_INTACT = 0x59
_SET_TAMPERED = 0x6B
_JUMP_IF_NO_MATCH = 0x7D
_JUMP = 0x8F
_KILL = 0x91

_ONE_BYTE_OPS = frozenset({_HALT, _DERIVE_KEY, _DECRYPT_BLOB, _CHECK_MARKER, _SET_INTACT, _SET_TAMPERED, _KILL})
_TWO_BYTE_OPS = frozenset({_JUMP_IF_NO_MATCH, _JUMP})
_ALL_OPS = _ONE_BYTE_OPS | _TWO_BYTE_OPS


def testGuardProgram_whenEmitted_matchesTheRuntimeDefaultProgramByteForByte() -> None:
    program = vm_assembler.guard_program()

    assert program == _RUNTIME_GUARD_PROGRAM


def testGuardProgram_whenEmitted_derivesDecryptsAndChecksBeforeAnyBranch() -> None:
    program = vm_assembler.guard_program()

    assert program[0] == _DERIVE_KEY
    assert program[1] == _DECRYPT_BLOB
    assert program[2] == _CHECK_MARKER


def testGuardProgram_whenEmitted_containsTheKillAndHaltOpcodes() -> None:
    program = vm_assembler.guard_program()

    assert _KILL in program
    assert _HALT in program


def testGuardProgram_whenEmitted_hasOnlyKnownOpcodesAndInRangeBranchTargets() -> None:
    program = vm_assembler.guard_program()

    index = 0
    seen_opcodes: list[int] = []
    while index < len(program):
        opcode = program[index]
        assert opcode in _ALL_OPS
        seen_opcodes.append(opcode)
        if opcode in _TWO_BYTE_OPS:
            assert index + 1 < len(program)
            target = program[index + 1]
            assert target < len(program)
            index += 2
        else:
            index += 1

    assert len(seen_opcodes) > 0
