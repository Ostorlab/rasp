"""The guard VM program the packer embeds in the iOS runtime binary, in the `__DATA,__rasp_vm` section.

The at-rest guard's decision runs as byte-code on a tiny interpreter in the runtime (ios/src/selfdecrypt/vm.cpp), not as
native code. This module emits that byte-code so the packer can write it into the binary. The encoding is fixed in this
build and mirrors runtime/ios/src/selfdecrypt/vm_ops.h; the two must stay in step.

The program drives the native guard steps in order and takes the tamper branch, which ends the process, when the marker
does not come back:

    [0] derive key
    [1] decrypt blob
    [2] check marker
    [3] jump-if-no-match -> 8
    [5] set intact
    [6] jump -> 10
    [8] set tampered
    [9] kill
    [10] halt
"""

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

# Absolute byte offsets of the two branch targets within the program below.
_TAMPER_BLOCK = 8
_HALT_BLOCK = 10


def guard_program() -> bytes:
    """The byte-code of the guard program the runtime's VM runs.

    Returns:
        The fixed guard program, as the `__DATA,__rasp_vm` section must contain it. Its layout and the branch offsets
        match the default program linked into the runtime (ios/src/selfdecrypt/guard.cpp).
    """
    return bytes(
        [
            _DERIVE_KEY,
            _DECRYPT_BLOB,
            _CHECK_MARKER,
            _JUMP_IF_NO_MATCH,
            _TAMPER_BLOCK,
            _SET_INTACT,
            _JUMP,
            _HALT_BLOCK,
            _SET_TAMPERED,
            _KILL,
            _HALT,
        ]
    )
