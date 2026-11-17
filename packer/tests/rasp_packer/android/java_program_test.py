"""Tests of the Java arm's programs: building, encoding, decoding, and the reference share.

The reference chain here is the one the stub executes on a real runtime (runtime/android/stub), over the classes
the packer can predict: the core hierarchies the platform contract fixes and the stub's own class. The native
runtime tests (runtime/tests/android/payload) share the armed vectors, so a disagreement between the packer's
prediction and the device's derivation shows up as a test failure on one side or the other.
"""

import random

import pytest

from rasp_packer.android import java_program
from rasp_packer.android import key_schedule


def testBuildProgram_whenGivenAGenerator_buildsPredictableSteps() -> None:
    program = java_program.build_program(random.Random(0))

    assert 4 <= len(program.steps) <= 7
    for step in program.steps:
        assert step.kind in (java_program.KIND_RESOLVE, java_program.KIND_SUPERS)
        if step.kind == java_program.KIND_RESOLVE:
            assert step.depth == 0
        else:
            assert step.name in java_program.CORE_STEPS
            assert 1 <= step.depth <= len(java_program.CORE_STEPS[step.name])


def testBuildProgram_whenGivenDifferentSeeds_buildsDifferentPrograms() -> None:
    programs = [java_program.build_program(random.Random(seed)) for seed in range(8)]

    assert len({java_program.encode_program(program) for program in programs}) > 1


def testEncodeDecode_whenGivenRandomPrograms_roundTrip() -> None:
    for seed in range(20):
        program = java_program.build_program(random.Random(seed))
        assert (
            java_program.decode_program(java_program.encode_program(program)) == program
        )


def testDecodeProgram_whenTheBlobIsTruncated_raisesProgramError() -> None:
    program = java_program.encode_program(java_program.build_program(random.Random(0)))
    for cut in (0, 1, 3, 5, len(program) - 1):
        with pytest.raises(java_program.ProgramError):
            java_program.decode_program(program[:cut])


def testDecodeProgram_whenAStepKindIsUnknown_raisesProgramError() -> None:
    blob = bytearray(
        java_program.encode_program(java_program.build_program(random.Random(1)))
    )
    blob[2] = 9
    with pytest.raises(java_program.ProgramError):
        java_program.decode_program(bytes(blob))


def testRunReference_whenGivenTheSameProgram_givesTheSameShare() -> None:
    program = java_program.build_program(random.Random(0))

    assert java_program.run_reference(program) == java_program.run_reference(program)
    assert len(java_program.run_reference(program)) == key_schedule.KEY_SIZE


def testRunReference_whenTheProgramDiffers_givesADifferentShare() -> None:
    one = java_program.build_program(random.Random(0))
    two = java_program.build_program(random.Random(1))

    assert java_program.run_reference(one) != java_program.run_reference(two)


def testRunReference_whenAStepIsReordered_givesADifferentShare() -> None:
    program = java_program.build_program(random.Random(0))
    reordered = java_program.Program(steps=program.steps[1:] + program.steps[:1])

    assert java_program.run_reference(reordered) != java_program.run_reference(program)


def testSupers_whenTheChainIsWalked_matchesThePlatformHierarchy() -> None:
    # The table must state what ART's getSuperclass chain yields on the platform the runtime supports; a step over
    # ArrayList three hops deep folds exactly the three names of its chain, in order.
    step = java_program.Step(
        kind=java_program.KIND_SUPERS, name="java.util.ArrayList", depth=3
    )

    assert java_program._step_input(step) == (
        b"java.util.AbstractList\0java.util.AbstractCollection\0java.lang.Object"
    )
    assert java_program.CORE_STEPS["java.util.ArrayList"] == (
        "java.util.AbstractList",
        "java.util.AbstractCollection",
        "java.lang.Object",
    )
