"""Boundary tests for the fold schedule's byte ranges."""

import random

import pytest

from rasp_packer.android import key_schedule


def testRangeOffset_whenEveryOffsetOverlapsTheKeystore_raisesValueError() -> None:
    with pytest.raises(ValueError, match="no range offset"):
        key_schedule._range_offset(random.Random(0), 64, 128, ((0, 128),))
