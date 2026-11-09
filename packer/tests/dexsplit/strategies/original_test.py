"""Tests for the strategy that keeps the classes in the DEX files they came from."""

import pytest
from dexsplit.strategies import original

from dexsplit import strategy
from tests.dexsplit import fake_app


def testOriginalPlan_whenClassesComeFromTwoDexFiles_makesOneGroupPerDexFile() -> None:
    classes = fake_app.make_classes(["La/A;", "Lb/B;", "Lc/C;"], sources=[0, 1, 0])

    groups = original.Original().plan(classes)

    assert groups == [strategy.Group.of_classes([0, 2]), strategy.Group.of_classes([1])]


def testOriginalPlan_whenMoreDexFilesThanMaxFiles_mergesTheSmallestGroups() -> None:
    classes = fake_app.make_classes(
        [f"Lp/C{index};" for index in range(7)], sources=[0, 0, 0, 1, 2, 2, 3]
    )

    groups = original.Original(max_files=2).plan(classes)

    assert [group.class_ids for group in groups] == [[0, 1, 2, 6], [4, 5, 3]]


def testOriginalInit_whenMaxFilesIsZero_raisesValueError() -> None:
    with pytest.raises(ValueError, match="max_files must be >= 1"):
        original.Original(max_files=0)
