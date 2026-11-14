"""Tests for the strategy that groups the classes by package and by the links between packages."""

import pytest
from dexsplit.strategies import package_affinity

from dexsplit import strategy
from tests.dexsplit import fake_app


def testPackageAffinityPlan_whenPackagesAreLinked_putsLinkedPackagesInOneGroup() -> (
    None
):
    classes = fake_app.make_classes(
        ["La/A;", "Lc/C;", "Lb/B;", "Ld/D;"], edges=[(0, 2), (2, 0), (1, 3), (3, 1)]
    )

    groups = package_affinity.PackageAffinity(cap=2).plan(classes)

    assert [group.class_ids for group in groups] == [[0, 2], [1, 3]]


def testPackageAffinityPlan_whenAGroupHoldsSeveralPackages_makesOneNamedBlockPerPackage() -> (
    None
):
    classes = fake_app.make_classes(["La/A1;", "La/A2;", "Lb/B;"], edges=[(0, 2)])

    groups = package_affinity.PackageAffinity().plan(classes)

    assert groups == [
        strategy.Group(
            (strategy.Block((0, 1), "package La"), strategy.Block((2,), "package Lb"))
        )
    ]


def testPackageAffinityPlan_whenTheSetIsEmpty_returnsNoGroupsWithoutBuildingLinks() -> (
    None
):
    app = fake_app.FakeApp(["La/A;"])

    groups = package_affinity.PackageAffinity().plan(strategy.Classes([], app))

    assert groups == []
    assert app.asked_weights == []


def testPackageAffinityInit_whenCapIsZero_raisesValueError() -> None:
    with pytest.raises(ValueError, match="cap must be >= 1"):
        package_affinity.PackageAffinity(cap=0)
