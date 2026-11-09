"""Tests for what a strategy is given and what it returns: the classes of a set, groups and blocks."""

from dexsplit import strategy
from tests.dexsplit import fake_app


def testGroupOfClasses_whenGivenClasses_makesOneUnnamedBlockPerClass() -> None:
    group = strategy.Group.of_classes([3, 1, 2])

    assert group == strategy.Group(
        (strategy.Block((3,)), strategy.Block((1,)), strategy.Block((2,)))
    )


def testGroupOfPackages_whenClassesOfAPackageAreTogether_makesOneNamedBlockPerPackage() -> (
    None
):
    descriptors = ["La/A1;", "La/A2;", "Lb/B;"]

    group = strategy.Group.of_packages([0, 1, 2], descriptors)

    assert group == strategy.Group(
        (strategy.Block((0, 1), "package La"), strategy.Block((2,), "package Lb"))
    )


def testGroupOfPackages_whenAPackageComesBackLater_makesABlockPerRun() -> None:
    descriptors = ["La/A1;", "Lb/B;", "La/A2;"]

    group = strategy.Group.of_packages([0, 1, 2], descriptors)

    assert [block.class_ids for block in group.blocks] == [(0,), (1,), (2,)]


def testGroupClassIds_whenTheGroupHasSeveralBlocks_listsEveryClassInWriteOrder() -> (
    None
):
    group = strategy.Group((strategy.Block((4, 2)), strategy.Block((7,))))

    assert group.class_ids == [4, 2, 7]


def testClassesIds_whenCreated_returnsTheClassesOfTheSet() -> None:
    classes = strategy.Classes([1, 2], fake_app.FakeApp(["La/A;", "Lb/B;", "Lc/C;"]))

    assert classes.ids == [1, 2]


def testClassesDescriptors_whenCreated_returnsTheDescriptorsOfTheWholeApp() -> None:
    classes = strategy.Classes([1], fake_app.FakeApp(["La/A;", "Lb/B;"]))

    assert classes.descriptors == ["La/A;", "Lb/B;"]


def testClassesSourceDex_whenAskedForAClass_returnsTheDexFileItComesFrom() -> None:
    classes = fake_app.make_classes(["La/A;", "Lb/B;"], sources=[0, 3])

    assert classes.source_dex(1) == 3


def testClassesLinks_whenNoWeightsAreGiven_weighsEveryKindOne() -> None:
    app = fake_app.FakeApp(["La/A;", "Lb/B;"])

    strategy.Classes([0, 1], app).links()

    assert app.asked_weights == [dict.fromkeys(strategy.LinkKind, 1)]


def testClassesLinks_whenSomeWeightsAreGiven_keepsOneForTheOtherKinds() -> None:
    app = fake_app.FakeApp(["La/A;", "Lb/B;"])

    strategy.Classes([0, 1], app).links({strategy.LinkKind.CALL: 3})

    expected = dict.fromkeys(strategy.LinkKind, 1)
    expected[strategy.LinkKind.CALL] = 3
    assert app.asked_weights == [expected]


def testClassesLinks_whenClassesAreLinked_returnsTheGraphOfTheSet() -> None:
    classes = fake_app.make_classes(["La/A;", "Lb/B;", "Lc/C;"], edges=[(0, 2)])

    graph = classes.links()

    assert dict(graph.neighbours(0)) == {2: 1}
    assert dict(graph.neighbours(1)) == {}
