"""Tests for the two strategies, over a fake app that supplies classes and links directly."""

import collections.abc

import pytest
from dexsplit.strategies import original
from dexsplit.strategies import package_affinity

from dexsplit import partition
from dexsplit import strategy


class _FakeApp:
    """A `strategy.App` with no app behind it: the test gives the classes and their links.

    Each given edge is one link, counted with weight 1 whatever its kind. `asked_weights` records
    the weights of every `links` call.
    """

    def __init__(
        self,
        descriptors: collections.abc.Sequence[str],
        sources: collections.abc.Sequence[int] | None = None,
        edges: collections.abc.Iterable[tuple[int, int]] = (),
    ) -> None:
        self._descriptors = descriptors
        self._sources = [0] * len(descriptors) if sources is None else sources
        self._edges = list(edges)
        self.asked_weights: list[dict[strategy.LinkKind, int]] = []

    @property
    def descriptors(self) -> collections.abc.Sequence[str]:
        return self._descriptors

    def source_dex(self, class_id: int) -> int:
        return self._sources[class_id]

    def links(
        self,
        class_ids: collections.abc.Sequence[int],
        weights: collections.abc.Mapping[strategy.LinkKind, int],
    ) -> partition.AffinityGraph:
        self.asked_weights.append(dict(weights))
        members = set(class_ids)
        graph = partition.AffinityGraph(len(self._descriptors))
        for first, second in self._edges:
            if first in members and second in members:
                graph.add_edge(first, second)
        return graph


def _make(
    descriptors: collections.abc.Sequence[str],
    sources: collections.abc.Sequence[int] | None = None,
    edges: collections.abc.Iterable[tuple[int, int]] = (),
) -> strategy.Classes:
    return strategy.Classes(
        list(range(len(descriptors))), _FakeApp(descriptors, sources, edges)
    )


def testOriginalPlan_whenClassesComeFromTwoDexFiles_makesOneGroupPerDexFile() -> None:
    classes = _make(["La/A;", "Lb/B;", "Lc/C;"], sources=[0, 1, 0])

    groups = original.Original().plan(classes)

    assert groups == [strategy.Group.of_classes([0, 2]), strategy.Group.of_classes([1])]


def testOriginalPlan_whenMoreDexFilesThanMaxFiles_mergesTheSmallestGroups() -> None:
    classes = _make(
        [f"Lp/C{index};" for index in range(7)], sources=[0, 0, 0, 1, 2, 2, 3]
    )

    groups = original.Original(max_files=2).plan(classes)

    assert [group.class_ids for group in groups] == [[0, 1, 2, 6], [4, 5, 3]]


def testOriginalInit_whenMaxFilesIsZero_raisesValueError() -> None:
    with pytest.raises(ValueError, match="max_files must be >= 1"):
        original.Original(max_files=0)


def testPackageAffinityPlan_whenPackagesAreLinked_putsLinkedPackagesInOneGroup() -> (
    None
):
    classes = _make(
        ["La/A;", "Lc/C;", "Lb/B;", "Ld/D;"], edges=[(0, 2), (2, 0), (1, 3), (3, 1)]
    )

    groups = package_affinity.PackageAffinity(cap=2).plan(classes)

    assert [group.class_ids for group in groups] == [[0, 2], [1, 3]]


def testPackageAffinityPlan_whenAGroupHoldsSeveralPackages_makesOneNamedBlockPerPackage() -> (
    None
):
    classes = _make(["La/A1;", "La/A2;", "Lb/B;"], edges=[(0, 2)])

    groups = package_affinity.PackageAffinity().plan(classes)

    assert groups == [
        strategy.Group(
            (strategy.Block((0, 1), "package La"), strategy.Block((2,), "package Lb"))
        )
    ]


def testPackageAffinityPlan_whenTheSetIsEmpty_returnsNoGroupsWithoutBuildingLinks() -> (
    None
):
    app = _FakeApp(["La/A;"])

    groups = package_affinity.PackageAffinity().plan(strategy.Classes([], app))

    assert groups == []
    assert app.asked_weights == []


def testPackageAffinityInit_whenCapIsZero_raisesValueError() -> None:
    with pytest.raises(ValueError, match="cap must be >= 1"):
        package_affinity.PackageAffinity(cap=0)
