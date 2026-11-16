"""Tests for the in-process splitter, over a small committed DEX fixture."""

import collections.abc
import logging
import pathlib
import re

import pytest
from dexsplit.strategies import original
from dexsplit.strategies import package_affinity

from dexsplit import _dex
from dexsplit import class_sets
from dexsplit import splitter
from dexsplit import strategy

_SAMPLE = pathlib.Path(__file__).parent / "fixtures" / "sample.dex"
_PACKAGE = "com.android.insecurebankv2"


def _sets() -> tuple[class_sets.ClassSet, ...]:
    return (
        class_sets.ClassSet("business", package_affinity.PackageAffinity()),
        class_sets.ClassSet("framework", original.Original()),
    )


def _assignments() -> tuple[class_sets.Assignment, ...]:
    return (
        class_sets.Assignment(f"{_PACKAGE}.**", "business"),
        class_sets.Assignment("**", "framework"),
    )


def _split() -> splitter.Result:
    entries = {"classes.dex": _SAMPLE.read_bytes()}
    return splitter.split(entries, _sets(), _assignments())


def testSplit_whenRun_sortsBusinessAndFrameworkBySet() -> None:
    result = _split()

    business = [output for output in result.files if output.set_name == "business"]
    framework = [output for output in result.files if output.set_name == "framework"]
    business_classes = [cls for output in business for cls in output.classes]
    framework_classes = [cls for output in framework for cls in output.classes]

    assert len(business_classes) == 6
    assert len(framework_classes) == 6
    assert (
        all(cls.startswith("Lcom/android/insecurebankv2/") for cls in business_classes)
        is True
    )
    assert all(cls.startswith("Landroid/support/") for cls in framework_classes) is True


def testSplit_whenRun_producesValidDexFiles() -> None:
    for output in _split().files:
        reread = _dex.Model.read(output.data)
        assert len(reread.class_descriptors) == len(output.classes)


def testSplit_whenNoDexEntries_raisesSplitError() -> None:
    with pytest.raises(splitter.SplitError, match="no classes"):
        splitter.split({}, _sets(), _assignments())


def testSplit_whenEntriesRepeatAClass_keepsItOnceInMultidexOrder() -> None:
    data = _SAMPLE.read_bytes()
    entries = {"classes2.dex": data, "classes.dex": data}

    result = splitter.split(entries, _sets(), _assignments())

    total_classes = sum(len(output.classes) for output in result.files)
    assert total_classes == 12


class _FixedPlan:
    """A strategy that returns the groups it was given, whatever the classes of the set."""

    def __init__(self, groups: collections.abc.Sequence[strategy.Group]) -> None:
        self._groups = groups

    def plan(
        self, classes: strategy.Classes
    ) -> collections.abc.Sequence[strategy.Group]:
        return self._groups


def _split_with_plan(groups: collections.abc.Sequence[strategy.Group]) -> None:
    sets = (class_sets.ClassSet("all", _FixedPlan(groups)),)
    assignments = (class_sets.Assignment("**", "all"),)
    splitter.split({"classes.dex": _SAMPLE.read_bytes()}, sets, assignments)


def _descriptors() -> list[str]:
    return splitter._read_classes([_SAMPLE.read_bytes()]).descriptors


def testSplit_whenAStrategyReturnsAnEmptyGroup_raisesStrategyError() -> None:
    with pytest.raises(
        strategy.StrategyError, match="set all: the strategy returned an empty group"
    ):
        _split_with_plan([strategy.Group(())])


def testSplit_whenAStrategyReturnsAnEmptyBlock_raisesStrategyError() -> None:
    with pytest.raises(
        strategy.StrategyError, match="set all: the strategy returned an empty block"
    ):
        _split_with_plan([strategy.Group((strategy.Block(()),))])


def testSplit_whenAStrategyReturnsAClassOutsideTheSet_raisesStrategyError() -> None:
    with pytest.raises(
        strategy.StrategyError,
        match="set all: the strategy returned class id 99, which is not in the set",
    ):
        _split_with_plan([strategy.Group.of_classes([99])])


def testSplit_whenAStrategyReturnsAClassTwice_raisesStrategyError() -> None:
    first = re.escape(_descriptors()[0])

    with pytest.raises(
        strategy.StrategyError, match=f"set all: the strategy returned {first} twice"
    ):
        _split_with_plan([strategy.Group.of_classes([0, 0])])


def testSplit_whenAStrategyLeavesAClassOut_raisesStrategyError() -> None:
    last = re.escape(_descriptors()[11])

    with pytest.raises(
        strategy.StrategyError,
        match=f"set all: the strategy left out 1 classes, such as {last}",
    ):
        _split_with_plan([strategy.Group.of_classes(range(11))])


def testOrderedNames_whenThereAreTenOrMoreEntries_ordersThemByNumber() -> None:
    entries = {"classes10.dex": b"", "classes2.dex": b"", "classes.dex": b""}

    assert splitter._ordered_names(entries) == [
        "classes.dex",
        "classes2.dex",
        "classes10.dex",
    ]


def _links(buffers: list[bytes]) -> list[dict[int, int]]:
    classes = splitter._read_classes(buffers)
    class_ids = range(len(classes.descriptors))
    weights = dict.fromkeys(strategy.LinkKind, 1)
    graph = splitter._App(buffers, classes).links(class_ids, weights)
    return [dict(graph.neighbours(class_id)) for class_id in class_ids]


def testLinks_whenEntriesRepeatAClass_countsItsLinksOnce() -> None:
    data = _SAMPLE.read_bytes()

    once = _links([data])
    twice = _links([data, data])

    assert any(len(neighbours) > 0 for neighbours in once) is True
    assert twice == once


class _OverflowingModel:
    """A `_dex.Model` whose `write` always reports a pool overflow."""

    def __init__(self, version: int) -> None:
        self.version = version

    def copy_class(self, src: _dex.Model, descriptor: str) -> None:
        pass

    def write(self) -> bytes:
        raise _dex.PoolOverflowError("65536 types; a DEX file holds at most 65535")


def testEncode_whenSeveralClassesOverflowAPool_returnsNone(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    classes = splitter._read_classes([_SAMPLE.read_bytes()])
    monkeypatch.setattr(_dex, "Model", _OverflowingModel)

    assert splitter._encode(classes, [0, 1]) is None


def testEncode_whenOneClassOverflowsAPool_raisesSplitError(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    classes = splitter._read_classes([_SAMPLE.read_bytes()])
    monkeypatch.setattr(_dex, "Model", _OverflowingModel)

    with pytest.raises(splitter.SplitError, match="write failed: 65536 types"):
        splitter._encode(classes, [0])


def testWriteGroup_whenTheGroupGoesOverALimit_cutsItUntilEveryPartFits(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    classes = splitter._read_classes([_SAMPLE.read_bytes()])
    encode = splitter._encode

    def encode_at_most_four(
        classes: splitter._Classes, class_ids: collections.abc.Sequence[int]
    ) -> bytes | None:
        if len(class_ids) > 4:
            return None
        return encode(classes, class_ids)

    monkeypatch.setattr(splitter, "_encode", encode_at_most_four)
    outputs: list[splitter.OutputDex] = []

    splitter._write_group(
        outputs, "business", strategy.Group.of_classes(range(12)), classes
    )

    assert [len(output.classes) for output in outputs] == [3, 3, 3, 3]
    assert [cls for output in outputs for cls in output.classes] == classes.descriptors
    for output in outputs:
        assert _dex.Model.read(output.data).class_descriptors == list(output.classes)


def testCut_whenANamedBlockIsCut_warnsWithItsName(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.WARNING):
        first, second = splitter._cut([strategy.Block((0, 1, 2, 3), "package Lcom/a")])

    assert first == [strategy.Block((0, 1), "package Lcom/a")]
    assert second == [strategy.Block((2, 3), "package Lcom/a")]
    assert [record.getMessage() for record in caplog.records] == [
        "package Lcom/a goes over a 64K limit of the DEX format, so it is cut into two DEX files"
    ]


def testCut_whenAnUnnamedBlockIsCut_doesNotWarn(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.WARNING):
        splitter._cut([strategy.Block((0, 1, 2, 3))])

    assert caplog.records == []


def testCut_whenSeveralBlocks_cutsAtTheBoundaryNearestTheMiddleWithoutWarning(
    caplog: pytest.LogCaptureFixture,
) -> None:
    blocks = [
        strategy.Block((0,), "package La"),
        strategy.Block((1, 2), "package Lb"),
        strategy.Block((3, 4, 5), "package Lc"),
    ]

    with caplog.at_level(logging.WARNING):
        first, second = splitter._cut(blocks)

    assert first == blocks[:2]
    assert second == blocks[2:]
    assert caplog.records == []
