"""Tests for the editable DEX model, over a small committed DEX fixture."""

import pathlib

import pytest

from dexsplit import _dex

_SAMPLE = pathlib.Path(__file__).parent / "fixtures" / "sample.dex"
_A_CLASS = "Lcom/android/insecurebankv2/BuildConfig;"


def _sample() -> _dex.Model:
    return _dex.Model.read(_SAMPLE.read_bytes())


def testRead_whenValidDex_readsEveryClass() -> None:
    model = _sample()

    assert len(model.class_descriptors) == 12
    assert _A_CLASS in model.class_descriptors


def testRead_whenValidDex_keepsTheDexVersion() -> None:
    assert _sample().version == 35


def testPoolStats_whenValidDex_countsTheTypesAndMethods() -> None:
    stats = _sample().pool_stats

    assert stats.types > 0
    assert stats.methods > 0


def testCopyClass_whenCopied_appearsInTheDestinationAndWritesBack() -> None:
    source = _sample()
    destination = _dex.Model(35)

    destination.copy_class(source, _A_CLASS)

    assert destination.class_descriptors == [_A_CLASS]
    reread = _dex.Model.read(destination.write())
    assert reread.class_descriptors == [_A_CLASS]


def testCopyClass_whenDestinationAlreadyHasTheClass_raisesValueError() -> None:
    source = _sample()
    destination = _dex.Model(35)
    destination.copy_class(source, _A_CLASS)

    with pytest.raises(ValueError, match="already has class"):
        destination.copy_class(source, _A_CLASS)


def testCopyClass_whenSourceHasNoSuchClass_raisesValueError() -> None:
    destination = _dex.Model(35)

    with pytest.raises(ValueError, match="source has no class"):
        destination.copy_class(_sample(), "Lno/such/Class;")


def testWrite_whenReadBack_givesTheSameClasses() -> None:
    model = _sample()

    reread = _dex.Model.read(model.write())

    assert sorted(reread.class_descriptors) == sorted(model.class_descriptors)
