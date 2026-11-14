"""Tests for the editable DEX model, over a small committed DEX fixture."""

import pathlib
import typing

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


def testRead_whenBytesAreNotADexFile_raisesValueError() -> None:
    with pytest.raises(ValueError, match="not a DEX file"):
        _dex.Model.read(b"not a dex file")


def testRead_whenTheFileIsCutShort_raisesValueError() -> None:
    with pytest.raises(ValueError, match="File too small"):
        _dex.Model.read(_SAMPLE.read_bytes()[:64])


def testRead_whenTheVersionIs041_raisesValueError() -> None:
    data = bytearray(_SAMPLE.read_bytes())
    data[4:7] = b"041"

    with pytest.raises(ValueError, match="not supported"):
        _dex.Model.read(bytes(data))


def testWrite_whenTheModelIsEmpty_readsBackWithNoClasses() -> None:
    reread = _dex.Model.read(_dex.Model(35).write())

    assert reread.version == 35
    assert reread.class_descriptors == []


def testWrite_whenTheVersionDoesNotExist_raisesValueError() -> None:
    with pytest.raises(ValueError, match="unsupported DEX version 36"):
        _dex.Model(36).write()


def testPoolOverflowError_whenCaughtAsValueError_isCaught() -> None:
    assert issubclass(_dex.PoolOverflowError, ValueError) is True
    assert issubclass(_dex.VersionTooLowError, ValueError) is True


@pytest.mark.parametrize("step", [2, -1])
def testRead_whenBufferIsStrided_rejectsItBeforeParsing(step: int) -> None:
    data = memoryview(_SAMPLE.read_bytes())[::step]

    with pytest.raises(ValueError, match="contiguous"):
        _dex.Model.read(typing.cast(bytes, data))


def testRead_whenBufferIsContiguous_readsEveryClass() -> None:
    data = memoryview(_SAMPLE.read_bytes())

    model = _dex.Model.read(typing.cast(bytes, data))

    assert len(model.class_descriptors) == 12
    assert _A_CLASS in model.class_descriptors
