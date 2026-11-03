"""Tests for the in-process splitter, over a small committed DEX fixture."""

import pathlib

import pytest
from dexsplit.strategies import original
from dexsplit.strategies import package_affinity

from dexsplit import _dex
from dexsplit import class_sets
from dexsplit import splitter

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
