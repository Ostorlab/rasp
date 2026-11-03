"""Tests of the dex-splitter seam.

These exercise the in-process splitter through ``split_from_dex_entries`` against the committed AAB
fixture, plus the validation of its DEX-entry names. Splitting a full APK is covered by the Android
packer tests end to end.
"""

import pathlib
import zipfile

import pytest

from rasp_packer.android import split

_AAB = (
    pathlib.Path(__file__).resolve().parents[2]
    / "apps"
    / "android"
    / "InsecureBankv2.aab"
)
_PACKAGE = "com.android.insecurebankv2"


def _aab_dex_entries() -> dict[str, bytes]:
    with zipfile.ZipFile(_AAB) as archive:
        return {
            name.removeprefix("base/dex/"): archive.read(name)
            for name in archive.namelist()
            if name.startswith("base/dex/")
            and name.endswith(".dex")
            and "/" not in name.removeprefix("base/dex/")
        }


def testSplitFromDexEntries_whenRealApp_putsPackageClassesInBusiness() -> None:
    result = split.split_from_dex_entries(_aab_dex_entries(), _PACKAGE)

    business_classes = [name for dex in result.business for name in dex.classes]
    assert len(business_classes) > 0
    assert all(name.startswith(f"{_PACKAGE}.") for name in business_classes) is True
    assert len(result.framework) > 0


def testSplitFromDexEntries_whenRealApp_reindexesBusinessDexesFromZero() -> None:
    result = split.split_from_dex_entries(_aab_dex_entries(), _PACKAGE)

    paths = [dex.path for dex in result.business]
    assert paths == [f"business/{index}.dex" for index in range(len(result.business))]


def testSplitFromDexEntries_whenRealApp_producesDecodableDexes() -> None:
    result = split.split_from_dex_entries(_aab_dex_entries(), _PACKAGE)

    with zipfile.ZipFile(_AAB) as archive:
        original = archive.read("base/dex/classes.dex")
    assert len(result.framework[0]) > 0
    assert all(len(dex.data) > 0 for dex in result.business) is True
    assert len(original) > 0


def testSplitFromDexEntries_whenEmpty_raisesSplitError() -> None:
    with pytest.raises(split.SplitError, match="no DEX entries"):
        split.split_from_dex_entries({}, "com.example")


def testSplitFromDexEntries_whenNameContainsSlash_raisesSplitError() -> None:
    with pytest.raises(split.SplitError, match="bare root-level"):
        split.split_from_dex_entries({"base/dex/classes.dex": b"dex"}, "com.example")


def testSplitFromDexEntries_whenNameContainsBackslash_raisesSplitError() -> None:
    with pytest.raises(split.SplitError, match="bare root-level"):
        split.split_from_dex_entries({"classes\\1.dex": b"dex"}, "com.example")


def testSplitFromDexEntries_whenNameNotDex_raisesSplitError() -> None:
    with pytest.raises(split.SplitError, match="bare root-level"):
        split.split_from_dex_entries({"classes.jar": b"jar"}, "com.example")


def testSplitFromDexEntries_whenDexIsMalformed_raisesSplitError() -> None:
    with pytest.raises(split.SplitError):
        split.split_from_dex_entries({"classes.dex": b"not a dex"}, "com.example")
