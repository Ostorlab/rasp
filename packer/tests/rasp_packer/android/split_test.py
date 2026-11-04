"""Tests of the dex-splitter seam.

These exercise the in-process splitter against the dex entries of the committed AAB fixture: through
``split_from_dex_entries``, with the validation of its DEX-entry names, and through ``split``, on an
APK built from the same entries.
"""

import logging
import pathlib
import zipfile

import pytest

from dexsplit import _dex
from rasp_packer.android import mapping
from rasp_packer.android import split

_AAB = (
    pathlib.Path(__file__).resolve().parents[2]
    / "apps"
    / "android"
    / "InsecureBankv2.aab"
)
_PACKAGE = "com.android.insecurebankv2"

# A class that is in the fixture's dex, directly in the app's package, and one in the same package not
# named in the mapping below, to show the whole package is protected and not only the named class.
_NAMED_CLASS = "com.android.insecurebankv2.CryptoClass"
_UNNAMED_CLASS = "com.android.insecurebankv2.DoLogin"


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

    for data in [*result.framework, *(dex.data for dex in result.business)]:
        _dex.Model.read(data)


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


def _write_apk(path: pathlib.Path, entries: dict[str, bytes]) -> None:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in entries.items():
            archive.writestr(name, data)


def testSplit_whenRealApk_splitsItsTopLevelDexEntries(tmp_path: pathlib.Path) -> None:
    entries = _aab_dex_entries()
    apk = tmp_path / "app.apk"
    _write_apk(
        apk, {**entries, "AndroidManifest.xml": b"manifest", "assets/classes.dex": b"x"}
    )

    result = split.split(apk, _PACKAGE)

    expected = split.split_from_dex_entries(entries, _PACKAGE)
    assert result.framework == expected.framework
    assert result.business == expected.business


def testSplit_whenADexEntryIsEncrypted_raisesSplitError(tmp_path: pathlib.Path) -> None:
    apk = tmp_path / "app.apk"
    _write_apk(apk, _aab_dex_entries())
    data = bytearray(apk.read_bytes())
    central = data.index(b"PK\x01\x02")
    data[central + 8] |= 0x01
    apk.write_bytes(bytes(data))

    with pytest.raises(split.SplitError, match="encrypted"):
        split.split(apk, _PACKAGE)


def testSplit_whenTheApkIsNotAZip_raisesSplitError(tmp_path: pathlib.Path) -> None:
    apk = tmp_path / "app.apk"
    apk.write_bytes(b"not a zip")

    with pytest.raises(split.SplitError, match="cannot read"):
        split.split(apk, _PACKAGE)


def testSplitFromDexEntries_whenMapping_protectsTheWholeObfuscatedPackage() -> None:
    # The mapping names one class, as if R8 had moved "myapp.Entry" into the fixture's app package.
    # The whole package must then be business, including classes the mapping does not name.
    class_mapping = mapping.ClassMapping(renames={"myapp.Entry": _NAMED_CLASS})

    result = split.split_from_dex_entries(_aab_dex_entries(), "myapp", class_mapping)

    business_classes = [name for dex in result.business for name in dex.classes]
    assert _NAMED_CLASS in business_classes
    assert _UNNAMED_CLASS in business_classes
    assert all(name.startswith(f"{_PACKAGE}.") for name in business_classes) is True
    assert len(result.framework) > 0


def testSplitFromDexEntries_whenMappingSelectsNoClasses_producesNoBusiness() -> None:
    class_mapping = mapping.ClassMapping(renames={"myapp.Entry": "not.in.the.Dex"})

    result = split.split_from_dex_entries(_aab_dex_entries(), "myapp", class_mapping)

    assert len(result.business) == 0
    assert len(result.framework) > 0


def testSplitFromDexEntries_whenNoMappingAndFewClassesUnderPackage_warns(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.WARNING, logger=split.__name__):
        split.split_from_dex_entries(_aab_dex_entries(), _PACKAGE)

    assert any(
        "pass the R8 mapping file" in record.message.lower()
        or "--mapping" in record.message
        for record in caplog.records
    )


def testSplitFromDexEntries_whenNoMappingAndManyClassesUnderPackage_doesNotWarn(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.WARNING, logger=split.__name__):
        split.split_from_dex_entries(_aab_dex_entries(), "com.google.android.gms")

    assert len(caplog.records) == 0
