"""Tests of the APK edits shared by both Android packers."""

import collections.abc

import pytest

from rasp_packer import errors
from rasp_packer.android import injection
from rasp_packer.android import resources
from rasp_packer.android.apk import archive


def _apk(names: collections.abc.Sequence[str]) -> archive.Apk:
    return archive.Apk(
        [archive.Entry(name=name, data=b"x", compressed=False) for name in names]
    )


def _artifacts(abis: collections.abc.Sequence[str]) -> resources.Artifacts:
    return resources.Artifacts(
        stub_dex=b"stub", libraries={abi: f"{abi} so".encode() for abi in abis}
    )


def testEntry_whenPresent_returnsItsBytes() -> None:
    apk = archive.Apk([archive.Entry(name="a", data=b"hello", compressed=False)])
    assert injection.entry(apk, "a") == b"hello"


def testEntry_whenAbsent_raisesInvalidApkError() -> None:
    with pytest.raises(errors.InvalidApkError):
        injection.entry(_apk(["a"]), "missing")


def testNativeAbis_whenLibHasSoFiles_returnsTheirAbis() -> None:
    apk = _apk(
        [
            "lib/arm64-v8a/libapp.so",
            "lib/x86_64/libapp.so",
            "lib/mips/notes.txt",
            "classes.dex",
        ]
    )
    assert injection.native_abis(apk) == {"arm64-v8a", "x86_64"}


def testNativeAbis_whenNoNativeLibraries_returnsEmpty() -> None:
    assert injection.native_abis(_apk(["classes.dex", "resources.arsc"])) == set()


def testLibraryEntries_whenAppHasAbis_returnsOnePerAppAbi() -> None:
    apk = _apk(["lib/arm64-v8a/libapp.so"])
    entries = injection.library_entries(apk, _artifacts(["arm64-v8a", "x86_64"]))
    assert set(entries) == {"lib/arm64-v8a/librasp.so"}


def testLibraryEntries_whenAppHasNoAbis_returnsOnePerRuntimeAbi() -> None:
    entries = injection.library_entries(_apk(["classes.dex"]), _artifacts(["a", "b"]))
    assert set(entries) == {"lib/a/librasp.so", "lib/b/librasp.so"}


def testLibraryEntries_whenAppAbiHasNoRuntime_raisesUnsupportedAbiError() -> None:
    apk = _apk(["lib/riscv64/libapp.so"])
    with pytest.raises(errors.UnsupportedAbiError):
        injection.library_entries(apk, _artifacts(["arm64-v8a"]))


def testStaleSignatureEntries_whenV1SignaturePresent_returnsThem() -> None:
    apk = _apk(
        [
            "META-INF/MANIFEST.MF",
            "META-INF/CERT.SF",
            "META-INF/CERT.RSA",
            "META-INF/other.txt",
            "classes.dex",
        ]
    )
    assert injection.stale_signature_entries(apk) == {
        "META-INF/MANIFEST.MF",
        "META-INF/CERT.SF",
        "META-INF/CERT.RSA",
    }


def testBaseDexEntries_whenFrameworkAndStub_namesThemInMultidexOrder() -> None:
    entries = injection.base_dex_entries([b"fw0", b"fw1"], b"stub")
    assert entries == {
        "classes.dex": b"fw0",
        "classes2.dex": b"fw1",
        "classes3.dex": b"stub",
    }


def testBaseDexEntries_whenNoFramework_makesTheStubThePrimaryDex() -> None:
    assert injection.base_dex_entries([], b"stub") == {"classes.dex": b"stub"}


def testPrimaryDexName_whenIndexIsZero_isClassesDex() -> None:
    assert injection.primary_dex_name(0) == "classes.dex"


def testPrimaryDexName_whenIndexIsPositive_isNumberedFromTwo() -> None:
    assert injection.primary_dex_name(1) == "classes2.dex"
    assert injection.primary_dex_name(4) == "classes5.dex"
