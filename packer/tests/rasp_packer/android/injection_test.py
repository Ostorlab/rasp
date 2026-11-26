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


def testResolveAbis_whenAppHasAbisAndNoChoice_returnsTheAppAbis() -> None:
    abis = injection.resolve_abis({"arm64-v8a"}, _artifacts(["arm64-v8a", "x86_64"]))
    assert abis == {"arm64-v8a"}


def testResolveAbis_whenAppHasNoAbisAndNoChoice_returnsEveryRuntimeAbi() -> None:
    assert injection.resolve_abis(set(), _artifacts(["a", "b"])) == {"a", "b"}


def testResolveAbis_whenAppAbiHasNoRuntimeAndNoChoice_raisesNamingTheOption() -> None:
    with pytest.raises(
        errors.UnsupportedAbiError,
        match=r"^the runtime is not built for the app's ABIs: x86; pass --abis to drop it$",
    ):
        injection.resolve_abis({"arm64-v8a", "x86"}, _artifacts(["arm64-v8a"]))


def testResolveAbis_whenChoiceExcludesAnAppAbi_returnsTheChoice() -> None:
    abis = injection.resolve_abis(
        {"arm64-v8a", "x86"}, _artifacts(["arm64-v8a", "x86_64"]), {"arm64-v8a"}
    )
    assert abis == {"arm64-v8a"}


def testResolveAbis_whenAppHasNoAbisAndAChoice_returnsTheChoice() -> None:
    abis = injection.resolve_abis(
        set(), _artifacts(["arm64-v8a", "x86_64"]), {"x86_64"}
    )
    assert abis == {"x86_64"}


def testResolveAbis_whenChosenAbiHasNoRuntime_raisesUnsupportedAbiError() -> None:
    with pytest.raises(
        errors.UnsupportedAbiError,
        match=r"^the runtime is not built for the chosen ABIs: x86$",
    ):
        injection.resolve_abis(
            {"arm64-v8a", "x86"}, _artifacts(["arm64-v8a"]), {"arm64-v8a", "x86"}
        )


def testResolveAbis_whenAppShipsNoLibrariesForAChosenAbi_raisesInvalidAbisError() -> (
    None
):
    with pytest.raises(
        errors.InvalidAbisError,
        match=r"^the app ships no native libraries for the chosen ABIs: x86_64;",
    ):
        injection.resolve_abis(
            {"arm64-v8a"}, _artifacts(["arm64-v8a", "x86_64"]), {"arm64-v8a", "x86_64"}
        )


def testResolveAbis_whenChoiceIsEmpty_raisesInvalidAbisError() -> None:
    with pytest.raises(errors.InvalidAbisError, match="no ABI is chosen"):
        injection.resolve_abis({"arm64-v8a"}, _artifacts(["arm64-v8a"]), set())


def testLibraryEntries_whenGivenAbis_returnsOnePerAbiUnderTheFilename() -> None:
    entries = injection.library_entries(
        {"a", "b"}, _artifacts(["a", "b", "c"]), "libx.so"
    )
    assert entries == {"lib/a/libx.so": b"a so", "lib/b/libx.so": b"b so"}


def testAbiFolderEntries_whenAbisGiven_returnsEveryEntryInTheirFolders() -> None:
    names = [
        "lib/x86/libapp.so",
        "lib/x86/libother.so",
        "lib/x86_64/libapp.so",
        "lib/arm64-v8a/libapp.so",
        "classes.dex",
    ]
    assert injection.abi_folder_entries(names, "lib/", {"x86"}) == {
        "lib/x86/libapp.so",
        "lib/x86/libother.so",
    }


def testAbiFolderEntries_whenNoAbis_returnsEmpty() -> None:
    assert injection.abi_folder_entries(["lib/x86/libapp.so"], "lib/", set()) == set()


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
