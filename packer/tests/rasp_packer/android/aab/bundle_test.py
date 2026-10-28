"""Tests of the bundle part accessors."""

import collections.abc
import pathlib
import zipfile

from rasp_packer.android.aab import bundle
from rasp_packer.android.apk import archive

type BundleBuilder = collections.abc.Callable[..., pathlib.Path]


def _read(path: pathlib.Path) -> archive.Apk:
    return archive.Apk.read(path)


def testIsBundle_whenBundleConfigPresent_returnsTrue(
    make_bundle: BundleBuilder, tmp_path: pathlib.Path
) -> None:
    apk = _read(make_bundle(tmp_path / "app.aab"))

    assert bundle.is_bundle(apk) is True


def testIsBundle_whenNoBundleConfig_returnsFalse(tmp_path: pathlib.Path) -> None:
    path = tmp_path / "app.apk"
    with zipfile.ZipFile(path, "w") as archive_file:
        archive_file.writestr("AndroidManifest.xml", b"binary xml")
        archive_file.writestr("classes.dex", b"dex")

    assert bundle.is_bundle(_read(path)) is False


def testBaseManifest_whenPresent_returnsItsBytes(
    make_bundle: BundleBuilder,
    build_manifest: collections.abc.Callable[..., bytes],
    tmp_path: pathlib.Path,
) -> None:
    manifest = build_manifest(package="dev.ostorlab.demo")
    apk = _read(make_bundle(tmp_path / "app.aab", manifest=manifest))

    assert bundle.base_manifest(apk) == manifest


def testBaseDexNames_whenMultidex_returnsThemInLoadOrder(
    make_bundle: BundleBuilder, tmp_path: pathlib.Path
) -> None:
    apk = _read(
        make_bundle(
            tmp_path / "app.aab",
            base_dexes=(
                "base/dex/classes2.dex",
                "base/dex/classes10.dex",
                "base/dex/classes.dex",
            ),
        )
    )

    assert bundle.base_dex_names(apk) == [
        "base/dex/classes.dex",
        "base/dex/classes2.dex",
        "base/dex/classes10.dex",
    ]


def testModulesWithCode_whenOnlyBaseHasCode_returnsEmpty(
    make_bundle: BundleBuilder, tmp_path: pathlib.Path
) -> None:
    apk = _read(
        make_bundle(
            tmp_path / "app.aab",
            extra={
                "assets_only/assets/data.bin": b"x",
                "assets_only/manifest/AndroidManifest.xml": b"m",
            },
        )
    )

    assert bundle.modules_with_code(apk) == set()


def testModulesWithCode_whenAnotherModuleHasDex_returnsIt(
    make_bundle: BundleBuilder, tmp_path: pathlib.Path
) -> None:
    apk = _read(
        make_bundle(
            tmp_path / "app.aab",
            extra={"feature/dex/classes.dex": b"feature dex"},
        )
    )

    assert bundle.modules_with_code(apk) == {"feature"}


def testNativeAbis_whenBaseShipsLibraries_returnsTheAbis(
    make_bundle: BundleBuilder, tmp_path: pathlib.Path
) -> None:
    apk = _read(
        make_bundle(
            tmp_path / "app.aab",
            native_libraries=[
                "base/lib/arm64-v8a/libapp.so",
                "base/lib/x86_64/libapp.so",
            ],
        )
    )

    assert bundle.native_abis(apk) == {"arm64-v8a", "x86_64"}
