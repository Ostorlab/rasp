"""End-to-end tests of the bundle packer, driven through the Android dispatch with a recorded split."""

import collections.abc
import pathlib
import zipfile

import pytest

from rasp_packer import errors
from rasp_packer.android import cipher
from rasp_packer.android import packer as android_packer
from rasp_packer.android import resources
from rasp_packer.android import split
from rasp_packer.android.aab import manifest as manifest_module
from rasp_packer.android.aab import packer as aab_packer
from rasp_packer.android.aab import proto_manifest

type BundleBuilder = collections.abc.Callable[..., pathlib.Path]
type ManifestBuilder = collections.abc.Callable[..., bytes]

_PACKAGE = "com.example.app"
_BUILD_ID = "rasp-build/v1:" + "ab" * 32
_STUB_DEX = b"stub dex bytes"
_ARM64_SO = b"arm64 librasp.so bytes"

_FRAMEWORK = (b"framework dex zero", b"framework dex one")
_BUSINESS = (
    split.BusinessDex(
        path="business/0.dex",
        data=b"business dex zero",
        classes=(f"{_PACKAGE}.A", f"{_PACKAGE}.B"),
    ),
    split.BusinessDex(
        path="business/1.dex",
        data=b"business dex one",
        classes=(f"{_PACKAGE}.sub.C",),
    ),
)


def _artifacts() -> resources.Artifacts:
    return resources.Artifacts(stub_dex=_STUB_DEX, libraries={"arm64-v8a": _ARM64_SO})


def _recorded_split(
    captured: list[tuple[pathlib.Path, str]] | None = None,
) -> aab_packer.Splitter:
    def splitter(app: pathlib.Path, package: str) -> split.Split:
        if captured is not None:
            captured.append((app, package))
        return split.Split(framework=_FRAMEWORK, business=_BUSINESS)

    return splitter


def _pack(
    make_bundle: BundleBuilder,
    tmp_path: pathlib.Path,
    *,
    manifest: bytes | None = None,
    native_libraries: collections.abc.Sequence[str] = (),
    extra: collections.abc.Mapping[str, bytes] | None = None,
    artifacts: resources.Artifacts | None = None,
) -> pathlib.Path:
    app = make_bundle(
        tmp_path / "app.aab",
        manifest=manifest,
        native_libraries=native_libraries,
        extra=extra,
    )
    output = tmp_path / "protected.aab"
    android_packer.pack(
        app=app,
        output=output,
        build_id=_BUILD_ID,
        artifacts=artifacts or _artifacts(),
        splitter=_recorded_split(),
    )
    return output


def testPack_whenValidBundle_splitsOnTheManifestPackage(
    make_bundle: BundleBuilder,
    build_manifest: ManifestBuilder,
    tmp_path: pathlib.Path,
) -> None:
    app = make_bundle(tmp_path / "app.aab", manifest=build_manifest(package=_PACKAGE))
    captured: list[tuple[pathlib.Path, str]] = []

    android_packer.pack(
        app=app,
        output=tmp_path / "out.aab",
        build_id=_BUILD_ID,
        artifacts=_artifacts(),
        splitter=_recorded_split(captured),
    )

    assert len(captured) == 1
    assert captured[0][1] == _PACKAGE


def testPack_whenValidBundle_writesTheRawKeyStored(
    make_bundle: BundleBuilder, tmp_path: pathlib.Path
) -> None:
    output = _pack(make_bundle, tmp_path)

    with zipfile.ZipFile(output) as archive:
        info = archive.getinfo(aab_packer.BASE_KEY_ENTRY)
        assert len(archive.read(aab_packer.BASE_KEY_ENTRY)) == cipher.KEY_SIZE
    assert info.compress_type == zipfile.ZIP_STORED


def testPack_whenValidBundle_writesTheBuildId(
    make_bundle: BundleBuilder, tmp_path: pathlib.Path
) -> None:
    output = _pack(make_bundle, tmp_path)

    with zipfile.ZipFile(output) as archive:
        assert archive.read(aab_packer.BASE_BUILD_ID_ENTRY) == _BUILD_ID.encode("utf-8")


def testPack_whenValidBundle_writesAnEncryptedMapNamingEveryBusinessClass(
    make_bundle: BundleBuilder, tmp_path: pathlib.Path
) -> None:
    output = _pack(make_bundle, tmp_path)

    with zipfile.ZipFile(output) as archive:
        key = archive.read(aab_packer.BASE_KEY_ENTRY)
        map_text = cipher.decrypt(key, archive.read(aab_packer.BASE_MAP_ENTRY)).decode(
            "utf-8"
        )
        names = set(archive.namelist())
    mapped = dict(line.partition(",")[::2] for line in map_text.splitlines() if line)
    assert set(mapped) == {f"{_PACKAGE}.A", f"{_PACKAGE}.B", f"{_PACKAGE}.sub.C"}
    for path in set(mapped.values()):
        assert f"base/assets/{path}" in names


def testPack_whenValidBundle_writesEachBusinessDexEncryptedUnderBaseAssets(
    make_bundle: BundleBuilder, tmp_path: pathlib.Path
) -> None:
    output = _pack(make_bundle, tmp_path)

    with zipfile.ZipFile(output) as archive:
        key = archive.read(aab_packer.BASE_KEY_ENTRY)
        for dex in _BUSINESS:
            entry = f"base/assets/{dex.path}"
            assert cipher.decrypt(key, archive.read(entry)) == dex.data


def testPack_whenValidBundle_shipsFrameworkAndStubInTheClearUnderBaseDex(
    make_bundle: BundleBuilder, tmp_path: pathlib.Path
) -> None:
    output = _pack(make_bundle, tmp_path)

    with zipfile.ZipFile(output) as archive:
        names = set(archive.namelist())
        assert archive.read("base/dex/classes.dex") == _FRAMEWORK[0]
        assert archive.read("base/dex/classes2.dex") == _FRAMEWORK[1]
        assert archive.read("base/dex/classes3.dex") == _STUB_DEX
    assert "base/dex/classes4.dex" not in names


def testPack_whenValidBundle_addsTheRuntimeLibraryUnderBaseLib(
    make_bundle: BundleBuilder, tmp_path: pathlib.Path
) -> None:
    output = _pack(make_bundle, tmp_path)

    with zipfile.ZipFile(output) as archive:
        assert archive.read("base/lib/arm64-v8a/librasp.so") == _ARM64_SO


def testPack_whenValidBundle_setsTheComponentFactoryAndRaisesMinSdk(
    make_bundle: BundleBuilder,
    build_manifest: ManifestBuilder,
    tmp_path: pathlib.Path,
) -> None:
    output = _pack(make_bundle, tmp_path, manifest=build_manifest(min_sdk=21))

    with zipfile.ZipFile(output) as archive:
        manifest = archive.read("base/manifest/AndroidManifest.xml")
    node = proto_manifest.parse(manifest)
    assert (
        proto_manifest.read_app_component_factory(node) == resources.STUB_FACTORY_CLASS
    )
    assert proto_manifest.read_min_sdk_version(node) == android_packer.MINIMUM_API_LEVEL


def testPack_whenValidBundle_dropsTheOriginalBaseDexesAndSignatures(
    make_bundle: BundleBuilder, tmp_path: pathlib.Path
) -> None:
    extra = {
        "META-INF/MANIFEST.MF": b"Manifest-Version: 1.0\n",
        "META-INF/CERT.SF": b"sig\n",
        "META-INF/CERT.RSA": b"rsa\n",
        "base/root/META-INF/app.kotlin_module": b"keep me",
    }
    output = _pack(make_bundle, tmp_path, extra=extra)

    with zipfile.ZipFile(output) as archive:
        names = set(archive.namelist())
        assert archive.read("base/dex/classes.dex") != b"base dex 0"
    assert "META-INF/MANIFEST.MF" not in names
    assert "META-INF/CERT.SF" not in names
    assert "META-INF/CERT.RSA" not in names
    assert "base/root/META-INF/app.kotlin_module" in names


def testPack_whenBundleAlreadyHasTheMap_raisesAlreadyProtectedError(
    make_bundle: BundleBuilder, tmp_path: pathlib.Path
) -> None:
    app = make_bundle(
        tmp_path / "app.aab", extra={aab_packer.BASE_MAP_ENTRY: b"already"}
    )

    with pytest.raises(errors.AlreadyProtectedError):
        android_packer.pack(
            app=app,
            output=tmp_path / "out.aab",
            build_id=_BUILD_ID,
            artifacts=_artifacts(),
            splitter=_recorded_split(),
        )


def testPack_whenAnotherModuleHasCode_raisesUnprotectedModuleError(
    make_bundle: BundleBuilder, tmp_path: pathlib.Path
) -> None:
    app = make_bundle(
        tmp_path / "app.aab", extra={"feature/dex/classes.dex": b"feature code"}
    )

    with pytest.raises(errors.UnprotectedModuleError, match="feature"):
        android_packer.pack(
            app=app,
            output=tmp_path / "out.aab",
            build_id=_BUILD_ID,
            artifacts=_artifacts(),
            splitter=_recorded_split(),
        )


def testPack_whenBundleAbiHasNoRuntime_raisesUnsupportedAbiError(
    make_bundle: BundleBuilder, tmp_path: pathlib.Path
) -> None:
    with pytest.raises(errors.UnsupportedAbiError):
        _pack(
            make_bundle,
            tmp_path,
            native_libraries=["base/lib/armeabi-v7a/libapp.so"],
        )


def testPack_whenNoBaseCode_raisesInvalidBundleError(
    make_bundle: BundleBuilder, tmp_path: pathlib.Path
) -> None:
    app = make_bundle(tmp_path / "app.aab", base_dexes=())

    with pytest.raises(errors.InvalidBundleError):
        android_packer.pack(
            app=app,
            output=tmp_path / "out.aab",
            build_id=_BUILD_ID,
            artifacts=_artifacts(),
            splitter=_recorded_split(),
        )


def testPack_whenValidBundle_returnsTheAppIdentity(
    make_bundle: BundleBuilder,
    build_manifest: ManifestBuilder,
    tmp_path: pathlib.Path,
) -> None:
    app = make_bundle(
        tmp_path / "app.aab",
        manifest=build_manifest(package=_PACKAGE, version_name="2.4.1"),
    )

    app_identity = android_packer.pack(
        app=app,
        output=tmp_path / "out.aab",
        build_id=_BUILD_ID,
        artifacts=_artifacts(),
        splitter=_recorded_split(),
    )

    assert app_identity.package_name == _PACKAGE
    assert app_identity.version == "2.4.1"


def testProtect_whenMinSdkAlreadyMeetsTheFloor_isNotLowered(
    make_bundle: BundleBuilder,
    build_manifest: ManifestBuilder,
    tmp_path: pathlib.Path,
) -> None:
    output = _pack(make_bundle, tmp_path, manifest=build_manifest(min_sdk=33))

    with zipfile.ZipFile(output) as archive:
        manifest = archive.read("base/manifest/AndroidManifest.xml")
    assert (
        manifest_module.app_component_factory(manifest) == resources.STUB_FACTORY_CLASS
    )
    assert proto_manifest.read_min_sdk_version(proto_manifest.parse(manifest)) == 33
