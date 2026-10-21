"""End-to-end tests of the Android packer."""

import collections.abc
import pathlib
import struct
import zipfile

import pytest

from rasp_packer import errors
from rasp_packer import identity
from rasp_packer.android import config
from rasp_packer.android import packer
from rasp_packer.android import payload
from rasp_packer.android import resources
from rasp_packer.android.apk import axml

_FIXTURES = pathlib.Path(__file__).parent / "apk" / "fixtures"
_BUILD_ID = (
    "rasp-build/v1:abababababababababababababababababababababababababababababababab"
)
_STUB_DEX = b"stub dex bytes"
_ARM64_SO = b"arm64 librasp.so bytes"
_X86_64_SO = b"x86_64 librasp.so bytes"
_PRIMARY = b"primary dex code"
_SECONDARY = b"secondary dex code"
_ARSC = b"resources table"


def _artifacts() -> resources.Artifacts:
    return resources.Artifacts(stub_dex=_STUB_DEX, libraries={"arm64-v8a": _ARM64_SO})


def _make_apk(
    path: pathlib.Path,
    manifest_fixture: str,
    native_libraries: collections.abc.Sequence[str] = (),
) -> None:
    manifest = (_FIXTURES / manifest_fixture).read_bytes()
    with zipfile.ZipFile(path, "w") as archive:
        for name in native_libraries:
            archive.writestr(name, b"app native code", compress_type=zipfile.ZIP_STORED)
        archive.writestr(
            "AndroidManifest.xml", manifest, compress_type=zipfile.ZIP_STORED
        )
        archive.writestr("classes.dex", _PRIMARY, compress_type=zipfile.ZIP_DEFLATED)
        archive.writestr("classes2.dex", _SECONDARY, compress_type=zipfile.ZIP_DEFLATED)
        archive.writestr("resources.arsc", _ARSC, compress_type=zipfile.ZIP_STORED)
        archive.writestr(
            "res/layout/main.xml", b"a resource", compress_type=zipfile.ZIP_DEFLATED
        )
        archive.writestr(
            "META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\n", zipfile.ZIP_DEFLATED
        )
        archive.writestr("META-INF/CERT.SF", b"sig\n", zipfile.ZIP_DEFLATED)
        archive.writestr("META-INF/CERT.RSA", b"rsa\n", zipfile.ZIP_STORED)


def _pack(tmp_path: pathlib.Path, manifest_fixture: str) -> pathlib.Path:
    app = tmp_path / "app.apk"
    output = tmp_path / "protected.apk"
    _make_apk(app, manifest_fixture)
    packer.pack(
        app=app,
        output=output,
        build_id=_BUILD_ID,
        artifacts=_artifacts(),
    )
    return output


def testPack_whenValidApk_replacesPrimaryDexWithStubAndDropsOthers(
    tmp_path: pathlib.Path,
) -> None:
    output = _pack(tmp_path, "manifest_with_application_and_version.bin")
    with zipfile.ZipFile(output) as archive:
        names = set(archive.namelist())
        assert archive.read("classes.dex") == _STUB_DEX
    assert "classes2.dex" not in names


def testPack_whenValidApk_addsTheRuntimeLibrary(tmp_path: pathlib.Path) -> None:
    output = _pack(tmp_path, "manifest_with_application_and_version.bin")
    with zipfile.ZipFile(output) as archive:
        assert archive.read("lib/arm64-v8a/librasp.so") == _ARM64_SO


def testPack_whenValidApk_setsTheManifestComponentFactoryToTheStub(
    tmp_path: pathlib.Path,
) -> None:
    output = _pack(tmp_path, "manifest_with_application_and_version.bin")
    with zipfile.ZipFile(output) as archive:
        manifest = archive.read("AndroidManifest.xml")
    assert axml.read_app_component_factory(manifest) == resources.STUB_FACTORY_CLASS


def testPack_whenAppHasApplication_keepsItsApplicationClass(
    tmp_path: pathlib.Path,
) -> None:
    output = _pack(tmp_path, "manifest_with_application_and_version.bin")
    with zipfile.ZipFile(output) as archive:
        manifest = archive.read("AndroidManifest.xml")
    assert axml.read_application_class(manifest) == "com.example.withapp.MyApp"


def testPack_whenValidApk_keepsResourcesStored(tmp_path: pathlib.Path) -> None:
    output = _pack(tmp_path, "manifest_with_application_and_version.bin")
    with zipfile.ZipFile(output) as archive:
        info = archive.getinfo("resources.arsc")
        assert archive.read("resources.arsc") == _ARSC
    assert info.compress_type == zipfile.ZIP_STORED


def testPack_whenValidApk_writesAPayloadThatDecryptsToTheDexes(
    tmp_path: pathlib.Path,
) -> None:
    output = _pack(tmp_path, "manifest_with_application_and_version.bin")
    with zipfile.ZipFile(output) as archive:
        runtime_config = config.RuntimeConfig.from_json(
            archive.read(config.CONFIG_ENTRY).decode("utf-8")
        )
        payload_bytes = archive.read(config.PAYLOAD_ENTRY)
    assert runtime_config.dex_names == ("classes.dex", "classes2.dex")
    dexes = payload.parse(bytes.fromhex(runtime_config.key_hex), payload_bytes)
    assert {dex.name: dex.data for dex in dexes} == {
        "classes.dex": _PRIMARY,
        "classes2.dex": _SECONDARY,
    }


def testPack_whenValidApk_writesTheRawKeyAsAStoredAsset(
    tmp_path: pathlib.Path,
) -> None:
    output = _pack(tmp_path, "manifest_with_application_and_version.bin")
    with zipfile.ZipFile(output) as archive:
        info = archive.getinfo(config.KEY_ENTRY)
        key = archive.read(config.KEY_ENTRY)
        runtime_config = config.RuntimeConfig.from_json(
            archive.read(config.CONFIG_ENTRY).decode("utf-8")
        )
        payload_bytes = archive.read(config.PAYLOAD_ENTRY)
    assert info.compress_type == zipfile.ZIP_STORED
    assert key == bytes.fromhex(runtime_config.key_hex)
    dexes = payload.parse(key, payload_bytes)
    assert {dex.name for dex in dexes} == {"classes.dex", "classes2.dex"}


def testPack_whenValidApk_keepsPlaintextDexOutOfThePayload(
    tmp_path: pathlib.Path,
) -> None:
    output = _pack(tmp_path, "manifest_with_application_and_version.bin")
    with zipfile.ZipFile(output) as archive:
        payload_bytes = archive.read(config.PAYLOAD_ENTRY)
    assert _PRIMARY not in payload_bytes
    assert _SECONDARY not in payload_bytes


def testPack_whenValidApk_recordsTheBuildId(tmp_path: pathlib.Path) -> None:
    output = _pack(tmp_path, "manifest_with_application_and_version.bin")
    with zipfile.ZipFile(output) as archive:
        runtime_config = config.RuntimeConfig.from_json(
            archive.read(config.CONFIG_ENTRY).decode("utf-8")
        )
    assert runtime_config.build_id == _BUILD_ID


def testPack_whenAppHasNoApplication_addsNoApplicationClass(
    tmp_path: pathlib.Path,
) -> None:
    output = _pack(tmp_path, "manifest_without_application_with_version.bin")
    with zipfile.ZipFile(output) as archive:
        manifest = archive.read("AndroidManifest.xml")
    assert axml.read_app_component_factory(manifest) == resources.STUB_FACTORY_CLASS
    assert axml.read_application_class(manifest) is None


def testPack_whenNotApk_raisesInvalidApkError(tmp_path: pathlib.Path) -> None:
    app = tmp_path / "bad.apk"
    app.write_bytes(b"not a zip file")
    with pytest.raises(errors.InvalidApkError):
        packer.pack(
            app=app,
            output=tmp_path / "out.apk",
            build_id=_BUILD_ID,
            artifacts=_artifacts(),
        )


def testPack_whenArtifactsMissing_raisesMissingRuntimeArtifactError(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    app = tmp_path / "app.apk"
    _make_apk(app, "manifest_with_application_and_version.bin")

    def missing() -> resources.Artifacts:
        raise errors.MissingRuntimeArtifactError("stub dex not found")

    monkeypatch.setattr(resources, "load", missing)
    with pytest.raises(errors.MissingRuntimeArtifactError):
        packer.pack(app=app, output=tmp_path / "out.apk", build_id=_BUILD_ID)


def _data_offset(path: pathlib.Path, name: str) -> int:
    with zipfile.ZipFile(path) as archive:
        header = archive.getinfo(name).header_offset
    with path.open("rb") as stream:
        stream.seek(header + 26)
        name_length, extra_length = struct.unpack("<HH", stream.read(4))
    return int(header + 30 + name_length + extra_length)


def testPack_whenValidApk_alignsNativeLibrariesAndResources(
    tmp_path: pathlib.Path,
) -> None:
    output = _pack(tmp_path, "manifest_with_application_and_version.bin")
    assert _data_offset(output, "lib/arm64-v8a/librasp.so") % 16384 == 0
    assert _data_offset(output, "resources.arsc") % 4 == 0


def testPack_whenAppSigned_stripsTheOldSignatureFiles(tmp_path: pathlib.Path) -> None:
    output = _pack(tmp_path, "manifest_with_application_and_version.bin")
    with zipfile.ZipFile(output) as archive:
        names = archive.namelist()
    assert "META-INF/MANIFEST.MF" not in names
    assert "META-INF/CERT.SF" not in names
    assert "META-INF/CERT.RSA" not in names


def testPack_whenValidApk_returnsThePackageAndVersionOfTheApp(
    tmp_path: pathlib.Path,
) -> None:
    app = tmp_path / "app.apk"
    _make_apk(app, "manifest_with_application_and_version.bin")

    result = packer.pack(
        app=app,
        output=tmp_path / "protected.apk",
        build_id=_BUILD_ID,
        artifacts=_artifacts(),
    )

    assert result == identity.AppIdentity(
        package_name="com.example.withapp", version="2.4.1"
    )


def testPack_whenTheManifestHasNoVersionName_raisesInvalidApkError(
    tmp_path: pathlib.Path,
) -> None:
    app = tmp_path / "app.apk"
    _make_apk(app, "manifest_with_application.bin")

    with pytest.raises(errors.InvalidApkError, match="versionName"):
        packer.pack(
            app=app,
            output=tmp_path / "protected.apk",
            build_id=_BUILD_ID,
            artifacts=_artifacts(),
        )


def testPack_whenTheAppIsAlreadyProtected_raisesAlreadyProtectedError(
    tmp_path: pathlib.Path,
) -> None:
    protected = _pack(tmp_path, "manifest_with_application_and_version.bin")

    with pytest.raises(errors.AlreadyProtectedError):
        packer.pack(
            app=protected,
            output=tmp_path / "twice.apk",
            build_id=_BUILD_ID,
            artifacts=_artifacts(),
        )


def _pack_with_libraries(
    tmp_path: pathlib.Path,
    native_libraries: collections.abc.Sequence[str],
    libraries: collections.abc.Mapping[str, bytes],
) -> list[str]:
    app = tmp_path / "app.apk"
    output = tmp_path / "protected.apk"
    _make_apk(app, "manifest_with_application_and_version.bin", native_libraries)
    packer.pack(
        app=app,
        output=output,
        build_id=_BUILD_ID,
        artifacts=resources.Artifacts(stub_dex=_STUB_DEX, libraries=libraries),
    )
    with zipfile.ZipFile(output) as archive:
        return [name for name in archive.namelist() if name.endswith("/librasp.so")]


def testPack_whenTheAppHasNoNativeLibraries_addsTheRuntimeForEveryRuntimeAbi(
    tmp_path: pathlib.Path,
) -> None:
    added = _pack_with_libraries(
        tmp_path, [], {"arm64-v8a": _ARM64_SO, "x86_64": _X86_64_SO}
    )

    assert sorted(added) == ["lib/arm64-v8a/librasp.so", "lib/x86_64/librasp.so"]


def testPack_whenTheAppHasNativeLibraries_addsTheRuntimeOnlyForTheAppsAbis(
    tmp_path: pathlib.Path,
) -> None:
    added = _pack_with_libraries(
        tmp_path,
        ["lib/arm64-v8a/libapp.so"],
        {"arm64-v8a": _ARM64_SO, "x86_64": _X86_64_SO},
    )

    assert added == ["lib/arm64-v8a/librasp.so"]


def testPack_whenTheRuntimeIsNotBuiltForAnAbiOfTheApp_raisesUnsupportedAbiError(
    tmp_path: pathlib.Path,
) -> None:
    with pytest.raises(errors.UnsupportedAbiError, match="armeabi-v7a"):
        _pack_with_libraries(
            tmp_path,
            ["lib/arm64-v8a/libapp.so", "lib/armeabi-v7a/libapp.so"],
            {"arm64-v8a": _ARM64_SO},
        )


def testPack_whenTheAppSupportsOlderAndroidVersions_raisesItsMinSdkVersion(
    tmp_path: pathlib.Path,
) -> None:
    output = _pack(tmp_path, "manifest_with_application_and_version.bin")

    with zipfile.ZipFile(output) as archive:
        manifest = archive.read("AndroidManifest.xml")
    assert axml.read_min_sdk_version(manifest) == packer.MINIMUM_API_LEVEL


def testPack_whenTheManifestHasNoMinSdkVersion_raisesInvalidApkError(
    tmp_path: pathlib.Path,
) -> None:
    app = tmp_path / "app.apk"
    _make_apk(app, "manifest_without_min_sdk.bin")

    with pytest.raises(errors.InvalidApkError, match="minSdkVersion"):
        packer.pack(
            app=app,
            output=tmp_path / "protected.apk",
            build_id=_BUILD_ID,
            artifacts=_artifacts(),
        )
