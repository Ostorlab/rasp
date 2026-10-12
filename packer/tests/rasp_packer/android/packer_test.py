"""End-to-end tests of the Android packer."""

import pathlib
import struct
import zipfile

import pytest

from rasp_packer import errors
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
_PRIMARY = b"primary dex code"
_SECONDARY = b"secondary dex code"
_ARSC = b"resources table"


def _artifacts() -> resources.Artifacts:
    return resources.Artifacts(stub_dex=_STUB_DEX, libraries={"arm64-v8a": _ARM64_SO})


def _make_apk(path: pathlib.Path, manifest_fixture: str) -> None:
    manifest = (_FIXTURES / manifest_fixture).read_bytes()
    with zipfile.ZipFile(path, "w") as archive:
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


def testPack_replacesPrimaryDexWithStubAndDropsOthers(tmp_path: pathlib.Path) -> None:
    output = _pack(tmp_path, "manifest_with_application.bin")
    with zipfile.ZipFile(output) as archive:
        names = set(archive.namelist())
        assert archive.read("classes.dex") == _STUB_DEX
    assert "classes2.dex" not in names


def testPack_addsRuntimeLibrary(tmp_path: pathlib.Path) -> None:
    output = _pack(tmp_path, "manifest_with_application.bin")
    with zipfile.ZipFile(output) as archive:
        assert archive.read("lib/arm64-v8a/librasp.so") == _ARM64_SO


def testPack_pointsManifestAtStub(tmp_path: pathlib.Path) -> None:
    output = _pack(tmp_path, "manifest_with_application.bin")
    with zipfile.ZipFile(output) as archive:
        manifest = archive.read("AndroidManifest.xml")
    assert axml.read_application_class(manifest) == resources.STUB_APPLICATION_CLASS


def testPack_keepsResourcesStored(tmp_path: pathlib.Path) -> None:
    output = _pack(tmp_path, "manifest_with_application.bin")
    with zipfile.ZipFile(output) as archive:
        info = archive.getinfo("resources.arsc")
        assert archive.read("resources.arsc") == _ARSC
    assert info.compress_type == zipfile.ZIP_STORED


def testPack_payloadDecryptsToOriginalDexes(tmp_path: pathlib.Path) -> None:
    output = _pack(tmp_path, "manifest_with_application.bin")
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


def testPack_payloadDoesNotContainPlaintextDex(tmp_path: pathlib.Path) -> None:
    output = _pack(tmp_path, "manifest_with_application.bin")
    with zipfile.ZipFile(output) as archive:
        payload_bytes = archive.read(config.PAYLOAD_ENTRY)
    assert _PRIMARY not in payload_bytes


def testPack_recordsTheOriginalApplicationClass(tmp_path: pathlib.Path) -> None:
    output = _pack(tmp_path, "manifest_with_application.bin")
    with zipfile.ZipFile(output) as archive:
        runtime_config = config.RuntimeConfig.from_json(
            archive.read(config.CONFIG_ENTRY).decode("utf-8")
        )
    assert runtime_config.application_class == "com.example.withapp.MyApp"


def testPack_recordsTheBuildId(tmp_path: pathlib.Path) -> None:
    output = _pack(tmp_path, "manifest_with_application.bin")
    with zipfile.ZipFile(output) as archive:
        runtime_config = config.RuntimeConfig.from_json(
            archive.read(config.CONFIG_ENTRY).decode("utf-8")
        )
    assert runtime_config.build_id == _BUILD_ID


def testPack_whenAppHasNoApplication_recordsTheDefault(tmp_path: pathlib.Path) -> None:
    output = _pack(tmp_path, "manifest_without_application.bin")
    with zipfile.ZipFile(output) as archive:
        runtime_config = config.RuntimeConfig.from_json(
            archive.read(config.CONFIG_ENTRY).decode("utf-8")
        )
        manifest = archive.read("AndroidManifest.xml")
    assert runtime_config.application_class == "android.app.Application"
    assert axml.read_application_class(manifest) == resources.STUB_APPLICATION_CLASS


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
    tmp_path: pathlib.Path,
) -> None:
    app = tmp_path / "app.apk"
    _make_apk(app, "manifest_with_application.bin")
    with pytest.raises(errors.MissingRuntimeArtifactError):
        packer.pack(app=app, output=tmp_path / "out.apk", build_id=_BUILD_ID)


def _data_offset(path: pathlib.Path, name: str) -> int:
    with zipfile.ZipFile(path) as archive:
        header = archive.getinfo(name).header_offset
    with path.open("rb") as stream:
        stream.seek(header + 26)
        name_length, extra_length = struct.unpack("<HH", stream.read(4))
    return int(header + 30 + name_length + extra_length)


def testPack_alignsNativeLibrariesAndResources(tmp_path: pathlib.Path) -> None:
    output = _pack(tmp_path, "manifest_with_application.bin")
    assert _data_offset(output, "lib/arm64-v8a/librasp.so") % 16384 == 0
    assert _data_offset(output, "resources.arsc") % 4 == 0


def testPack_stripsStaleSignatureFiles(tmp_path: pathlib.Path) -> None:
    output = _pack(tmp_path, "manifest_with_application.bin")
    with zipfile.ZipFile(output) as archive:
        names = archive.namelist()
    assert not any(name.startswith("META-INF/") for name in names)
