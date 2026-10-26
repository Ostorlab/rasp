"""End-to-end tests of the Android packer, with a recorded split."""

import collections.abc
import pathlib
import struct
import zipfile

import pytest

from rasp_packer import errors
from rasp_packer import plugins
from rasp_packer.android import cipher
from rasp_packer.android import injection
from rasp_packer.android import packer
from rasp_packer.android import resources
from rasp_packer.android import split
from rasp_packer.android.apk import axml

_FIXTURES = pathlib.Path(__file__).parent / "apk" / "fixtures"
_MANIFEST = "manifest_with_application_and_version.bin"
_PACKAGE = "com.example.withapp"
_BUILD_ID = "rasp-build/v1:" + "ab" * 32
_STUB_DEX = b"stub dex bytes"
_ARM64_SO = b"arm64 librasp.so bytes"
_ARSC = b"resources table"

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


def _make_apk(
    path: pathlib.Path,
    *,
    manifest_fixture: str = _MANIFEST,
    native_libraries: collections.abc.Sequence[str] = (),
    extra: collections.abc.Mapping[str, bytes] | None = None,
) -> None:
    manifest = (_FIXTURES / manifest_fixture).read_bytes()
    with zipfile.ZipFile(path, "w") as archive:
        for name in native_libraries:
            archive.writestr(name, b"app native code", compress_type=zipfile.ZIP_STORED)
        for name, data in (extra or {}).items():
            archive.writestr(name, data, compress_type=zipfile.ZIP_STORED)
        archive.writestr(
            "AndroidManifest.xml", manifest, compress_type=zipfile.ZIP_STORED
        )
        archive.writestr(
            "classes.dex", b"app primary", compress_type=zipfile.ZIP_DEFLATED
        )
        archive.writestr(
            "classes2.dex", b"app secondary", compress_type=zipfile.ZIP_DEFLATED
        )
        archive.writestr("resources.arsc", _ARSC, compress_type=zipfile.ZIP_STORED)
        archive.writestr(
            "META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\n", zipfile.ZIP_DEFLATED
        )
        archive.writestr("META-INF/CERT.SF", b"sig\n", zipfile.ZIP_DEFLATED)
        archive.writestr("META-INF/CERT.RSA", b"rsa\n", zipfile.ZIP_STORED)


def _recorded_split(
    captured: list[tuple[pathlib.Path, str]] | None = None,
) -> packer.Splitter:
    def splitter(app: pathlib.Path, package: str) -> split.Split:
        if captured is not None:
            captured.append((app, package))
        return split.Split(framework=_FRAMEWORK, business=_BUSINESS)

    return splitter


def _pack(
    tmp_path: pathlib.Path,
    *,
    native_libraries: collections.abc.Sequence[str] = (),
    artifacts: resources.Artifacts | None = None,
) -> pathlib.Path:
    app = tmp_path / "app.apk"
    output = tmp_path / "protected.apk"
    _make_apk(app, native_libraries=native_libraries)
    packer.pack(
        app=app,
        output=output,
        build_id=_BUILD_ID,
        artifacts=artifacts or _artifacts(),
        splitter=_recorded_split(),
    )
    return output


def testPack_whenValidApk_splitsOnTheManifestPackage(tmp_path: pathlib.Path) -> None:
    app = tmp_path / "app.apk"
    _make_apk(app)
    captured: list[tuple[pathlib.Path, str]] = []
    packer.pack(
        app=app,
        output=tmp_path / "out.apk",
        build_id=_BUILD_ID,
        artifacts=_artifacts(),
        splitter=_recorded_split(captured),
    )
    assert captured == [(app, _PACKAGE)]


def testPack_whenValidApk_writesTheRawKey(tmp_path: pathlib.Path) -> None:
    output = _pack(tmp_path)
    with zipfile.ZipFile(output) as archive:
        info = archive.getinfo(packer.KEY_ENTRY)
        assert len(archive.read(packer.KEY_ENTRY)) == cipher.KEY_SIZE
    assert info.compress_type == zipfile.ZIP_STORED


def testPack_whenValidApk_writesTheBuildId(tmp_path: pathlib.Path) -> None:
    output = _pack(tmp_path)
    with zipfile.ZipFile(output) as archive:
        assert archive.read(packer.BUILD_ID_ENTRY) == _BUILD_ID.encode("utf-8")


def testPack_whenValidApk_writesAnEncryptedMapThatNamesEveryBusinessClass(
    tmp_path: pathlib.Path,
) -> None:
    output = _pack(tmp_path)
    with zipfile.ZipFile(output) as archive:
        assert archive.getinfo(packer.MAP_ENTRY).compress_type == zipfile.ZIP_STORED
        key = archive.read(packer.KEY_ENTRY)
        map_text = cipher.decrypt(key, archive.read(packer.MAP_ENTRY)).decode("utf-8")
        names = set(archive.namelist())
    lines = [line for line in map_text.splitlines() if line]
    assert len(lines) == 3
    mapped: dict[str, str] = {}
    for line in lines:
        name, _, path = line.partition(",")
        mapped[name] = path
    assert set(mapped) == {f"{_PACKAGE}.A", f"{_PACKAGE}.B", f"{_PACKAGE}.sub.C"}
    for path in set(mapped.values()):
        assert f"{packer.ASSET_PREFIX}{path}" in names


def testPack_whenValidApk_writesEachBusinessDexEncryptedAndStored(
    tmp_path: pathlib.Path,
) -> None:
    output = _pack(tmp_path)
    with zipfile.ZipFile(output) as archive:
        key = archive.read(packer.KEY_ENTRY)
        for dex in _BUSINESS:
            entry = f"{packer.ASSET_PREFIX}{dex.path}"
            assert archive.getinfo(entry).compress_type == zipfile.ZIP_STORED
            assert cipher.decrypt(key, archive.read(entry)) == dex.data


def testPack_whenValidApk_shipsFrameworkAndStubInTheClearAsBaseDexes(
    tmp_path: pathlib.Path,
) -> None:
    output = _pack(tmp_path)
    with zipfile.ZipFile(output) as archive:
        names = set(archive.namelist())
        assert archive.read("classes.dex") == _FRAMEWORK[0]
        assert archive.read("classes2.dex") == _FRAMEWORK[1]
        assert archive.read("classes3.dex") == _STUB_DEX
    assert "classes4.dex" not in names


def testPack_whenValidApk_addsTheRuntimeLibraryUnmodified(
    tmp_path: pathlib.Path,
) -> None:
    output = _pack(tmp_path)
    with zipfile.ZipFile(output) as archive:
        assert archive.read("lib/arm64-v8a/librasp.so") == _ARM64_SO


def testPack_whenValidApk_writesNoWholePayloadAssets(tmp_path: pathlib.Path) -> None:
    output = _pack(tmp_path)
    with zipfile.ZipFile(output) as archive:
        names = set(archive.namelist())
    assert "assets/rasp/config.json" not in names
    assert "assets/rasp/payload.bin" not in names


def testPack_whenValidApk_setsTheComponentFactoryAndRaisesMinSdk(
    tmp_path: pathlib.Path,
) -> None:
    output = _pack(tmp_path)
    with zipfile.ZipFile(output) as archive:
        manifest = archive.read("AndroidManifest.xml")
    assert axml.read_app_component_factory(manifest) == resources.STUB_FACTORY_CLASS
    assert axml.read_min_sdk_version(manifest) == packer.MINIMUM_API_LEVEL


def testPack_whenValidApk_dropsTheOriginalDexesAndSignatures(
    tmp_path: pathlib.Path,
) -> None:
    output = _pack(tmp_path)
    with zipfile.ZipFile(output) as archive:
        names = set(archive.namelist())
        assert archive.read("classes.dex") != b"app primary"
        assert archive.getinfo("resources.arsc").compress_type == zipfile.ZIP_STORED
    assert "META-INF/MANIFEST.MF" not in names
    assert "META-INF/CERT.SF" not in names
    assert "META-INF/CERT.RSA" not in names


def testPack_whenAppAlreadyHasTheMap_raisesAlreadyProtectedError(
    tmp_path: pathlib.Path,
) -> None:
    app = tmp_path / "app.apk"
    _make_apk(app, extra={packer.MAP_ENTRY: b"already"})
    with pytest.raises(errors.AlreadyProtectedError):
        packer.pack(
            app=app,
            output=tmp_path / "out.apk",
            build_id=_BUILD_ID,
            artifacts=_artifacts(),
            splitter=_recorded_split(),
        )


def testPack_whenAppAbiHasNoRuntime_raisesUnsupportedAbiError(
    tmp_path: pathlib.Path,
) -> None:
    with pytest.raises(errors.UnsupportedAbiError):
        _pack(tmp_path, native_libraries=["lib/armeabi-v7a/libapp.so"])


def testPack_whenNoPrimaryDex_raisesInvalidApkError(tmp_path: pathlib.Path) -> None:
    app = tmp_path / "app.apk"
    output = tmp_path / "out.apk"
    with zipfile.ZipFile(app, "w") as archive:
        archive.writestr(
            "AndroidManifest.xml",
            (_FIXTURES / _MANIFEST).read_bytes(),
            compress_type=zipfile.ZIP_STORED,
        )
        archive.writestr("resources.arsc", _ARSC, compress_type=zipfile.ZIP_STORED)
    with pytest.raises(errors.InvalidApkError):
        packer.pack(
            app=app,
            output=output,
            build_id=_BUILD_ID,
            artifacts=_artifacts(),
            splitter=_recorded_split(),
        )


def testPack_whenValidApk_returnsTheAppIdentity(tmp_path: pathlib.Path) -> None:
    app = tmp_path / "app.apk"
    _make_apk(app)
    app_identity = packer.pack(
        app=app,
        output=tmp_path / "out.apk",
        build_id=_BUILD_ID,
        artifacts=_artifacts(),
        splitter=_recorded_split(),
    )
    assert app_identity.package_name == _PACKAGE
    assert app_identity.version == "2.4.1"


_X86_64_SO = b"x86_64 librasp.so bytes"


def _data_offset(path: pathlib.Path, name: str) -> int:
    with zipfile.ZipFile(path) as archive:
        header = archive.getinfo(name).header_offset
    with path.open("rb") as stream:
        stream.seek(header + 26)
        name_length, extra_length = struct.unpack("<HH", stream.read(4))
    return int(header + 30 + name_length + extra_length)


def _pack_with_plugins(
    tmp_path: pathlib.Path,
    bundles: collections.abc.Sequence[pathlib.Path],
    native_libraries: collections.abc.Sequence[str] = (),
) -> pathlib.Path:
    app = tmp_path / "app.apk"
    output = tmp_path / "protected.apk"
    _make_apk(app, native_libraries=native_libraries)
    packer.pack(
        app=app,
        output=output,
        build_id=_BUILD_ID,
        artifacts=resources.Artifacts(
            stub_dex=_STUB_DEX,
            libraries={"arm64-v8a": _ARM64_SO, "x86_64": _X86_64_SO},
        ),
        splitter=_recorded_split(),
        plugins=plugins.load_all(bundles),
    )
    return output


def testPack_whenPluginsAreGiven_addsTheirLibrariesNextToTheRuntime(
    tmp_path: pathlib.Path, make_plugin: collections.abc.Callable[..., pathlib.Path]
) -> None:
    output = _pack_with_plugins(
        tmp_path, [make_plugin(name="example", abis=("arm64-v8a", "x86_64"))]
    )

    with zipfile.ZipFile(output) as archive:
        arm64 = archive.getinfo("lib/arm64-v8a/librasp_plugin_example.so")
        assert archive.read(arm64) == b"example arm64-v8a"
        assert archive.read("lib/x86_64/librasp_plugin_example.so") == b"example x86_64"
    assert arm64.compress_type == zipfile.ZIP_STORED
    assert _data_offset(output, "lib/arm64-v8a/librasp_plugin_example.so") % 16384 == 0
    assert _data_offset(output, "lib/x86_64/librasp_plugin_example.so") % 16384 == 0


def testPack_whenPluginsAreGiven_writesTheListAndTheConfigsAsStoredAssets(
    tmp_path: pathlib.Path, make_plugin: collections.abc.Callable[..., pathlib.Path]
) -> None:
    output = _pack_with_plugins(
        tmp_path,
        [
            make_plugin(name="zeta", abis=("arm64-v8a", "x86_64"), config=b"z=1"),
            make_plugin(name="alpha", abis=("arm64-v8a", "x86_64")),
        ],
    )

    with zipfile.ZipFile(output) as archive:
        names = archive.namelist()
        plugin_list = archive.getinfo(injection.PLUGIN_LIST_ENTRY)
        assert archive.read(plugin_list) == b"zeta\nalpha\n"
        assert archive.read(f"{injection.PLUGIN_CONFIG_DIRECTORY}/zeta") == b"z=1"
    assert plugin_list.compress_type == zipfile.ZIP_STORED
    assert f"{injection.PLUGIN_CONFIG_DIRECTORY}/alpha" not in names


def testPack_whenNoPluginIsGiven_writesNoPluginList(tmp_path: pathlib.Path) -> None:
    output = _pack_with_plugins(tmp_path, [])

    with zipfile.ZipFile(output) as archive:
        names = archive.namelist()
    assert injection.PLUGIN_LIST_ENTRY not in names
    assert not any("librasp_plugin_" in name for name in names)


def testPack_whenAPluginLacksAnAbiTheAppGetsTheRuntimeFor_raisesInvalidPluginError(
    tmp_path: pathlib.Path, make_plugin: collections.abc.Callable[..., pathlib.Path]
) -> None:
    with pytest.raises(errors.InvalidPluginError, match="x86_64"):
        _pack_with_plugins(tmp_path, [make_plugin(abis=("arm64-v8a",))])


def testPack_whenAPluginLacksOnlyAnAbiTheAppDoesNotShip_packs(
    tmp_path: pathlib.Path, make_plugin: collections.abc.Callable[..., pathlib.Path]
) -> None:
    output = _pack_with_plugins(
        tmp_path,
        [make_plugin(abis=("arm64-v8a",))],
        native_libraries=["lib/arm64-v8a/libapp.so"],
    )

    with zipfile.ZipFile(output) as archive:
        names = archive.namelist()
    assert "lib/arm64-v8a/librasp_plugin_example.so" in names
    assert "lib/x86_64/librasp_plugin_example.so" not in names
