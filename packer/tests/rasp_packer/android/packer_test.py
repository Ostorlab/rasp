"""End-to-end tests of the Android packer, with a recorded split."""

import collections.abc
import pathlib
import zipfile

import pytest

from rasp_packer import capabilities
from rasp_packer import errors
from rasp_packer import runtime_config
from rasp_packer.android import cipher
from rasp_packer.android import packer
from rasp_packer.android import resources
from rasp_packer.android import runtime_library
from rasp_packer.android import split
from rasp_packer.android.apk import archive as apk_archive
from rasp_packer.android.apk import axml
from tests.rasp_packer import conftest

_FIXTURES = pathlib.Path(__file__).parent / "apk" / "fixtures"
_MANIFEST = "manifest_with_application_and_version.bin"
_PACKAGE = "com.example.withapp"
_CONFIG = runtime_config.RuntimeConfig(
    build_id="rasp-build/v1:" + "ab" * 32, checks=("identity",)
)
_STUB_DEX = b"stub dex bytes"
_ARM64_SO = (conftest.RUNTIME_CONFIG_DATA / "librasp.so").read_bytes()
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
        config=_CONFIG,
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
        config=_CONFIG,
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


def testPack_whenValidApk_addsTheRuntimeLibraryWithTheConfigWrittenIntoIt(
    tmp_path: pathlib.Path,
) -> None:
    output = _pack(tmp_path)
    with zipfile.ZipFile(output) as archive:
        library = archive.read("lib/arm64-v8a/librasp.so")
        names = archive.namelist()

    assert library == runtime_library.write_config(_ARM64_SO, _CONFIG)
    assert runtime_library.read_config(library) == _CONFIG.to_json()
    assert "assets/rasp/config.json" not in names


def testPack_whenValidApk_writesNoWholePayload(tmp_path: pathlib.Path) -> None:
    output = _pack(tmp_path)
    with zipfile.ZipFile(output) as archive:
        names = set(archive.namelist())
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
            config=_CONFIG,
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
            config=_CONFIG,
            artifacts=_artifacts(),
            splitter=_recorded_split(),
        )


def testPack_whenValidApk_returnsTheAppIdentity(tmp_path: pathlib.Path) -> None:
    app = tmp_path / "app.apk"
    _make_apk(app)
    app_identity = packer.pack(
        app=app,
        output=tmp_path / "out.apk",
        config=_CONFIG,
        artifacts=_artifacts(),
        splitter=_recorded_split(),
    )
    assert app_identity.package_name == _PACKAGE
    assert app_identity.version == "2.4.1"


@pytest.mark.parametrize("bound", [True, False])
def testPack_whenRuntimeHasOrLacksManifest_reportsExactBindingOrUnknown(
    tmp_path: pathlib.Path, bound: bool
) -> None:
    app = tmp_path / "app.apk"
    _make_apk(app)
    manifests = (
        {"arm64-v8a": capabilities.emit(_ARM64_SO, "android", "arm64-v8a", "31")}
        if bound is True
        else {}
    )
    artifacts = resources.Artifacts(
        stub_dex=_STUB_DEX, libraries={"arm64-v8a": _ARM64_SO}, manifests=manifests
    )
    result = packer.pack(
        app=app,
        output=tmp_path / "protected.apk",
        config=_CONFIG,
        artifacts=artifacts,
        splitter=_recorded_split(),
    )
    assert result.effective_checks == _CONFIG.checks
    assert (result.bindings is not None) is bound
    if result.bindings is not None:
        expected = capabilities.bind(
            _ARM64_SO, manifests["arm64-v8a"], "android", "arm64-v8a"
        )
        assert expected is not None
        assert result.bindings == (expected,)


def testPack_whenRuntimeDigestMismatch_rejectsBeforeOutput(
    tmp_path: pathlib.Path,
) -> None:
    app = tmp_path / "app.apk"
    _make_apk(app)
    artifacts = resources.Artifacts(
        stub_dex=_STUB_DEX,
        libraries={"arm64-v8a": _ARM64_SO},
        manifests={
            "arm64-v8a": capabilities.emit(b"wrong", "android", "arm64-v8a", "31")
        },
    )
    output = tmp_path / "bad.apk"
    with pytest.raises(errors.InvalidRuntimeError, match="digest"):
        packer.pack(
            app=app,
            output=output,
            config=_CONFIG,
            artifacts=artifacts,
            splitter=_recorded_split(),
        )
    assert output.exists() is False


def testPack_whenArchiveWriterDropsRuntime_rejectsWithoutOutput(
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = tmp_path / "input.apk"
    _make_apk(app)
    output = tmp_path / "out.apk"
    write = apk_archive.Apk.write

    def incomplete_write(
        self: apk_archive.Apk,
        path: pathlib.Path,
        *,
        replace: collections.abc.Mapping[str, bytes],
        add: collections.abc.Mapping[str, bytes],
        remove: collections.abc.Set[str],
    ) -> None:
        write(
            self,
            path,
            replace=replace,
            add={
                name: data
                for name, data in add.items()
                if name.endswith("librasp.so") is False
            },
            remove=remove,
        )

    monkeypatch.setattr(apk_archive.Apk, "write", incomplete_write)
    with pytest.raises(errors.VerificationError, match="missing required"):
        packer.pack(
            app=app,
            output=output,
            config=_CONFIG,
            artifacts=_artifacts(),
            splitter=_recorded_split(),
        )
    assert output.exists() is False
    assert list(tmp_path.glob(".rasp-*")) == []


def testPack_whenNoBusinessClasses_verifiesEmptyMapWithoutInventingPayloadRequirement(
    tmp_path: pathlib.Path,
) -> None:
    app = tmp_path / "input.apk"
    _make_apk(app)
    output = tmp_path / "out.apk"
    packer.pack(
        app=app,
        output=output,
        config=_CONFIG,
        artifacts=_artifacts(),
        splitter=lambda *_: split.Split(framework=_FRAMEWORK, business=()),
    )
    with zipfile.ZipFile(output) as archive:
        assert (
            cipher.decrypt(
                archive.read(packer.KEY_ENTRY), archive.read(packer.MAP_ENTRY)
            )
            == b""
        )


def testPack_whenInputOversized_rejectsBeforeFormatProbeReadsZip(
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = tmp_path / "oversized.apk"
    with app.open("wb") as stream:
        stream.truncate(4 * 1024**3 + 1)

    def unexpected_zip_read(*_: object, **__: object) -> None:
        pytest.fail("oversized input must be refused before ZIP metadata is parsed")

    monkeypatch.setattr(zipfile, "ZipFile", unexpected_zip_read)
    with pytest.raises(errors.InvalidApkError, match="4 GiB"):
        packer.pack(
            app=app, output=tmp_path / "out.apk", config=_CONFIG, artifacts=_artifacts()
        )


@pytest.mark.parametrize("selected", [True, False])
def testPack_whenRootPackagesSelected_addsOnlyExactOptInQueries(
    tmp_path: pathlib.Path, selected: bool
) -> None:
    app = tmp_path / "app.apk"
    output = tmp_path / "protected.apk"
    _make_apk(app, manifest_fixture="manifest_with_queries.bin")
    config = runtime_config.RuntimeConfig(
        build_id=_CONFIG.build_id,
        checks=("identity", "root_packages") if selected else ("identity",),
    )
    packer.pack(
        app=app,
        output=output,
        config=config,
        artifacts=_artifacts(),
        splitter=_recorded_split(),
    )
    with zipfile.ZipFile(output) as archive:
        manifest = archive.read("AndroidManifest.xml")
    expected: tuple[str, ...] = ("org.example.partner", "com.topjohnwu.magisk")
    if selected:
        expected += ("me.weishu.kernelsu", "me.bmax.apatch")
    assert axml.read_package_queries(manifest) == expected
    assert b"QUERY_ALL_PACKAGES" not in manifest
