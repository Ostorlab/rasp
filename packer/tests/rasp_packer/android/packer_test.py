"""End-to-end tests of the Android packer, with a recorded split."""

import collections.abc
import io
import pathlib
import zipfile

import lief
import pytest

from rasp_packer import errors
from rasp_packer import runtime_config
from rasp_packer.android import cipher
from rasp_packer.android import key_schedule
from rasp_packer.android import packer
from rasp_packer.android import resources
from rasp_packer.android import runtime_library
from rasp_packer.android import split
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


def _recover_root(
    archive: zipfile.ZipFile,
    library_entry: str = "lib/arm64-v8a/librasp.so",
    gates: bytes = key_schedule.CLEAN_GATES,
) -> bytes:
    """Recovers the root key from a packed APK the way the runtime does on the device."""
    library = archive.read(library_entry)
    return key_schedule.root_key(
        runtime_library.keystore(library),
        archive.read(packer.SHARE_ENTRY),
        key_schedule.bind_config(runtime_library.config_region(library)),
        key_schedule.bind_text(runtime_library.text_region(library)),
        gates,
    )


def _decrypt_map(archive: zipfile.ZipFile, root: bytes) -> bytes:
    frame = archive.read(packer.MAP_ENTRY)
    key = key_schedule.frame_key(root, frame[: cipher.NONCE_SIZE], packer.MAP_ENTRY)
    return cipher.decrypt(key, frame)


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


def testPack_whenValidApk_writesNoKeyEntry(tmp_path: pathlib.Path) -> None:
    output = _pack(tmp_path)
    with zipfile.ZipFile(output) as archive:
        names = set(archive.namelist())
    assert "assets/rasp/key.bin" not in names


def testPack_whenValidApk_writesTheScheduleShareStored(
    tmp_path: pathlib.Path,
) -> None:
    output = _pack(tmp_path)
    with zipfile.ZipFile(output) as archive:
        info = archive.getinfo(packer.SHARE_ENTRY)
        assert len(archive.read(packer.SHARE_ENTRY)) == key_schedule.KEY_SIZE
    assert info.compress_type == zipfile.ZIP_STORED


def testPack_whenValidApk_recoversTheRootFromTheShippedArtifacts(
    tmp_path: pathlib.Path,
) -> None:
    output = _pack(tmp_path)
    with zipfile.ZipFile(output) as archive:
        root = _recover_root(archive)
        with pytest.raises(cipher.CipherError):
            # The root is random per packing, so it only proves the map opens below; here a wrong
            # root must fail, showing the recovery is exact and not accidental.
            _decrypt_map(archive, bytes(key_schedule.KEY_SIZE))
        assert len(root) == key_schedule.KEY_SIZE


def testPack_whenValidApk_writesAnEncryptedMapThatNamesEveryBusinessClass(
    tmp_path: pathlib.Path,
) -> None:
    output = _pack(tmp_path)
    with zipfile.ZipFile(output) as archive:
        assert archive.getinfo(packer.MAP_ENTRY).compress_type == zipfile.ZIP_STORED
        map_text = _decrypt_map(archive, _recover_root(archive)).decode("utf-8")
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
        root = _recover_root(archive)
        frame = archive.read(packer.MAP_ENTRY)
        master = key_schedule.dex_master(root, frame)
        for dex in _BUSINESS:
            entry = f"{packer.ASSET_PREFIX}{dex.path}"
            encrypted = archive.read(entry)
            assert archive.getinfo(entry).compress_type == zipfile.ZIP_STORED
            key = key_schedule.frame_key(master, encrypted[: cipher.NONCE_SIZE], entry)
            assert cipher.decrypt(key, encrypted) == dex.data


def testPack_whenTheLibraryCodeIsPatched_theMapNoLongerDecrypts(
    tmp_path: pathlib.Path,
) -> None:
    output = _pack(tmp_path)
    with zipfile.ZipFile(output) as archive:
        root = _recover_root(archive)
        _decrypt_map(archive, root)
    elf = lief.ELF.parse(io.BytesIO(_ARM64_SO))
    assert elf is not None
    text = elf.get_section(runtime_library.TEXT_SECTION)
    assert text is not None
    patched_library = bytearray(_ARM64_SO)
    patched_library[text.offset] ^= 0x01
    repacked = tmp_path / "patched.apk"
    with (
        zipfile.ZipFile(output) as archive,
        zipfile.ZipFile(repacked, "w") as repacked_archive,
    ):
        for name in archive.namelist():
            data = (
                patched_library
                if name == "lib/arm64-v8a/librasp.so"
                else archive.read(name)
            )
            info = archive.getinfo(name)
            repacked_archive.writestr(info, bytes(data))
    with zipfile.ZipFile(repacked) as archive:
        root = _recover_root(archive)
        with pytest.raises(cipher.CipherError):
            _decrypt_map(archive, root)


def testPack_whenAGateFails_theMapNoLongerDecrypts(tmp_path: pathlib.Path) -> None:
    output = _pack(tmp_path)
    dirty_gates = key_schedule.gate_block(
        java_environment=True, no_tracer=True, installed_under_data=False
    )
    with zipfile.ZipFile(output) as archive:
        root = _recover_root(archive, gates=dirty_gates)
        with pytest.raises(cipher.CipherError):
            _decrypt_map(archive, root)


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


def testPack_whenValidApk_addsTheRuntimeLibraryWithTheConfigAndKeystore(
    tmp_path: pathlib.Path,
) -> None:
    output = _pack(tmp_path)
    with zipfile.ZipFile(output) as archive:
        library = archive.read("lib/arm64-v8a/librasp.so")
        names = archive.namelist()

    assert runtime_library.read_config(library) == _CONFIG.to_json()
    assert len(runtime_library.keystore(library)) == key_schedule.KEY_SIZE
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
