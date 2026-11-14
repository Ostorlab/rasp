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
from rasp_packer.android import java_program
from rasp_packer.android import key_schedule
from rasp_packer.android import mapping
from rasp_packer.android import packer
from rasp_packer.android import resources
from rasp_packer.android import runtime_library
from rasp_packer.android import split
from rasp_packer.android.apk import axml
from tests.rasp_packer import conftest
from tests.rasp_packer.android import schedule_recovery

_FIXTURES = pathlib.Path(__file__).parent / "apk" / "fixtures"
_MANIFEST = "manifest_with_application_and_version.bin"
_PACKAGE = "com.example.withapp"
_CONFIG = runtime_config.RuntimeConfig(
    build_id="rasp-build/v1:" + "ab" * 32, checks=("identity",), checks_mask=32
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
    captured: list[tuple[pathlib.Path, str, mapping.ClassMapping | None]] | None = None,
) -> packer.Splitter:
    def splitter(
        app: pathlib.Path,
        package: str,
        class_mapping: mapping.ClassMapping | None = None,
    ) -> split.Split:
        if captured is not None:
            captured.append((app, package, class_mapping))
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
) -> bytes | None:
    """Recovers the root key from a packed APK the way the runtime does on the device."""
    library = archive.read(library_entry)
    entries = {
        name: archive.read(name)
        for name in archive.namelist()
        if name.startswith("assets/")
    }
    return schedule_recovery.recover_root(library, entries, gates, _PACKAGE.encode())


def _decrypt_map(archive: zipfile.ZipFile, root: bytes) -> bytes:
    frame = archive.read(packer.MAP_ENTRY)
    key = key_schedule.frame_key(root, frame[: cipher.NONCE_SIZE], packer.MAP_ENTRY)
    return cipher.decrypt(key, frame)


def _armed_guard(archive: zipfile.ZipFile, root: bytes, map_frame: bytes) -> bytes:
    """Returns the guard that seals the packed dexes: the armed chain over the app's own Java program.

    It decrypts the program the packer shipped, runs its reference the way the stub runs it on a real runtime, and
    derives through the armed master — so what these tests decrypt with is exactly what the device decrypts with
    when the runtime resolves the program's steps as the packer predicted.
    """
    frame = archive.read(packer.JAVA_PROGRAM_ENTRY)
    key = key_schedule.frame_key(
        root, frame[: cipher.NONCE_SIZE], packer.JAVA_PROGRAM_ENTRY
    )
    program = java_program.decode_program(cipher.decrypt(key, frame))
    armed = key_schedule.armed_master(
        key_schedule.seed_from(root, map_frame), java_program.run_reference(program)
    )
    return key_schedule.guarded_master(armed, key_schedule.CLEAN_SENSORS)


def _pack_with_decoy(tmp_path: pathlib.Path) -> tuple[pathlib.Path, str]:
    """Packs until a pack's random fold program names a decoy entry, and returns it and the entry.

    Args:
        tmp_path: The directory to pack into.

    Returns:
        The protected APK and one decoy entry name it holds.
    """
    for attempt in range(10):
        directory = tmp_path / f"round{attempt}"
        directory.mkdir()
        output = _pack(directory)
        with zipfile.ZipFile(output) as archive:
            decoys = [name for name in archive.namelist() if "assets/rasp/r" in name]
        if decoys:
            return output, decoys[0]
    pytest.fail("no pack drew a decoy entry in ten rounds")


def testPack_whenValidApk_splitsOnTheManifestPackage(tmp_path: pathlib.Path) -> None:
    app = tmp_path / "app.apk"
    _make_apk(app)
    captured: list[tuple[pathlib.Path, str, mapping.ClassMapping | None]] = []
    packer.pack(
        app=app,
        output=tmp_path / "out.apk",
        config=_CONFIG,
        artifacts=_artifacts(),
        splitter=_recorded_split(captured),
    )
    assert captured == [(app, _PACKAGE, None)]


def testPack_whenMappingGiven_parsesItAndPassesItToTheSplitter(
    tmp_path: pathlib.Path,
) -> None:
    app = tmp_path / "app.apk"
    _make_apk(app)
    mapping_file = tmp_path / "mapping.txt"
    mapping_file.write_text(f"myapp.Entry -> {_PACKAGE}.a:\n", encoding="utf-8")
    captured: list[tuple[pathlib.Path, str, mapping.ClassMapping | None]] = []

    packer.pack(
        app=app,
        output=tmp_path / "out.apk",
        config=_CONFIG,
        mapping=mapping_file,
        artifacts=_artifacts(),
        splitter=_recorded_split(captured),
    )

    _, _, class_mapping = captured[0]
    assert class_mapping is not None
    assert class_mapping.business_packages("myapp") == frozenset({_PACKAGE})


def testPack_whenMappingCannotBeRead_raisesMappingError(
    tmp_path: pathlib.Path,
) -> None:
    app = tmp_path / "app.apk"
    _make_apk(app)

    with pytest.raises(mapping.MappingError, match="cannot read mapping"):
        packer.pack(
            app=app,
            output=tmp_path / "out.apk",
            config=_CONFIG,
            mapping=tmp_path / "does-not-exist.txt",
            artifacts=_artifacts(),
            splitter=_recorded_split(),
        )


def testPack_whenMappingIsNotUtf8_raisesMappingError(
    tmp_path: pathlib.Path,
) -> None:
    app = tmp_path / "app.apk"
    _make_apk(app)
    mapping_file = tmp_path / "mapping.txt"
    mapping_file.write_bytes(b"app.Main -> a.b:\n\xff\xfe\n")

    with pytest.raises(mapping.MappingError, match="cannot read mapping"):
        packer.pack(
            app=app,
            output=tmp_path / "out.apk",
            config=_CONFIG,
            mapping=mapping_file,
            artifacts=_artifacts(),
            splitter=_recorded_split(),
        )


def testPack_whenValidApk_writesNoKeyEntry(tmp_path: pathlib.Path) -> None:
    output = _pack(tmp_path)
    with zipfile.ZipFile(output) as archive:
        names = set(archive.namelist())
    assert "assets/rasp/key.bin" not in names


def testPack_whenValidApk_writesTheScheduleShareStored(tmp_path: pathlib.Path) -> None:
    output = _pack(tmp_path)
    with zipfile.ZipFile(output) as archive:
        info = archive.getinfo(packer.SHARE_ENTRY)
        assert len(archive.read(packer.SHARE_ENTRY)) == key_schedule.KEY_SIZE
    assert info.compress_type == zipfile.ZIP_STORED


def testPack_whenValidApk_writesTheDecoyEntriesStored(tmp_path: pathlib.Path) -> None:
    # The fold program draws its decoy kinds at random, so a pack may name no decoy entry; a few
    # packs always draw one, and every pack must write exactly the entries its program names.
    output, _first = _pack_with_decoy(tmp_path)
    with zipfile.ZipFile(output) as archive:
        for name in archive.namelist():
            if "assets/rasp/r" in name:
                assert archive.getinfo(name).compress_type == zipfile.ZIP_STORED
                assert len(archive.read(name)) == key_schedule.KEY_SIZE


def testPack_whenValidApk_recoversTheRootFromTheShippedArtifacts(
    tmp_path: pathlib.Path,
) -> None:
    output = _pack(tmp_path)
    with zipfile.ZipFile(output) as archive:
        root = _recover_root(archive)
        assert root is not None
        with pytest.raises(cipher.CipherError):
            # The root is random per packing, so a wrong root must fail; here the map decrypts
            # below, proving the recovery is exact and not accidental.
            _decrypt_map(archive, bytes(key_schedule.KEY_SIZE))
        assert len(root) == key_schedule.KEY_SIZE
        map_text = _decrypt_map(archive, root).decode("utf-8")
    lines = [line for line in map_text.splitlines() if line]
    assert len(lines) == 3


def testPack_whenValidApk_writesAnEncryptedMapThatNamesEveryBusinessClass(
    tmp_path: pathlib.Path,
) -> None:
    output = _pack(tmp_path)
    with zipfile.ZipFile(output) as archive:
        assert archive.getinfo(packer.MAP_ENTRY).compress_type == zipfile.ZIP_STORED
        root = _recover_root(archive)
        assert root is not None
        map_text = _decrypt_map(archive, root).decode("utf-8")
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
        assert root is not None
        frame = archive.read(packer.MAP_ENTRY)
        guard = _armed_guard(archive, root, frame)
        for dex in _BUSINESS:
            entry = f"{packer.ASSET_PREFIX}{dex.path}"
            encrypted = archive.read(entry)
            assert archive.getinfo(entry).compress_type == zipfile.ZIP_STORED
            key = key_schedule.frame_key(guard, encrypted[: cipher.NONCE_SIZE], entry)
            assert cipher.decrypt(key, encrypted) == dex.data


def testPack_whenEveryPackDrawsAFreshFold_recoversEveryTime(
    tmp_path: pathlib.Path,
) -> None:
    # Different packs draw different fold programs, orders and decoys; every one must recover.
    for round_index in range(3):
        directory = tmp_path / f"round{round_index}"
        directory.mkdir()
        output = _pack(directory)
        with zipfile.ZipFile(output) as archive:
            root = _recover_root(archive)
            assert root is not None
            _decrypt_map(archive, root)


def testPack_whenTheLibraryCodeIsPatched_theMapNoLongerDecrypts(
    tmp_path: pathlib.Path,
) -> None:
    output = _pack(tmp_path)
    with zipfile.ZipFile(output) as archive:
        root = _recover_root(archive)
        assert root is not None
        _decrypt_map(archive, root)
    elf = lief.ELF.parse(io.BytesIO(_ARM64_SO))
    assert elf is not None
    text = elf.get_section(".text")
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
        assert root is not None
        with pytest.raises(cipher.CipherError):
            _decrypt_map(archive, root)


def testPack_whenTheFoldProgramIsPatched_theMapNoLongerDecrypts(
    tmp_path: pathlib.Path,
) -> None:
    output = _pack(tmp_path)
    with zipfile.ZipFile(output) as archive:
        library = archive.read("lib/arm64-v8a/librasp.so")
        root = _recover_root(archive)
        assert root is not None
        _decrypt_map(archive, root)
    elf = lief.ELF.parse(io.BytesIO(library))
    assert elf is not None
    section = elf.get_section(".init")
    assert section is not None
    program_offset = (
        section.offset
        + section.size
        - key_schedule.PROGRAM_SIZE
        - key_schedule.KEY_SIZE
    )
    patched_library = bytearray(library)
    patched_library[program_offset + 100] ^= 0x01
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
        assert root is not None
        with pytest.raises(cipher.CipherError):
            _decrypt_map(archive, root)


def testPack_whenADecoyEntryIsRemoved_theRootNoLongerRecovers(
    tmp_path: pathlib.Path,
) -> None:
    # A pack names decoy entries only when its random fold program drew them; find one that did.
    for attempt in range(10):
        directory = tmp_path / f"round{attempt}"
        directory.mkdir()
        output = _pack(directory)
        with zipfile.ZipFile(output) as archive:
            decoys = [name for name in archive.namelist() if "assets/rasp/r" in name]
        if decoys:
            break
    else:
        pytest.fail("no pack drew a decoy entry in ten rounds")
    stripped = tmp_path / "stripped.apk"
    with (
        zipfile.ZipFile(output) as archive,
        zipfile.ZipFile(stripped, "w") as stripped_archive,
    ):
        for name in archive.namelist():
            if name == decoys[0]:
                continue
            stripped_archive.writestr(archive.getinfo(name), archive.read(name))
    with zipfile.ZipFile(stripped) as archive:
        assert _recover_root(archive) is None


def testPack_whenAGateFails_theMapNoLongerDecrypts(tmp_path: pathlib.Path) -> None:
    output = _pack(tmp_path)
    dirty_gates = key_schedule.gate_block(
        java_environment=True, no_tracer=True, installed_under_data=False
    )
    with zipfile.ZipFile(output) as archive:
        root = _recover_root(archive, gates=dirty_gates)
        assert root is not None
        with pytest.raises(cipher.CipherError):
            _decrypt_map(archive, root)


def testPack_whenASensorWouldFail_theDexesNoLongerDecrypt(
    tmp_path: pathlib.Path,
) -> None:
    output = _pack(tmp_path)
    dirty_sensors = key_schedule.sensor_block(no_tracer=False, text_intact=True)
    with zipfile.ZipFile(output) as archive:
        root = _recover_root(archive)
        assert root is not None
        frame = archive.read(packer.MAP_ENTRY)
        guard = key_schedule.guarded_master(
            key_schedule.seed_from(root, frame), dirty_sensors
        )
        for dex in _BUSINESS:
            entry = f"{packer.ASSET_PREFIX}{dex.path}"
            encrypted = archive.read(entry)
            key = key_schedule.frame_key(guard, encrypted[: cipher.NONCE_SIZE], entry)
            with pytest.raises(cipher.CipherError):
                cipher.decrypt(key, encrypted)


def testPack_whenTheAppShipsTwoAbis_bothRecoverTheSameRoot(
    tmp_path: pathlib.Path,
) -> None:
    artifacts = resources.Artifacts(
        stub_dex=_STUB_DEX,
        libraries={"arm64-v8a": _ARM64_SO, "x86_64": _ARM64_SO},
    )
    output = _pack(
        tmp_path,
        native_libraries=["lib/arm64-v8a/libapp.so", "lib/x86_64/libapp.so"],
        artifacts=artifacts,
    )
    with zipfile.ZipFile(output) as archive:
        root_arm64 = _recover_root(archive, library_entry="lib/arm64-v8a/librasp.so")
        root_x86 = _recover_root(archive, library_entry="lib/x86_64/librasp.so")

    assert root_arm64 is not None
    assert root_x86 == root_arm64


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


def testPack_whenValidApk_addsTheRuntimeLibraryWithTheConfigProgramAndKeystore(
    tmp_path: pathlib.Path,
) -> None:
    output = _pack(tmp_path)
    with zipfile.ZipFile(output) as archive:
        library = archive.read("lib/arm64-v8a/librasp.so")
        names = archive.namelist()

    # The placed library is self-encrypted — not the plain config-written library — but the fold's
    # config, program and keystore still read back from its untouched `.rasp_config` section.
    assert library != runtime_library.write_config(_ARM64_SO, _CONFIG)
    assert runtime_library.read_config(library) == _CONFIG.to_json()
    assert len(runtime_library.keystore(library)) == key_schedule.KEY_SIZE
    assert key_schedule.decode_program(runtime_library.program(library)) is not None
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
