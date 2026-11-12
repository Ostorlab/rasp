"""End-to-end tests of the AAB packer, with a recorded split."""

import pathlib
import zipfile

import pytest

from rasp_packer import errors
from rasp_packer import runtime_config
from rasp_packer.android import cipher
from rasp_packer.android import packer
from rasp_packer.android import resources
from rasp_packer.android import runtime_library
from rasp_packer.android import split
from rasp_packer.android.aab import proto_manifest
from tests.rasp_packer import conftest

_FIXTURE = (
    pathlib.Path(__file__).resolve().parents[3]
    / "apps"
    / "android"
    / "InsecureBankv2.aab"
)
_BUILD_ID = "rasp-build/v1:" + "ab" * 32
_STUB_DEX = b"stub dex bytes"
_ARM64_SO = (conftest.RUNTIME_CONFIG_DATA / "librasp.so").read_bytes()
_PACKAGE = "com.android.insecurebankv2"
_CONFIG = runtime_config.RuntimeConfig(build_id=_BUILD_ID, checks=("identity",))

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


def _proto_manifest() -> bytes:
    """Return the proto manifest from the real AAB fixture."""
    with zipfile.ZipFile(_FIXTURE) as zf:
        return zf.read("base/manifest/AndroidManifest.xml")


def _make_aab(
    path: pathlib.Path,
    *,
    native_libraries: list[str] | None = None,
    extra: dict[str, bytes] | None = None,
) -> None:
    """Build a synthetic AAB with the real proto manifest."""
    manifest = _proto_manifest()
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("BundleConfig.pb", b"\x0a\x08\x22\x06" + b"1.15.0")
        zf.writestr("base/manifest/AndroidManifest.xml", manifest)
        zf.writestr("base/dex/classes.dex", b"app primary dex")
        zf.writestr("base/dex/classes2.dex", b"app secondary dex")
        for lib in native_libraries or []:
            zf.writestr(lib, b"native code")
        for name, data in (extra or {}).items():
            zf.writestr(name, data)


def _recorded_aab_split(
    captured: list[tuple[dict[str, bytes], str]] | None = None,
) -> packer.AabSplitter:
    def splitter(dex_entries: dict[str, bytes], package: str) -> split.Split:
        if captured is not None:
            captured.append((dex_entries, package))
        return split.Split(framework=_FRAMEWORK, business=_BUSINESS)

    return splitter


def _pack_aab(
    tmp_path: pathlib.Path,
    *,
    native_libraries: list[str] | None = None,
    artifacts: resources.Artifacts | None = None,
) -> pathlib.Path:
    app = tmp_path / "app.aab"
    output = tmp_path / "protected.aab"
    _make_aab(app, native_libraries=native_libraries)
    packer.pack(
        app=app,
        output=output,
        config=runtime_config.RuntimeConfig(build_id=_BUILD_ID, checks=("identity",)),
        artifacts=artifacts or _artifacts(),
        aab_splitter=_recorded_aab_split(),
    )
    return output


# ── format detection ─────────────────────────────────────────


def testPack_whenAab_detectsFormatAndUsesAabPath(tmp_path: pathlib.Path) -> None:
    app = tmp_path / "app.aab"
    _make_aab(app)
    captured: list[tuple[dict[str, bytes], str]] = []
    packer.pack(
        app=app,
        output=tmp_path / "out.aab",
        config=runtime_config.RuntimeConfig(build_id=_BUILD_ID, checks=("identity",)),
        artifacts=_artifacts(),
        aab_splitter=_recorded_aab_split(captured),
    )
    assert len(captured) == 1
    dex_entries, package = captured[0]
    assert package == _PACKAGE
    assert "classes.dex" in dex_entries
    assert "classes2.dex" in dex_entries


# ── key, map, config ────────────────────────────────────────


def testPackAab_writesTheRawKey(tmp_path: pathlib.Path) -> None:
    output = _pack_aab(tmp_path)
    with zipfile.ZipFile(output) as zf:
        assert len(zf.read(packer.AAB_KEY_ENTRY)) == cipher.KEY_SIZE


def testPackAab_writesTheConfigIntoLibrasp(tmp_path: pathlib.Path) -> None:
    output = _pack_aab(tmp_path)
    with zipfile.ZipFile(output) as zf:
        library = zf.read("base/lib/arm64-v8a/librasp.so")
    assert library == runtime_library.write_config(_ARM64_SO, _CONFIG)
    assert runtime_library.read_config(library) == _CONFIG.to_json()


def testPackAab_writesEncryptedMapThatNamesEveryBusinessClass(
    tmp_path: pathlib.Path,
) -> None:
    output = _pack_aab(tmp_path)
    with zipfile.ZipFile(output) as zf:
        key = zf.read(packer.AAB_KEY_ENTRY)
        map_text = cipher.decrypt(key, zf.read(packer.AAB_MAP_ENTRY)).decode("utf-8")
        names = set(zf.namelist())
    lines = [line for line in map_text.splitlines() if len(line) > 0]
    assert len(lines) == 3
    mapped: dict[str, str] = {}
    for line in lines:
        name, _, path = line.partition(",")
        mapped[name] = path
    assert set(mapped) == {
        f"{_PACKAGE}.A",
        f"{_PACKAGE}.B",
        f"{_PACKAGE}.sub.C",
    }
    for path in set(mapped.values()):
        assert f"{packer.AAB_ASSET_PREFIX}{path}" in names


# ── encrypted business DEX ───────────────────────────────────


def testPackAab_writesEachBusinessDexEncrypted(tmp_path: pathlib.Path) -> None:
    output = _pack_aab(tmp_path)
    with zipfile.ZipFile(output) as zf:
        key = zf.read(packer.AAB_KEY_ENTRY)
        for dex in _BUSINESS:
            entry = f"{packer.AAB_ASSET_PREFIX}{dex.path}"
            assert cipher.decrypt(key, zf.read(entry)) == dex.data


# ── framework + stub as base DEX ─────────────────────────────


def testPackAab_shipsFrameworkAndStubUnderBaseDex(tmp_path: pathlib.Path) -> None:
    output = _pack_aab(tmp_path)
    with zipfile.ZipFile(output) as zf:
        assert zf.read("base/dex/classes.dex") == _FRAMEWORK[0]
        assert zf.read("base/dex/classes2.dex") == _FRAMEWORK[1]
        assert zf.read("base/dex/classes3.dex") == _STUB_DEX
        names = set(zf.namelist())
    assert "base/dex/classes4.dex" not in names


# ── runtime library ──────────────────────────────────────────


def testPackAab_addsRuntimeLibraryUnderBaseLib(tmp_path: pathlib.Path) -> None:
    output = _pack_aab(tmp_path)
    with zipfile.ZipFile(output) as zf:
        assert zf.read("base/lib/arm64-v8a/librasp.so") == runtime_library.write_config(
            _ARM64_SO, _CONFIG
        )


# ── manifest patching ────────────────────────────────────────


def testPackAab_setsComponentFactoryAndRaisesMinSdk(tmp_path: pathlib.Path) -> None:
    output = _pack_aab(tmp_path)
    with zipfile.ZipFile(output) as zf:
        manifest = zf.read("base/manifest/AndroidManifest.xml")
    assert (
        proto_manifest.read_app_component_factory(manifest)
        == resources.STUB_FACTORY_CLASS
    )
    assert proto_manifest.read_min_sdk_version(manifest) == packer.MINIMUM_API_LEVEL


# ── original DEX removed ─────────────────────────────────────


def testPackAab_removesOriginalDexEntries(tmp_path: pathlib.Path) -> None:
    output = _pack_aab(tmp_path)
    with zipfile.ZipFile(output) as zf:
        assert zf.read("base/dex/classes.dex") != b"app primary dex"


# ── preserves BundleConfig.pb ─────────────────────────────────


def testPackAab_preservesBundleConfig(tmp_path: pathlib.Path) -> None:
    output = _pack_aab(tmp_path)
    with zipfile.ZipFile(output) as zf:
        assert "BundleConfig.pb" in zf.namelist()


# ── already protected ────────────────────────────────────────


def testPackAab_whenAlreadyHasMap_raisesAlreadyProtectedError(
    tmp_path: pathlib.Path,
) -> None:
    app = tmp_path / "app.aab"
    _make_aab(app, extra={packer.AAB_MAP_ENTRY: b"already"})
    with pytest.raises(errors.AlreadyProtectedError):
        packer.pack(
            app=app,
            output=tmp_path / "out.aab",
            config=runtime_config.RuntimeConfig(
                build_id=_BUILD_ID, checks=("identity",)
            ),
            artifacts=_artifacts(),
            aab_splitter=_recorded_aab_split(),
        )


# ── unsupported ABI ──────────────────────────────────────────


def testPackAab_whenAppAbiHasNoRuntime_raisesUnsupportedAbiError(
    tmp_path: pathlib.Path,
) -> None:
    with pytest.raises(errors.UnsupportedAbiError):
        _pack_aab(tmp_path, native_libraries=["base/lib/armeabi-v7a/libapp.so"])


# ── identity ─────────────────────────────────────────────────


def testPackAab_returnsTheAppIdentity(tmp_path: pathlib.Path) -> None:
    app = tmp_path / "app.aab"
    _make_aab(app)
    app_identity = packer.pack(
        app=app,
        output=tmp_path / "out.aab",
        config=runtime_config.RuntimeConfig(build_id=_BUILD_ID, checks=("identity",)),
        artifacts=_artifacts(),
        aab_splitter=_recorded_aab_split(),
    )
    assert app_identity.package_name == _PACKAGE
    assert app_identity.version == "1.0"


@pytest.mark.parametrize("selected", [True, False])
def testPack_whenRootPackagesSelected_addsOnlyExactOptInQueries(
    tmp_path: pathlib.Path, selected: bool
) -> None:
    app = tmp_path / "app.aab"
    output = tmp_path / "protected.aab"
    _make_aab(app)
    config = runtime_config.RuntimeConfig(
        build_id=_BUILD_ID,
        checks=("identity", "root_packages") if selected else ("identity",),
    )
    packer.pack(
        app=app,
        output=output,
        config=config,
        artifacts=_artifacts(),
        aab_splitter=_recorded_aab_split(),
    )
    with zipfile.ZipFile(output) as archive:
        manifest = archive.read("base/manifest/AndroidManifest.xml")
    assert proto_manifest.read_package_queries(manifest) == (
        resources.ROOT_MANAGER_PACKAGES_V1 if selected else ()
    )
    assert b"QUERY_ALL_PACKAGES" not in manifest


@pytest.mark.parametrize("oversize", ["map", "map_utf8", "dex"])
def testPack_whenPayloadExceedsRuntimeLimit_rejectsBeforePublication(
    tmp_path: pathlib.Path, oversize: str
) -> None:
    app = tmp_path / "app.aab"
    output = tmp_path / "protected.aab"
    _make_aab(app)
    business = split.BusinessDex(
        path="business/0.dex",
        data=b"x" * (64 * 1024 * 1024 + 1) if oversize == "dex" else b"dex",
        classes=(
            ("x" * (8 * 1024 * 1024),)
            if oversize == "map"
            else ("é" * (4 * 1024 * 1024),)
            if oversize == "map_utf8"
            else (f"{_PACKAGE}.A",)
        ),
    )

    def splitter(app_data: object, package: str) -> split.Split:
        return split.Split(framework=_FRAMEWORK, business=(business,))

    with pytest.raises(errors.InvalidAppError, match="runtime payload limit"):
        packer.pack(
            app=app,
            output=output,
            config=_CONFIG,
            artifacts=_artifacts(),
            aab_splitter=splitter,
        )
    assert output.exists() is False
    assert list(tmp_path.glob(".rasp-*")) == []
