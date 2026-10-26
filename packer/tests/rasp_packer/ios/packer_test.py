"""Tests of packing an IPA."""

import collections.abc
import pathlib
import plistlib
import stat
import zipfile

import lief
import pytest

from rasp_packer import errors
from rasp_packer import identity
from rasp_packer import plugins
from rasp_packer.ios import macho
from rasp_packer.ios import packer
from tests.rasp_packer import conftest

_BUILD_ID = "build-1"
_APP = "Payload/Demo.app"
_FRAMEWORK = f"{_APP}/Frameworks/RaspRuntime.framework"


def _pack(
    app: pathlib.Path, runtime: pathlib.Path, output: pathlib.Path
) -> zipfile.ZipFile:
    """Packs the app with the test build id and opens the protected IPA."""
    packer.pack(app=app, output=output, runtime=runtime, build_id=_BUILD_ID)
    return zipfile.ZipFile(output)


def testPack_whenValidIpa_makesTheExecutableLoadTheRuntime(
    ipa_file: pathlib.Path, runtime: pathlib.Path, tmp_path: pathlib.Path
) -> None:
    with _pack(ipa_file, runtime, tmp_path / "out.ipa") as archive:
        executable = tmp_path / "Demo"
        executable.write_bytes(archive.read(f"{_APP}/Demo"))
        mode = stat.S_IMODE(archive.getinfo(f"{_APP}/Demo").external_attr >> 16)

    fat = lief.MachO.parse(str(executable))
    assert fat is not None
    binary = fat.take(lief.MachO.Header.CPU_TYPE.ARM64)
    assert binary is not None
    assert macho.RUNTIME_INSTALL_NAME in [library.name for library in binary.libraries]
    assert mode == 0o755


def testPack_whenValidIpa_embedsTheRuntimeWithTheBuildId(
    ipa_file: pathlib.Path, runtime: pathlib.Path, tmp_path: pathlib.Path
) -> None:
    with _pack(ipa_file, runtime, tmp_path / "out.ipa") as archive:
        binary = archive.read(f"{_FRAMEWORK}/RaspRuntime")
        info = plistlib.loads(archive.read(f"{_FRAMEWORK}/Info.plist"))

    assert binary == b"runtime binary"
    assert info[packer.RASP_BUILD_ID_KEY] == _BUILD_ID


def testPack_whenValidIpa_returnsTheAppIdentity(
    ipa_file: pathlib.Path, runtime: pathlib.Path, tmp_path: pathlib.Path
) -> None:
    app_identity = packer.pack(
        app=ipa_file, output=tmp_path / "out.ipa", runtime=runtime, build_id=_BUILD_ID
    )

    assert app_identity == identity.AppIdentity(
        package_name=conftest.PACKAGE_NAME, version=conftest.VERSION
    )


def testPack_whenAppWasSigned_removesItsSignature(
    ipa_file: pathlib.Path, runtime: pathlib.Path, tmp_path: pathlib.Path
) -> None:
    with _pack(ipa_file, runtime, tmp_path / "out.ipa") as archive:
        names = archive.namelist()

    assert all("_CodeSignature" not in name for name in names)


def testPack_whenAppEmbedsTheRuntimeAlready_raisesAlreadyProtectedError(
    make_ipa: collections.abc.Callable[..., pathlib.Path],
    runtime: pathlib.Path,
    tmp_path: pathlib.Path,
) -> None:
    app = make_ipa(extra_entries={f"{_FRAMEWORK}/RaspRuntime": b""})

    with pytest.raises(errors.AlreadyProtectedError):
        packer.pack(
            app=app, output=tmp_path / "out.ipa", runtime=runtime, build_id=_BUILD_ID
        )


@pytest.mark.parametrize("missing", ["RaspRuntime", "Info.plist"])
def testPack_whenRuntimeIsIncomplete_raisesInvalidRuntimeError(
    ipa_file: pathlib.Path, runtime: pathlib.Path, tmp_path: pathlib.Path, missing: str
) -> None:
    (runtime / missing).unlink()

    with pytest.raises(errors.InvalidRuntimeError, match=missing):
        packer.pack(
            app=ipa_file,
            output=tmp_path / "out.ipa",
            runtime=runtime,
            build_id=_BUILD_ID,
        )


def testPack_whenRuntimeIsNotTheFramework_raisesInvalidRuntimeError(
    ipa_file: pathlib.Path, tmp_path: pathlib.Path
) -> None:
    with pytest.raises(errors.InvalidRuntimeError):
        packer.pack(
            app=ipa_file,
            output=tmp_path / "out.ipa",
            runtime=tmp_path,
            build_id=_BUILD_ID,
        )


def _pack_with_plugins(
    app: pathlib.Path,
    runtime: pathlib.Path,
    output: pathlib.Path,
    bundles: collections.abc.Sequence[pathlib.Path],
) -> zipfile.ZipFile:
    """Packs the app with the given plugin bundles and opens the protected IPA."""
    packer.pack(
        app=app,
        output=output,
        runtime=runtime,
        build_id=_BUILD_ID,
        plugins=plugins.load_all(bundles),
    )
    return zipfile.ZipFile(output)


def testPack_whenPluginsAreGiven_embedsTheirFrameworks(
    ipa_file: pathlib.Path,
    runtime: pathlib.Path,
    tmp_path: pathlib.Path,
    make_plugin: collections.abc.Callable[..., pathlib.Path],
) -> None:
    with _pack_with_plugins(
        ipa_file, runtime, tmp_path / "out.ipa", [make_plugin(name="example")]
    ) as archive:
        framework = f"{_APP}/Frameworks/rasp_plugin_example.framework"
        binary = archive.read(f"{framework}/rasp_plugin_example")
        info = plistlib.loads(archive.read(f"{framework}/Info.plist"))

    assert binary == b"example ios"
    assert info["CFBundleExecutable"] == "rasp_plugin_example"


def testPack_whenPluginsAreGiven_writesTheListAndConfigsIntoTheRuntime(
    ipa_file: pathlib.Path,
    runtime: pathlib.Path,
    tmp_path: pathlib.Path,
    make_plugin: collections.abc.Callable[..., pathlib.Path],
) -> None:
    bundles = [make_plugin(name="zeta", config=b"z=1"), make_plugin(name="alpha")]

    with _pack_with_plugins(
        ipa_file, runtime, tmp_path / "out.ipa", bundles
    ) as archive:
        names = archive.namelist()
        plugin_list = archive.read(f"{_FRAMEWORK}/plugins.list")
        zeta_config = archive.read(f"{_FRAMEWORK}/plugin-config/zeta")

    assert plugin_list == b"zeta\nalpha\n"
    assert zeta_config == b"z=1"
    assert f"{_FRAMEWORK}/plugin-config/alpha" not in names


def testPack_whenNoPluginIsGiven_writesNoPluginList(
    ipa_file: pathlib.Path, runtime: pathlib.Path, tmp_path: pathlib.Path
) -> None:
    with _pack(ipa_file, runtime, tmp_path / "out.ipa") as archive:
        names = archive.namelist()

    assert f"{_FRAMEWORK}/plugins.list" not in names


def testPack_whenAPluginHasNoIosBuild_raisesInvalidPluginError(
    ipa_file: pathlib.Path,
    runtime: pathlib.Path,
    tmp_path: pathlib.Path,
    make_plugin: collections.abc.Callable[..., pathlib.Path],
) -> None:
    with pytest.raises(
        errors.InvalidPluginError, match="without an iOS build: example"
    ):
        _pack_with_plugins(
            ipa_file, runtime, tmp_path / "out.ipa", [make_plugin(ios=False)]
        )
    assert (tmp_path / "out.ipa").exists() is False


def testPack_whenTheAppAlreadyEmbedsThePluginsFramework_raisesInvalidPluginError(
    make_ipa: collections.abc.Callable[..., pathlib.Path],
    runtime: pathlib.Path,
    tmp_path: pathlib.Path,
    make_plugin: collections.abc.Callable[..., pathlib.Path],
) -> None:
    app = make_ipa(
        extra_entries={
            f"{_APP}/Frameworks/rasp_plugin_example.framework/rasp_plugin_example": b""
        }
    )

    with pytest.raises(errors.InvalidPluginError, match="already embeds"):
        _pack_with_plugins(app, runtime, tmp_path / "out.ipa", [make_plugin()])
