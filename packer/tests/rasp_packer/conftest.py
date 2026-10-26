"""Fixtures: arm64 iOS executables, IPAs, a runtime framework and plugin bundles."""

import collections.abc
import itertools
import json
import pathlib
import plistlib
import shutil
import zipfile

import pytest

_DATA = pathlib.Path(__file__).parent / "ios" / "data"
PACKAGE_NAME = "dev.ostorlab.demo"
VERSION = "1.2.3"
APP_INFO = {
    "CFBundleExecutable": "Demo",
    "CFBundleIdentifier": PACKAGE_NAME,
    "CFBundleShortVersionString": VERSION,
}


@pytest.fixture
def executable(tmp_path: pathlib.Path) -> pathlib.Path:
    return pathlib.Path(shutil.copy(_DATA / "arm64_app", tmp_path / "Demo"))


@pytest.fixture
def signed_executable(tmp_path: pathlib.Path) -> pathlib.Path:
    return pathlib.Path(shutil.copy(_DATA / "arm64_app_signed", tmp_path / "Demo"))


@pytest.fixture
def runtime(tmp_path: pathlib.Path) -> pathlib.Path:
    framework = tmp_path / "runtime" / "RaspRuntime.framework"
    framework.mkdir(parents=True)
    (framework / "RaspRuntime").write_bytes(b"runtime binary")
    (framework / "Info.plist").write_bytes(
        plistlib.dumps(
            {
                "CFBundleIdentifier": "co.ostorlab.rasp.runtime",
                "CFBundleExecutable": "RaspRuntime",
            }
        )
    )
    return framework


@pytest.fixture
def make_ipa(tmp_path: pathlib.Path) -> collections.abc.Callable[..., pathlib.Path]:
    def make(
        *,
        executable_source: pathlib.Path = _DATA / "arm64_app",
        extra_entries: collections.abc.Mapping[str, bytes] | None = None,
        info: collections.abc.Mapping[str, str] | None = None,
    ) -> pathlib.Path:
        path = tmp_path / "Demo.ipa"
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr(
                "Payload/Demo.app/Info.plist",
                plistlib.dumps(dict(APP_INFO if info is None else info)),
            )
            binary = zipfile.ZipInfo("Payload/Demo.app/Demo")
            binary.external_attr = 0o100755 << 16
            archive.writestr(binary, executable_source.read_bytes())
            archive.writestr(
                "Payload/Demo.app/_CodeSignature/CodeResources", b"signature"
            )
            if extra_entries is not None:
                for name, content in extra_entries.items():
                    archive.writestr(name, content)
        return path

    return make


@pytest.fixture
def ipa_file(make_ipa: collections.abc.Callable[..., pathlib.Path]) -> pathlib.Path:
    return make_ipa()


@pytest.fixture
def make_plugin(
    tmp_path: pathlib.Path,
) -> collections.abc.Callable[..., pathlib.Path]:
    """Gives a function that writes a plugin bundle and returns its directory.

    The library of each ABI holds `<name> <abi>`, and the framework binary `<name> ios`.
    """
    counter = itertools.count()

    def make(
        *,
        name: str = "example",
        abis: collections.abc.Sequence[str] = ("arm64-v8a",),
        ios: bool = True,
        config: bytes | None = None,
        manifest: collections.abc.Mapping[str, object] | None = None,
    ) -> pathlib.Path:
        directory = tmp_path / "plugins" / f"{next(counter)}-{name}"
        directory.mkdir(parents=True)
        document = (
            {"name": name, "version": "1.0.0", "api_version": 1}
            if manifest is None
            else manifest
        )
        (directory / "plugin.json").write_text(json.dumps(document))
        for abi in abis:
            library = directory / "android" / abi / f"librasp_plugin_{name}.so"
            library.parent.mkdir(parents=True)
            library.write_bytes(f"{name} {abi}".encode())
        if ios is True:
            framework = directory / "ios" / f"rasp_plugin_{name}.framework"
            framework.mkdir(parents=True)
            (framework / f"rasp_plugin_{name}").write_bytes(f"{name} ios".encode())
            (framework / "Info.plist").write_bytes(
                plistlib.dumps({"CFBundleExecutable": f"rasp_plugin_{name}"})
            )
        if config is not None:
            (directory / "config").write_bytes(config)
        return directory

    return make
