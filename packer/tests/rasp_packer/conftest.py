"""Fixtures: arm64 iOS executables, IPAs, a runtime framework, stand-ins for the runtime's binaries, and a test deadline."""

import collections.abc
import pathlib
import plistlib
import shutil
import signal
import types
import zipfile

import pytest

_DATA = pathlib.Path(__file__).parent / "ios" / "data"
RUNTIME_CONFIG_DATA = pathlib.Path(__file__).parent / "data" / "runtime_config"
STUB_DEX = pathlib.Path(__file__).parent / "data" / "stub.dex"
PACKAGE_NAME = "dev.ostorlab.demo"
VERSION = "1.2.3"
APP_INFO = {
    "CFBundleExecutable": "Demo",
    "CFBundleIdentifier": PACKAGE_NAME,
    "CFBundleShortVersionString": VERSION,
}

_DEADLINE_SECONDS = 5


@pytest.fixture
def deadline() -> collections.abc.Iterator[None]:
    """Fails the test with TimeoutError when it runs too long, instead of letting it hang."""

    def expire(signal_number: int, frame: types.FrameType | None) -> None:
        raise TimeoutError(f"the test still ran after {_DEADLINE_SECONDS} seconds")

    previous = signal.signal(signal.SIGALRM, expire)
    signal.alarm(_DEADLINE_SECONDS)
    try:
        yield
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)


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
    shutil.copy(RUNTIME_CONFIG_DATA / "RaspRuntime", framework / "RaspRuntime")
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
