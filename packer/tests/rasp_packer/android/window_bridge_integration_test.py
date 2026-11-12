"""Optional real SDK/NDK APK+AAB integration; never a device or finalized catalogue claim.

Build the RT10 stub/device/native artifacts first, then set RASP_WINDOW_STUB,
RASP_WINDOW_HOST_APK and RASP_WINDOW_NATIVE_DIRECTORY (parent of ABI directories).
This fixture explicitly tests the unknown-capability path by omitting sidecars;
installed-wheel validation additionally exercises exact current release bindings. No splitter, verifier or native bytes are mocked.
"""

from __future__ import annotations

import os
import pathlib
import zipfile

import pytest

from rasp_packer import checks
from rasp_packer import platforms
from rasp_packer import runtime_config
from rasp_packer.android import packer
from rasp_packer.android import resources
from rasp_packer.android import runtime_library

_REQUIRED = (
    "RASP_WINDOW_STUB",
    "RASP_WINDOW_HOST_APK",
    "RASP_WINDOW_NATIVE_DIRECTORY",
)
_ABIS = ("arm64-v8a", "armeabi-v7a", "x86", "x86_64")


@pytest.mark.skipif(
    any(os.environ.get(name) is None for name in _REQUIRED),
    reason="requires real compiled RT10 SDK/NDK artifacts (see module docstring)",
)
@pytest.mark.parametrize("artifact_format", ["apk", "aab"])
def testWindowBridge_whenRealCompiledArtifactsPacked_preservesSingleBridgeAndSelection(
    artifact_format: str, tmp_path: pathlib.Path
) -> None:
    native = pathlib.Path(os.environ["RASP_WINDOW_NATIVE_DIRECTORY"])
    stub = pathlib.Path(os.environ["RASP_WINDOW_STUB"]).read_bytes()
    assert stub.startswith(b"dex\n")
    assert b"Lco/ostorlab/rasp/RuntimeBridge;" in stub
    assert b"Lco/ostorlab/rasp/RuntimeBridge$TouchCallback;" in stub
    assert b"startWindowObservation" in stub
    libraries = {abi: (native / abi / "librasp.so").read_bytes() for abi in _ABIS}
    artifacts = resources.Artifacts(stub_dex=stub, libraries=libraries)
    source = pathlib.Path(os.environ["RASP_WINDOW_HOST_APK"])
    if artifact_format == "aab":
        source = pathlib.Path(__file__).parents[2] / "apps/android/InsecureBankv2.aab"
    resolved = checks.resolve_checks(platforms.Platform.ANDROID, ("overlay",))
    config = runtime_config.RuntimeConfig(
        build_id="rt10-sdk-ndk-fixture", checks=resolved.checks
    )
    output = tmp_path / ("protected." + artifact_format)
    result = packer.pack(app=source, output=output, config=config, artifacts=artifacts)
    assert result.effective_checks == ("identity", "overlay")
    assert (
        result.bindings is None
    )  # Omitted metadata must remain unknown even with valid current compiled bytes.
    prefix = "base/" if artifact_format == "aab" else ""
    with zipfile.ZipFile(output) as archive:
        for abi in _ABIS:
            actual = archive.read(prefix + "lib/" + abi + "/librasp.so")
            assert actual == runtime_library.write_config(libraries[abi], config)
            assert runtime_library.read_config(actual) == config.to_json()
        dex_prefix = prefix + ("dex/" if artifact_format == "aab" else "")
        dexes = [
            archive.read(name)
            for name in archive.namelist()
            if name.startswith(dex_prefix + "classes") and name.endswith(".dex")
        ]
        assert dexes.count(stub) == 1
        assert sum(b"Lco/ostorlab/rasp/RuntimeBridge;" in dex for dex in dexes) == 1
        assert (
            sum(
                b"Lco/ostorlab/rasp/RuntimeBridge$TouchCallback;" in dex
                for dex in dexes
            )
            == 1
        )
        assert archive.read(prefix + "assets/rasp/map.bin") != b""
