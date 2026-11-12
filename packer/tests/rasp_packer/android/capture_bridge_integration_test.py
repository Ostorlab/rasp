"""Real SDK/NDK archive integration with explicit unknown-binding compatibility.

Provide RASP_CAPTURE_STUB, RASP_CAPTURE_HOST_APK, RASP_CAPTURE_NATIVE_DIRECTORY and
RASP_CAPTURE_AAPT2 after building the actual stub, harmless host and four native ABIs.
This exercises the unknown-binding compatibility path using actual production libraries.
Installed public release/canonical bindings are checked independently after integration.
"""

import os
import pathlib
import subprocess
import zipfile

import pytest

from rasp_packer import runtime_config
from rasp_packer.android import packer
from rasp_packer.android import resources
from rasp_packer.android import runtime_library

_REQUIRED = (
    "RASP_CAPTURE_STUB",
    "RASP_CAPTURE_HOST_APK",
    "RASP_CAPTURE_NATIVE_DIRECTORY",
    "RASP_CAPTURE_AAPT2",
)
_ABIS = ("arm64-v8a", "armeabi-v7a", "x86", "x86_64")
_PERMISSIONS = (
    ("screenshot", "android.permission.DETECT_SCREEN_CAPTURE"),
    ("screen_recording", "android.permission.DETECT_SCREEN_RECORDING"),
)


@pytest.mark.skipif(
    any(os.environ.get(name) is None for name in _REQUIRED),
    reason="requires actual compiled SDK/NDK capture artifacts and aapt2",
)
@pytest.mark.parametrize("artifact_format", ["apk", "aab"])
@pytest.mark.parametrize(
    "groups",
    [(), ("screenshot",), ("screen_recording",), ("screenshot", "screen_recording")],
    ids=["disabled", "screenshot", "recording", "both"],
)
def testCaptureBridge_whenActualArtifactsPacked_preservesOwnershipAndSelectedPermissions(
    artifact_format: str, groups: tuple[str, ...], tmp_path: pathlib.Path
) -> None:
    stub = pathlib.Path(os.environ["RASP_CAPTURE_STUB"]).read_bytes()
    assert stub.startswith(b"dex\n")
    native = pathlib.Path(os.environ["RASP_CAPTURE_NATIVE_DIRECTORY"])
    libraries = {abi: (native / abi / "librasp.so").read_bytes() for abi in _ABIS}
    artifacts = resources.Artifacts(stub_dex=stub, libraries=libraries)
    source = pathlib.Path(os.environ["RASP_CAPTURE_HOST_APK"])
    if artifact_format == "aab":
        source = pathlib.Path(__file__).parents[2] / "apps/android/InsecureBankv2.aab"
    config = runtime_config.RuntimeConfig(
        build_id="capture-sdk-fixture", checks=("identity", *groups)
    )
    output = tmp_path / ("protected." + artifact_format)
    result = packer.pack(app=source, output=output, config=config, artifacts=artifacts)
    assert result.effective_checks == config.checks
    assert result.bindings is None
    prefix = "base/" if artifact_format == "aab" else ""
    inspected = output
    with zipfile.ZipFile(output) as archive:
        for abi in _ABIS:
            binary = archive.read(prefix + "lib/" + abi + "/librasp.so")
            assert binary == runtime_library.write_config(libraries[abi], config)
        dex_prefix = prefix + ("dex/" if artifact_format == "aab" else "")
        dexes = [
            archive.read(name)
            for name in archive.namelist()
            if name.startswith(dex_prefix + "classes") and name.endswith(".dex")
        ]
        assert dexes.count(stub) == 1
        for suffix in (
            "",
            "$CaptureSession",
            "$CaptureEntry",
            "$CaptureGate",
            "$CaptureExecutor",
            "$Api34",
            "$Api34$ShotCallback",
            "$Api35",
            "$RecordCallback",
        ):
            descriptor = ("Lco/ostorlab/rasp/RuntimeBridge" + suffix + ";").encode()
            assert sum(descriptor in dex for dex in dexes) == 1
        if artifact_format == "aab":
            inspected = tmp_path / "base-proto.apk"
            with zipfile.ZipFile(inspected, "w") as base:
                base.writestr(
                    "AndroidManifest.xml",
                    archive.read("base/manifest/AndroidManifest.xml"),
                )
                base.writestr("resources.pb", archive.read("base/resources.pb"))
    dumped = subprocess.run(
        [os.environ["RASP_CAPTURE_AAPT2"], "dump", "permissions", str(inspected)],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    ).stdout
    for group, permission in _PERMISSIONS:
        assert (permission in dumped) == (group in groups)
