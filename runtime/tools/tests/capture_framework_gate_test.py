"""Portable first-nm boundary tests, not Apple ABI/SDK or framework acceptance.

Run the real checker and host compiler/nm. Every case stops before Apple tools:
positive adapter-selection cases intentionally fail on a missing framework
binary in the next nm call. No mock nm, SDK headers or successful Apple gate.
"""

from __future__ import annotations

import pathlib
import shutil
import subprocess

import pytest

SCRIPT = (
    pathlib.Path(__file__).resolve().parents[2] / "tests/ios/capture/check_framework.sh"
)


@pytest.fixture
def layout(tmp_path: pathlib.Path) -> dict[str, pathlib.Path]:
    build = tmp_path / "build with spaces" / "ios"
    framework = build / "RaspRuntime.framework"
    installed = (
        tmp_path
        / "stage with spaces"
        / "rasp_packer/ios/resources/RaspRuntime.framework"
    )
    adapter = build / "CMakeFiles/RaspRuntime.dir/src/capture/capture_bridge.mm.o"
    adapter.parent.mkdir(parents=True)
    framework.mkdir()
    installed.mkdir(parents=True)
    source = tmp_path / "probe.c"
    source.write_text("int capture_gate_probe(void) { return 7; }\n")
    compiler = shutil.which("clang")
    assert compiler is not None
    subprocess.run(
        [
            compiler,
            "-std=c17",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-Wpedantic",
            "-c",
            str(source),
            "-o",
            str(adapter),
        ],
        check=True,
        capture_output=True,
    )
    return {
        "build": build,
        "framework": framework,
        "installed": installed,
        "adapter": adapter,
    }


def run_gate(
    framework: pathlib.Path, work: pathlib.Path, adapter: pathlib.Path | None = None
) -> subprocess.CompletedProcess[str]:
    arguments = ["/bin/bash", str(SCRIPT), str(framework), str(work)]
    if adapter is not None:
        arguments.append(str(adapter))
    return subprocess.run(arguments, check=False, capture_output=True, text=True)


def testCaptureGate_whenInstalledFrameworkUsesExplicitBuildAdapter_reachesNextRealNmBoundary(
    layout: dict[str, pathlib.Path], tmp_path: pathlib.Path
) -> None:
    work = tmp_path / "output"
    result = run_gate(layout["installed"], work, layout["adapter"])
    assert result.returncode != 0
    assert "capture_gate_probe" in (work / "adapter-symbols.txt").read_text()
    assert (work / "exports.txt").exists() is True
    assert str(layout["installed"] / "RaspRuntime") in result.stderr


def testCaptureGate_whenBuildFrameworkUsesDefaultAdapter_keepsOriginalFirstGate(
    layout: dict[str, pathlib.Path], tmp_path: pathlib.Path
) -> None:
    work = tmp_path / "output"
    result = run_gate(layout["framework"], work)
    assert result.returncode != 0
    assert "capture_gate_probe" in (work / "adapter-symbols.txt").read_text()
    assert (work / "exports.txt").exists() is True
    assert str(layout["framework"] / "RaspRuntime") in result.stderr


def testCaptureGate_whenInstallHasNoExplicitAdapter_reproducesMissingBuildObject(
    layout: dict[str, pathlib.Path], tmp_path: pathlib.Path
) -> None:
    work = tmp_path / "output"
    result = run_gate(layout["installed"], work)
    assert result.returncode != 0
    missing = (
        layout["installed"].parent
        / "CMakeFiles/RaspRuntime.dir/src/capture/capture_bridge.mm.o"
    )
    assert str(missing) in result.stderr
    assert (work / "exports.txt").exists() is False


def testCaptureGate_whenExplicitObjectMissing_refusesWithoutDefaultFallback(
    layout: dict[str, pathlib.Path], tmp_path: pathlib.Path
) -> None:
    work = tmp_path / "output"
    missing = tmp_path / "absent object.o"
    result = run_gate(layout["framework"], work, missing)
    assert result.returncode != 0
    assert str(missing) in result.stderr
    assert (work / "exports.txt").exists() is False


@pytest.mark.parametrize("installed", [False, True])
def testCaptureGate_whenRealObjectContainsForbiddenSymbol_preservesRefusal(
    layout: dict[str, pathlib.Path], tmp_path: pathlib.Path, installed: bool
) -> None:
    source = tmp_path / "forbidden.c"
    source.write_text(
        'void forbidden(void) __asm__("___cxa_rt19_capture_probe");\nvoid forbidden(void) {}\n'
    )
    compiler = shutil.which("clang")
    assert compiler is not None
    subprocess.run(
        [
            compiler,
            "-std=c17",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-Wpedantic",
            "-c",
            str(source),
            "-o",
            str(layout["adapter"]),
        ],
        check=True,
        capture_output=True,
    )
    framework = layout["installed"] if installed is True else layout["framework"]
    work = tmp_path / "output"
    result = run_gate(framework, work, layout["adapter"] if installed is True else None)
    assert result.returncode != 0
    assert (
        "FAIL: the capture adapter references C++ exception or terminate machinery"
        in result.stdout
    )
    assert (work / "exports.txt").exists() is False
