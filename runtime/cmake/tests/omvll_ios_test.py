"""Real CMake default/unsupported-host checks, without a compiler or fake SDK."""

from __future__ import annotations

import os
import pathlib
import platform
import shutil
import subprocess
import tempfile
import unittest

HELPER = pathlib.Path(__file__).resolve().parents[1] / "omvll_ios.cmake"


@unittest.skipUnless(platform.system() == "Linux", "negative Linux host gate")
class IosHelperTest(unittest.TestCase):
    def testIosHelper_whenConfiguringOnLinux_preservesDefaultsAndFailsClosed(
        self,
    ) -> None:
        cmake = shutil.which("cmake")
        assert cmake is not None, "CMake is required for configuration boundary checks"
        with tempfile.TemporaryDirectory(prefix="omvll-cmake-") as directory:
            root = pathlib.Path(directory)
            (root / "CMakeLists.txt").write_text(
                "cmake_minimum_required(VERSION 3.18)\n"
                "project(omvll_gate NONE)\n"
                f"include([[{HELPER}]])\n"
                'if(RASP_OBFUSCATE_IOS)\nmessage(FATAL_ERROR "unexpected enabled state")\nendif()\n'
            )
            for build_type, expected in (("Debug", 0), ("Release", 1)):
                with self.subTest(build_type=build_type):
                    result = subprocess.run(
                        [
                            cmake,
                            "-S",
                            str(root),
                            "-B",
                            str(root / build_type),
                            f"-DCMAKE_BUILD_TYPE={build_type}",
                        ],
                        capture_output=True,
                        text=True,
                        check=False,
                    )
                    assert result.returncode == expected, result.stdout + result.stderr
                    if build_type == "Release":
                        assert "only supported for the Apple build" in result.stderr

            environment = dict(os.environ)
            environment["RASP_OMVLL_SEED"] = "-1"
            result = subprocess.run(
                [
                    cmake,
                    "-S",
                    str(root),
                    "-B",
                    str(root / "disabled-seed"),
                    "-DCMAKE_BUILD_TYPE=Debug",
                ],
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )
            assert result.returncode == 1, (
                "explicit seed must not be silently ignored when protection is off"
            )

            environment.pop("RASP_OMVLL_SEED")
            result = subprocess.run(
                [
                    cmake,
                    "-S",
                    str(root),
                    "-B",
                    str(root / "cache-seed"),
                    "-DCMAKE_BUILD_TYPE=Debug",
                    "-DRASP_OMVLL_SEED=42",
                ],
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )
            assert result.returncode == 1, (
                "unsupported cache seed must not be silently ignored"
            )
