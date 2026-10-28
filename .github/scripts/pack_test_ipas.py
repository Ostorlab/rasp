"""Packs every test IPA with the installed packer and checks that each protected app embeds the runtime.

The release workflow runs it with the Python of the environment where it installed the packer it is about to
release, so `python -m rasp_packer` is that packer.
"""

import argparse
import collections.abc
import io
import pathlib
import plistlib
import subprocess
import sys
import tempfile
import zipfile

import lief

from rasp_packer import runtime_config

_RUNTIME_DIR = "Frameworks/RaspRuntime.framework"
_RUNTIME_BINARY = "RaspRuntime"
_RUNTIME_INSTALL_NAME = "@rpath/RaspRuntime.framework/RaspRuntime"
_FRAMEWORKS_RPATH = "@executable_path/Frameworks"
_BUILD_ID = "0" * 64


def main(argv: collections.abc.Sequence[str] | None = None) -> int:
    """Packs each IPA in the test apps folder and checks the protected app.

    Args:
        argv: The arguments, without the program name. None reads them from the process.

    Returns:
        0 when every app was packed and its protected app is correct, 1 otherwise.
    """
    arguments = _parser().parse_args(argv)
    apps = sorted(arguments.apps.glob("*.ipa"))
    if len(apps) == 0:
        print(f"no .ipa file in {arguments.apps}", file=sys.stderr)
        return 1
    failed = 0
    with tempfile.TemporaryDirectory(prefix="rasp-test-ipas-") as workspace:
        for app in apps:
            problems = _pack_and_check(
                app, arguments.framework, pathlib.Path(workspace)
            )
            if len(problems) == 0:
                print(f"ok      {app.name}")
            else:
                failed += 1
                print(f"FAILED  {app.name}: {'; '.join(problems)}")
    print(f"{len(apps) - failed} of {len(apps)} test apps packed correctly")
    return 0 if failed == 0 else 1


def _parser() -> argparse.ArgumentParser:
    """Builds the command line: the folder of test IPAs and the framework the protected apps must embed."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("apps", type=pathlib.Path, help="the folder of test IPAs")
    parser.add_argument(
        "framework",
        type=pathlib.Path,
        help="the RaspRuntime.framework the packer ships",
    )
    return parser


def _pack_and_check(
    app: pathlib.Path, framework: pathlib.Path, workspace: pathlib.Path
) -> list[str]:
    """Packs `app` with the installed packer and gives what is wrong with the protected app."""
    output = workspace / f"{app.stem}-protected.ipa"
    command = [
        sys.executable,
        "-m",
        "rasp_packer",
        "pack",
        str(app),
        "--platform",
        "ios",
        "--build-id",
        _BUILD_ID,
        "--output",
        str(output),
    ]
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        return [f"rasp pack failed: {result.stderr.strip()}"]
    return _protected_app_problems(output, (framework / _RUNTIME_BINARY).read_bytes())


def _protected_app_problems(protected: pathlib.Path, runtime: bytes) -> list[str]:
    """Gives what is wrong with the protected IPA at `protected`, which must embed the runtime binary `runtime`."""
    with zipfile.ZipFile(protected) as archive:
        names = set(archive.namelist())
        apps = sorted(
            {
                name.split("/")[1]
                for name in names
                if name.startswith("Payload/") and name.count("/") >= 2
            }
        )
        if len(apps) != 1:
            return [f"expected one app under Payload/, found {len(apps)}"]
        app_dir = f"Payload/{apps[0]}/"
        if f"{app_dir}Info.plist" not in names:
            return ["the app has no Info.plist"]
        executable_name = plistlib.loads(archive.read(f"{app_dir}Info.plist")).get(
            "CFBundleExecutable"
        )
        executable_path = f"{app_dir}{executable_name}"
        if not isinstance(executable_name, str) or executable_path not in names:
            return ["the app's main executable is missing"]
        runtime_path = f"{app_dir}{_RUNTIME_DIR}/{_RUNTIME_BINARY}"
        runtime_config_path = f"{app_dir}{_RUNTIME_DIR}/{runtime_config.FILE_NAME}"
        if runtime_path not in names or runtime_config_path not in names:
            return ["the runtime framework is not embedded"]
        problems = []
        if archive.read(runtime_path) != runtime:
            problems.append("the embedded runtime is not the one the packer ships")
        config = archive.read(runtime_config_path)
        if config != runtime_config.RuntimeConfig(build_id=_BUILD_ID).to_json():
            problems.append(
                f"the runtime's config is {config!r}, not one with the build id passed to the packer"
            )
        if any(name.startswith(f"{app_dir}_CodeSignature/") for name in names):
            problems.append("the app's _CodeSignature is still there")
        if (archive.getinfo(executable_path).external_attr >> 16) & 0o111 == 0:
            problems.append("the main executable is no longer executable")
        problems.extend(_executable_problems(archive.read(executable_path)))
    return problems


def _executable_problems(executable: bytes) -> list[str]:
    """Gives what is wrong with the arm64 slices of the protected main executable `executable`."""
    fat = lief.MachO.parse(io.BytesIO(executable))
    if fat is None:
        return ["the main executable is not a Mach-O file"]
    slices = [
        binary
        for binary in fat
        if binary.header.cpu_type == lief.MachO.Header.CPU_TYPE.ARM64
    ]
    if len(slices) == 0:
        return ["the main executable has no arm64 slice"]
    problems = []
    for binary in slices:
        if _RUNTIME_INSTALL_NAME not in [library.name for library in binary.libraries]:
            problems.append(f"an arm64 slice doesn't load {_RUNTIME_INSTALL_NAME}")
        rpaths = [
            command.path
            for command in binary.commands
            if isinstance(command, lief.MachO.RPathCommand)
        ]
        if _FRAMEWORKS_RPATH not in rpaths:
            problems.append(f"an arm64 slice has no {_FRAMEWORKS_RPATH} search path")
        if binary.has_code_signature is True:
            problems.append("an arm64 slice still has its code signature")
    return problems


if __name__ == "__main__":
    sys.exit(main())
