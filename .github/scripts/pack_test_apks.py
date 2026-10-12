"""Packs every test APK with the installed packer and checks that each protected app embeds the runtime.

The release workflow runs it with the Python of the environment where it installed the packer it is about to
release, so `python -m rasp_packer` is that packer.
"""

import argparse
import collections.abc
import pathlib
import subprocess
import sys
import tempfile
import zipfile

from rasp_packer.android import config
from rasp_packer.android import resources
from rasp_packer.android.apk import archive as apk_archive
from rasp_packer.android.apk import axml

# A fixed build id: on main the runtime does not compute it, the caller passes it (see Ostorlab/rasp#47).
_BUILD_ID = "0" * 64
_PRIMARY_DEX = "classes.dex"


def main(argv: collections.abc.Sequence[str] | None = None) -> int:
    """Packs each APK in the test apps folder and checks the protected app.

    Args:
        argv: The arguments, without the program name. None reads them from the process.

    Returns:
        0 when every app was packed and its protected app is correct, 1 otherwise.
    """
    arguments = _parser().parse_args(argv)
    artifacts = _shipped_artifacts(arguments.resources)
    apps = sorted(arguments.apps.glob("*.apk"))
    if len(apps) == 0:
        print(f"no .apk file in {arguments.apps}", file=sys.stderr)
        return 1
    failed = 0
    with tempfile.TemporaryDirectory(prefix="rasp-test-apks-") as workspace:
        for app in apps:
            problems = _pack_and_check(app, artifacts, pathlib.Path(workspace))
            if len(problems) == 0:
                print(f"ok      {app.name}")
            else:
                failed += 1
                print(f"FAILED  {app.name}: {'; '.join(problems)}")
    print(f"{len(apps) - failed} of {len(apps)} test apps packed correctly")
    return 0 if failed == 0 else 1


def _parser() -> argparse.ArgumentParser:
    """Builds the command line: the folder of test APKs and the runtime resources the protected apps must embed."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("apps", type=pathlib.Path, help="the folder of test APKs")
    parser.add_argument(
        "resources",
        type=pathlib.Path,
        help="the Android runtime resources directory the packer ships (stub.dex and lib/<abi>/librasp.so)",
    )
    return parser


def _shipped_artifacts(root: pathlib.Path) -> resources.Artifacts:
    """Reads the stub dex and the native libraries from the resources directory `root`."""
    stub = root / "stub.dex"
    if stub.is_file() is False:
        print(f"no stub.dex under {root}", file=sys.stderr)
        raise SystemExit(1)
    libraries: dict[str, bytes] = {}
    library_root = root / "lib"
    if library_root.is_dir() is True:
        for abi in sorted(library_root.iterdir()):
            library = abi / resources.RUNTIME_LIBRARY
            if library.is_file() is True:
                libraries[abi.name] = library.read_bytes()
    if len(libraries) == 0:
        print(f"no {resources.RUNTIME_LIBRARY} under {library_root}", file=sys.stderr)
        raise SystemExit(1)
    return resources.Artifacts(stub_dex=stub.read_bytes(), libraries=libraries)


def _pack_and_check(
    app: pathlib.Path, artifacts: resources.Artifacts, workspace: pathlib.Path
) -> list[str]:
    """Packs `app` with the installed packer and gives what is wrong with the protected app."""
    output = workspace / f"{app.stem}-protected.apk"
    command = [
        sys.executable,
        "-m",
        "rasp_packer",
        "pack",
        str(app),
        "--platform",
        "android",
        "--build-id",
        _BUILD_ID,
        "--output",
        str(output),
    ]
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        return [f"rasp pack failed: {result.stderr.strip()}"]
    return _protected_app_problems(output, artifacts)


def _protected_app_problems(
    protected: pathlib.Path, artifacts: resources.Artifacts
) -> list[str]:
    """Gives what is wrong with the protected APK at `protected`, which must embed the shipped `artifacts`."""
    with zipfile.ZipFile(protected) as archive:
        names = set(archive.namelist())
        problems: list[str] = []
        problems.extend(_stub_problems(archive, names, artifacts))
        problems.extend(_library_problems(archive, names, artifacts))
        problems.extend(_payload_problems(archive, names))
        problems.extend(_manifest_problems(archive, names))
        problems.extend(
            _leftover_problems(names, apk_archive.Apk.read(protected).dex_names())
        )
    return problems


def _stub_problems(
    archive: zipfile.ZipFile,
    names: collections.abc.Set[str],
    artifacts: resources.Artifacts,
) -> list[str]:
    """Checks that the primary dex is the shipped stub loader."""
    if _PRIMARY_DEX not in names:
        return [f"the protected app has no {_PRIMARY_DEX}"]
    if archive.read(_PRIMARY_DEX) != artifacts.stub_dex:
        return [f"{_PRIMARY_DEX} is not the stub the packer ships"]
    return []


def _library_problems(
    archive: zipfile.ZipFile,
    names: collections.abc.Set[str],
    artifacts: resources.Artifacts,
) -> list[str]:
    """Checks that every shipped native library is embedded unchanged, one per ABI."""
    problems: list[str] = []
    for abi, data in artifacts.libraries.items():
        entry = f"lib/{abi}/{resources.RUNTIME_LIBRARY}"
        if entry not in names:
            problems.append(f"the runtime library {entry} is not embedded")
        elif archive.read(entry) != data:
            problems.append(f"the embedded {entry} is not the one the packer ships")
    return problems


def _payload_problems(
    archive: zipfile.ZipFile, names: collections.abc.Set[str]
) -> list[str]:
    """Checks that the runtime config and the encrypted payload are present and well-formed."""
    if config.CONFIG_ENTRY not in names or config.PAYLOAD_ENTRY not in names:
        return ["the runtime config or payload is missing"]
    problems: list[str] = []
    runtime_config = config.RuntimeConfig.from_json(
        archive.read(config.CONFIG_ENTRY).decode("utf-8")
    )
    if runtime_config.build_id != _BUILD_ID:
        problems.append(
            f"the runtime config records {runtime_config.build_id!r}, not the build id passed to the packer"
        )
    if len(archive.read(config.PAYLOAD_ENTRY)) == 0:
        problems.append("the encrypted payload is empty")
    return problems


def _manifest_problems(
    archive: zipfile.ZipFile, names: collections.abc.Set[str]
) -> list[str]:
    """Checks that the manifest names the stub as its component factory."""
    manifest_entry = "AndroidManifest.xml"
    if manifest_entry not in names:
        return ["the protected app has no AndroidManifest.xml"]
    factory = axml.read_app_component_factory(archive.read(manifest_entry))
    if factory != resources.STUB_FACTORY_CLASS:
        return [f"the manifest does not name {resources.STUB_FACTORY_CLASS} as its component factory"]
    return []


def _leftover_problems(
    names: collections.abc.Set[str], dex_names: collections.abc.Sequence[str]
) -> list[str]:
    """Checks that the v1 signature files and the original secondary dexes, the entries the packer removes, are gone."""
    problems: list[str] = []
    signature = sorted(name for name in names if _is_v1_signature(name) is True)
    if len(signature) > 0:
        problems.append(f"v1 signature files are still there: {', '.join(signature)}")
    secondary = sorted(name for name in dex_names if name != _PRIMARY_DEX)
    if len(secondary) > 0:
        problems.append(f"original dexes are still present: {', '.join(secondary)}")
    return problems


def _is_v1_signature(name: str) -> bool:
    """Whether the entry `name` is a v1 signature file, by the rule the packer removes them with."""
    if name.startswith("META-INF/") is False:
        return False
    return (
        name.endswith((".SF", ".RSA", ".DSA", ".EC")) or name == "META-INF/MANIFEST.MF"
    )


if __name__ == "__main__":
    sys.exit(main())
