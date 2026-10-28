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

from rasp_packer import runtime_config
from rasp_packer.android import cipher
from rasp_packer.android import injection
from rasp_packer.android import packer
from rasp_packer.android import resources
from rasp_packer.android import split
from rasp_packer.android.apk import axml

# A fixed build id: on main the runtime does not compute it, the caller passes it (see Ostorlab/rasp#47).
_BUILD_ID = "0" * 64
_DEX_MAGIC = b"dex\n"


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
        problems.extend(_signature_problems(names))
    return problems


def _stub_problems(
    archive: zipfile.ZipFile,
    names: collections.abc.Set[str],
    artifacts: resources.Artifacts,
) -> list[str]:
    """Checks that the last base dex, the one Android loads after the app's framework dexes, is the shipped stub."""
    base = _base_dex_names(names)
    if len(base) == 0:
        return [f"the protected app has no {injection.primary_dex_name(0)}"]
    if archive.read(base[-1]) != artifacts.stub_dex:
        return [f"{base[-1]}, the last base dex, is not the stub the packer ships"]
    return []


def _base_dex_names(names: collections.abc.Set[str]) -> list[str]:
    """Gives the base dex entries in load order: classes.dex, classes2.dex and on, up to the first one missing."""
    base: list[str] = []
    while injection.primary_dex_name(len(base)) in names:
        base.append(injection.primary_dex_name(len(base)))
    return base


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
    """Checks the key, the runtime's config, the class map and the encrypted business dexes the runtime reads."""
    entries = (packer.KEY_ENTRY, packer.MAP_ENTRY, packer.CONFIG_ENTRY)
    missing = [entry for entry in entries if entry not in names]
    if len(missing) > 0:
        return [f"missing: {', '.join(missing)}"]
    key = archive.read(packer.KEY_ENTRY)
    if len(key) != cipher.KEY_SIZE:
        return [f"the key is {len(key)} bytes, not {cipher.KEY_SIZE}"]
    problems: list[str] = []
    config = archive.read(packer.CONFIG_ENTRY)
    if config != runtime_config.RuntimeConfig(build_id=_BUILD_ID).to_json():
        problems.append(
            f"the protected app's config is {config!r}, not one with the build id passed to the packer"
        )
    if _decrypted(archive, packer.MAP_ENTRY, key) is None:
        problems.append("the class map does not decrypt with the app's key")
    problems.extend(_business_problems(archive, names, key))
    return problems


def _business_problems(
    archive: zipfile.ZipFile, names: collections.abc.Set[str], key: bytes
) -> list[str]:
    """Checks that there is a business dex and that each one decrypts, with the app's key, to a dex file."""
    prefix = f"{packer.ASSET_PREFIX}{split.BUSINESS_DIRECTORY}/"
    business = sorted(name for name in names if name.startswith(prefix))
    if len(business) == 0:
        return [f"no encrypted business dex under {prefix}"]
    problems: list[str] = []
    for entry in business:
        plaintext = _decrypted(archive, entry, key)
        if plaintext is None:
            problems.append(f"{entry} does not decrypt with the app's key")
        elif plaintext.startswith(_DEX_MAGIC) is False:
            problems.append(f"{entry} is not a dex file once decrypted")
    return problems


def _decrypted(archive: zipfile.ZipFile, entry: str, key: bytes) -> bytes | None:
    """Decrypts the frame stored at `entry` with `key`, or gives None when its tag does not verify."""
    try:
        return cipher.decrypt(key, archive.read(entry))
    except cipher.CipherError:
        return None


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


def _signature_problems(names: collections.abc.Set[str]) -> list[str]:
    """Checks that the v1 signature files, which the packer removes, are gone."""
    signature = sorted(name for name in names if _is_v1_signature(name) is True)
    if len(signature) > 0:
        return [f"v1 signature files are still there: {', '.join(signature)}"]
    return []


def _is_v1_signature(name: str) -> bool:
    """Whether the entry `name` is a v1 signature file, by the rule the packer removes them with."""
    if name.startswith("META-INF/") is False:
        return False
    return (
        name.endswith((".SF", ".RSA", ".DSA", ".EC")) or name == "META-INF/MANIFEST.MF"
    )


if __name__ == "__main__":
    sys.exit(main())
