"""Post-pack structural verification against the bytes prepared for injection.

This is an unsigned artifact check, not an installability or attack-resistance test.
The expected entries must come from the trusted packing step, not the archive under test.
"""

from __future__ import annotations

import collections.abc
import contextlib
import dataclasses
import io
import os
import pathlib
import re
import tempfile
import zipfile
import zlib

import lief

from rasp_packer import archive_validation
from rasp_packer import checks
from rasp_packer import errors
from rasp_packer import identity
from rasp_packer import platforms
from rasp_packer import runtime_config
from rasp_packer.android import cipher
from rasp_packer.android import resources
from rasp_packer.android import runtime_library
from rasp_packer.android.aab import archive as aab_archive
from rasp_packer.android.aab import manifest as aab_manifest
from rasp_packer.android.apk import archive as apk_archive
from rasp_packer.android.apk import manifest as apk_manifest
from rasp_packer.ios import ipa
from rasp_packer.ios import macho
from rasp_packer.ios import runtime_binary

_MAX_MAP_BYTES = 16 * 1024**2
_ABI_HEADERS = {
    "arm64-v8a": (183, 2),
    "armeabi-v7a": (40, 1),
    "x86": (3, 1),
    "x86_64": (62, 2),
}
_BUSINESS_PATH = re.compile(r"business/(0|[1-9][0-9]*)\.dex")


@dataclasses.dataclass(frozen=True, slots=True, kw_only=True)
class VerificationResult:
    """A successful structural check; all failures raise VerificationError.

    artifact_format distinguishes APK from AAB: bundle alignment and feature delivery
    are evaluated by the store, rather than applying APK requirements to an AAB.
    """

    artifact_format: str
    app_identity: identity.AppIdentity
    config: runtime_config.RuntimeConfig
    runtime_entries: tuple[str, ...]


@contextlib.contextmanager
def staged_output(output: pathlib.Path) -> collections.abc.Iterator[pathlib.Path]:
    """Publish a completed artifact locally only after the caller verifies it.

    A hard link in the same directory provides atomic create-without-overwrite.
    Temporary files are removed on both verification and packing failures.
    Unusable output parents and failed hard links raise OutputError; no copy or
    replacement fallback can weaken atomic no-overwrite publication.
    """
    if output.exists() is True:
        raise errors.OutputExistsError(f"{output} already exists")
    try:
        temporary = tempfile.TemporaryDirectory(prefix=".rasp-", dir=output.parent)
    except OSError as error:
        raise errors.OutputError(
            f"cannot create output staging directory in {output.parent}: {error}"
        ) from error
    with temporary as directory:
        staged = pathlib.Path(directory) / output.name
        yield staged
        try:
            os.link(staged, output)
        except FileExistsError as error:
            raise errors.OutputExistsError(f"{output} already exists") from error
        except OSError as error:
            raise errors.OutputError(
                f"cannot publish {output} atomically with a hard link: {error}"
            ) from error


def verify(
    *,
    app: pathlib.Path,
    platform: platforms.Platform,
    config: runtime_config.RuntimeConfig,
    expected_entries: collections.abc.Mapping[str, bytes],
) -> VerificationResult:
    """Read actual packed output and verify its injection contract and platform structure.

    expected_entries contains every prepared injected/replaced entry, including the
    manifest, loader, runtime and encrypted payload. Byte equality detects replacement
    even when a replacement is a well-formed binary. This contract trusts the runtime
    build and DEX splitter; it does not establish executable semantics or provenance.
    The API is read-only, and accepts only unsigned artifacts produced by this packer.
    """
    try:
        _check_config(config, platform)
        archive_validation.check(app)
        with zipfile.ZipFile(app) as archive:
            names = set(archive.namelist())
        missing = set(expected_entries) - names
        if len(missing) > 0:
            raise errors.VerificationError(
                f"missing required artifacts: {sorted(missing)}"
            )
        if platform == platforms.Platform.ANDROID:
            return _verify_android(app, config, expected_entries)
        return _verify_ios(app, config, expected_entries)
    except errors.VerificationError:
        raise
    except errors.Error as error:
        raise errors.VerificationError(f"post-pack verification: {error}") from error
    except (
        OSError,
        ValueError,
        RuntimeError,
        zipfile.BadZipFile,
        NotImplementedError,
        EOFError,
        zlib.error,
    ) as error:
        raise errors.VerificationError(
            f"cannot verify packed archive: {error}"
        ) from error


def _check_config(
    config: runtime_config.RuntimeConfig, platform: platforms.Platform
) -> None:
    """Require the exact canonical platform config that the runtime will consume."""
    if (
        config.build_id == ""
        or re.search(r"[\x00-\x1f\x7f]", config.build_id) is not None
    ):
        raise errors.VerificationError("runtime config has an invalid build id")
    if checks.resolve_checks(platform, config.checks).checks != config.checks:
        raise errors.VerificationError(
            "runtime config checks must be supported, unique, sorted and include required checks"
        )


def _compare_entries(
    get: collections.abc.Callable[[str], bytes | None],
    expected: collections.abc.Mapping[str, bytes],
) -> None:
    """Verify prepared bytes survived serialization at their exact paths."""
    if len(expected) == 0:
        raise errors.VerificationError("the expected injection contract is empty")
    for name, data in expected.items():
        actual = get(name)
        if actual is None:
            raise errors.VerificationError(f"missing required artifact: {name}")
        if actual != data:
            raise errors.VerificationError(f"replaced required artifact: {name}")


def _verify_android(
    app: pathlib.Path,
    config: runtime_config.RuntimeConfig,
    expected: collections.abc.Mapping[str, bytes],
) -> VerificationResult:
    """Reuse platform readers and manifests, then check runtime and payload coherence."""
    with zipfile.ZipFile(app) as archive:
        is_aab = "BundleConfig.pb" in archive.namelist()
    packed = aab_archive.Aab.read(app) if is_aab is True else apk_archive.Apk.read(app)
    manifest_module = aab_manifest if is_aab is True else apk_manifest
    prefix = "base/" if is_aab is True else ""
    manifest_name = (
        aab_archive.MANIFEST_ENTRY if is_aab is True else apk_archive.MANIFEST_ENTRY
    )
    manifest = packed.manifest()
    app_identity = manifest_module.app_identity(manifest)
    if manifest_module.app_component_factory(manifest) != resources.STUB_FACTORY_CLASS:
        raise errors.VerificationError(
            "manifest does not load the RASP component factory"
        )
    if manifest_module.raise_min_sdk_version(manifest, 31) != manifest:
        raise errors.VerificationError(
            "manifest minimum SDK is below the runtime floor (31)"
        )
    dex_names = packed.dex_names()
    primary = prefix + ("dex/" if is_aab is True else "") + "classes.dex"
    if primary not in dex_names or any(packed.get(name) == b"" for name in dex_names):
        raise errors.VerificationError("missing or empty base loader DEX")
    names = packed.names()
    libraries = tuple(
        sorted(
            name
            for name in names
            if name.startswith(prefix + "lib/") and name.endswith("/librasp.so")
        )
    )
    abis = {name.split("/")[-2] for name in libraries}
    native_abis = {
        name.split("/")[-2]
        for name in names
        if name.startswith(prefix + "lib/")
        and len(name.removeprefix(prefix).split("/")) == 3
        and name.endswith(".so")
    }
    if len(libraries) == 0 or abis != native_abis:
        raise errors.VerificationError(
            "runtime libraries do not cover the base module's native ABIs"
        )
    required = {
        manifest_name,
        *dex_names,
        *libraries,
        prefix + "assets/rasp/key.bin",
        prefix + "assets/rasp/map.bin",
    }
    payloads = {
        name
        for name in names
        if name.startswith(prefix + "assets/business/") and name.endswith(".dex")
    }
    if required.union(payloads).issubset(expected) is False:
        raise errors.VerificationError("incomplete expected Android injection contract")
    _compare_entries(packed.get, expected)
    if is_aab is False:
        with zipfile.ZipFile(app) as archive:
            for name in payloads | {
                prefix + "assets/rasp/key.bin",
                prefix + "assets/rasp/map.bin",
            }:
                if archive.getinfo(name).compress_type != zipfile.ZIP_STORED:
                    raise errors.VerificationError(
                        f"runtime payload must be stored uncompressed: {name}"
                    )
        apk_archive.check_alignment(app)
    for name in libraries:
        library = packed.get(name)
        assert library is not None
        _check_elf(library, name.split("/")[-2])
        if runtime_library.read_config(library) != config.to_json():
            raise errors.VerificationError(
                f"runtime config differs from declared config: {name}"
            )
    _check_payload(packed.get, prefix, payloads)
    return VerificationResult(
        artifact_format="aab" if is_aab is True else "apk",
        app_identity=app_identity,
        config=config,
        runtime_entries=libraries,
    )


def _check_elf(library: bytes, abi: str) -> None:
    """Validate the ELF machine, class, byte order and shared-library type against its ABI path."""
    elf = lief.ELF.parse(io.BytesIO(library))
    if elf is None or abi not in _ABI_HEADERS:
        raise errors.VerificationError(f"invalid runtime ELF or unsupported ABI: {abi}")
    if (
        (int(elf.header.machine_type), int(elf.header.identity_class))
        != _ABI_HEADERS[abi]
        or int(elf.header.identity_data) != 1
        or int(elf.header.file_type) != 3
    ):
        raise errors.VerificationError(
            f"runtime ELF metadata disagrees with ABI path: {abi}"
        )


def _check_payload(
    get: collections.abc.Callable[[str], bytes | None], prefix: str, payloads: set[str]
) -> None:
    """Authenticate map and payload frames and validate every class-to-asset reference."""
    key = get(prefix + "assets/rasp/key.bin")
    frame = get(prefix + "assets/rasp/map.bin")
    if (
        key is None
        or len(key) != cipher.KEY_SIZE
        or frame is None
        or len(frame) > _MAX_MAP_BYTES
    ):
        raise errors.VerificationError("missing or invalid payload key/map")
    text = cipher.decrypt(key, frame).decode("utf-8")
    classes: set[str] = set()
    references: set[str] = set()
    for line in text.split("\n"):
        if line == "":
            continue
        class_name, separator, path = line.partition(",")
        if (
            separator == ""
            or class_name == ""
            or class_name in classes
            or _BUSINESS_PATH.fullmatch(path) is None
        ):
            raise errors.VerificationError("invalid or duplicate class-map entry")
        classes.add(class_name)
        references.add(prefix + "assets/" + path)
    if references != payloads:
        raise errors.VerificationError("class map and encrypted payload paths disagree")
    for name in payloads:
        frame = get(name)
        assert frame is not None
        if len(cipher.decrypt(key, frame)) == 0:
            raise errors.VerificationError(f"empty encrypted business DEX: {name}")


def _verify_ios(
    app: pathlib.Path,
    config: runtime_config.RuntimeConfig,
    expected: collections.abc.Mapping[str, bytes],
) -> VerificationResult:
    """Reuse IPA extraction and verify arm64 dyld paths and all embedded configs."""
    with tempfile.TemporaryDirectory(prefix="rasp-verify-") as workspace:
        root = pathlib.Path(workspace)
        bundle = ipa.extract(app, root)
        if bundle.executable.stat().st_mode & 0o111 == 0:
            raise errors.VerificationError(
                "the main executable has lost its execute permission"
            )
        runtime = bundle.frameworks_dir / macho.RUNTIME_FRAMEWORK / macho.RUNTIME_BINARY
        runtime_name = runtime.relative_to(root).as_posix()
        required = {
            runtime_name,
            runtime.with_name("Info.plist").relative_to(root).as_posix(),
            bundle.executable.relative_to(root).as_posix(),
            (bundle.app_dir / "Info.plist").relative_to(root).as_posix(),
        }
        if required.issubset(expected) is False:
            raise errors.VerificationError("incomplete expected IPA injection contract")
        _compare_entries(
            lambda name: (
                (root / name).read_bytes() if (root / name).is_file() is True else None
            ),
            expected,
        )
        info = ipa.read_info(runtime.with_name("Info.plist"))
        if info.get("CFBundleExecutable") != macho.RUNTIME_BINARY:
            raise errors.VerificationError(
                "runtime framework Info.plist has an invalid executable"
            )
        _check_macho(bundle.executable, executable=True)
        _check_macho(runtime, executable=False)
        configs = runtime_binary.read_config(runtime.read_bytes())
        if len(configs) == 0 or any(value != config.to_json() for value in configs):
            raise errors.VerificationError(
                "runtime config differs from declared config"
            )
        return VerificationResult(
            artifact_format="ipa",
            app_identity=bundle.identity,
            config=config,
            runtime_entries=(runtime_name,),
        )


def _check_macho(path: pathlib.Path, *, executable: bool) -> None:
    """Require unencrypted arm64 binaries and the main executable's actual load paths."""
    fat = lief.MachO.parse(str(path))
    if fat is None or fat.size == 0:
        raise errors.VerificationError(f"invalid Mach-O: {path.name}")
    for binary in fat:
        expected_type = (
            lief.MachO.Header.FILE_TYPE.EXECUTE
            if executable is True
            else lief.MachO.Header.FILE_TYPE.DYLIB
        )
        if binary.header.file_type != expected_type:
            raise errors.VerificationError(f"invalid Mach-O file type: {path.name}")
        if binary.header.cpu_type != lief.MachO.Header.CPU_TYPE.ARM64:
            raise errors.VerificationError(
                f"unsupported Mach-O architecture: {path.name}"
            )
        encryption = binary.encryption_info
        if encryption is not None and encryption.crypt_id != 0:
            raise errors.VerificationError(f"encrypted Mach-O: {path.name}")
        if executable is True and (
            sum(
                library.name == macho.RUNTIME_INSTALL_NAME
                and library.command == lief.MachO.LoadCommand.TYPE.LOAD_DYLIB
                for library in binary.libraries
            )
            != 1
            or all(rpath.path != macho.FRAMEWORKS_RPATH for rpath in binary.rpaths)
        ):
            raise errors.VerificationError(
                "executable does not load the runtime through its Frameworks path"
            )
