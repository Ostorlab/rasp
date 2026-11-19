"""Inspection of a built app: whether it is protected, and the runtime config the packer wrote into it.

The app is only read, never modified. The runtime's config ships in the clear in the runtime's binary
(see runtime_config), so its build id and check groups read back as the packer wrote them. A library or
framework counts as the runtime only when its config space holds a config the packer writes: a JSON
object with a string build id and an integer check mask.
"""

import dataclasses
import json
import pathlib
import tempfile

from rasp_packer import archive_safety
from rasp_packer import checks as check_groups
from rasp_packer import errors
from rasp_packer import identity
from rasp_packer import platforms
from rasp_packer.android import packer as android_packer
from rasp_packer.android import runtime_library
from rasp_packer.android.aab import archive as aab_archive
from rasp_packer.android.aab import manifest as aab_manifest
from rasp_packer.android.apk import archive as apk_archive
from rasp_packer.android.apk import manifest as apk_manifest
from rasp_packer.ios import ipa
from rasp_packer.ios import macho
from rasp_packer.ios import runtime_binary

_ELF_MAGIC = b"\x7fELF"
_APK_LIBRARY_PREFIX = ("lib",)
_AAB_LIBRARY_PREFIX = ("base", "lib")


@dataclasses.dataclass(frozen=True, slots=True, kw_only=True)
class InspectResult:
    """What an inspection read from a built app.

    Attributes:
        protected: Whether the app carries the runtime with a config the packer wrote.
        package_name: The app's package name: the bundle identifier on iOS.
        version: The app's version: the manifest's `android:versionName` on Android, the short
            version string on iOS.
        build_id: The build id written into the runtime's config, or None when the app is not
            protected.
        checks: The ids of the check groups the runtime's config turns on, sorted. Empty when the
            app is not protected.
        abis: The ABIs whose native library directory carries the runtime, sorted. Empty on iOS
            and when the app is not protected.
    """

    protected: bool
    package_name: str
    version: str
    build_id: str | None
    checks: tuple[str, ...]
    abis: tuple[str, ...]


@dataclasses.dataclass(frozen=True, slots=True, kw_only=True)
class _Config:
    """The fields of a runtime config the inspection reports."""

    build_id: str
    checks: tuple[str, ...]


def inspect(*, app: pathlib.Path, platform: platforms.Platform) -> InspectResult:
    """Reads a built app and reports whether it is protected, and the config the packer wrote.

    An app without the runtime is reported as not protected, with its identity.

    Args:
        app: Path to the built app: an APK or AAB for Android, an IPA for iOS.
        platform: The platform of the app.

    Returns:
        The app's identity, whether it is protected and, when it is, the build id, the check groups
        and, on Android, the ABIs that carry the runtime.

    Raises:
        DangerousAppError: The app archive holds an unsafe entry (encrypted, a symlink, or escaping
            its root), or cannot be read.
        InvalidApkError: The APK cannot be read, or its manifest has no package or version.
        InvalidAabError: The AAB cannot be read, or its manifest has no package or version.
        ManifestError: The Android manifest cannot be read.
        InvalidAppError: The IPA cannot be read, the copies of the runtime's config disagree, or the
            embedded iOS runtime holds no config the packer writes.
    """
    if archive_safety.is_dangerous(app) is True:
        raise errors.DangerousAppError(
            f"{app} holds an unsafe entry (encrypted, a symlink, or escaping the archive root), "
            "or cannot be read"
        )
    match platform:
        case platforms.Platform.ANDROID:
            return _inspect_android(app)
        case platforms.Platform.IOS:
            return _inspect_ios(app)


def _inspect_android(app: pathlib.Path) -> InspectResult:
    """Inspects an APK or AAB: its manifest's identity and the runtime library under each ABI."""
    archive: apk_archive.Apk | aab_archive.Aab
    app_identity: identity.AppIdentity
    prefix: tuple[str, ...]
    if android_packer.is_aab(app) is True:
        archive = aab_archive.Aab.read(app)
        app_identity = aab_manifest.app_identity(archive.manifest())
        prefix = _AAB_LIBRARY_PREFIX
    else:
        archive = apk_archive.Apk.read(app)
        app_identity = apk_manifest.app_identity(archive.manifest())
        prefix = _APK_LIBRARY_PREFIX
    configs: dict[str, _Config] = {}
    for name in sorted(archive.names()):
        abi = _library_abi(name, prefix)
        data = archive.get(name)
        if abi is None or data is None:
            continue
        config = _android_config(data)
        if config is not None:
            configs[abi] = config
    return _result(
        app_identity,
        list(configs.values()),
        tuple(sorted(configs)),
        platforms.Platform.ANDROID,
    )


def _library_abi(name: str, prefix: tuple[str, ...]) -> str | None:
    """Returns the ABI of a native library entry, `<prefix>/<abi>/<file>.so`, or None for any other entry."""
    parts = name.split("/")
    if len(parts) != len(prefix) + 2:
        return None
    if tuple(parts[: len(prefix)]) != prefix or parts[-1].endswith(".so") is False:
        return None
    return parts[len(prefix)]


def _android_config(library: bytes) -> _Config | None:
    """Reads the runtime config of a native library, or None when the library is not the runtime."""
    if library.startswith(_ELF_MAGIC) is False:
        return None
    try:
        json_config = runtime_library.read_config(library)
    except errors.InvalidRuntimeError:
        return None
    return _parse_config(json_config, platforms.Platform.ANDROID)


def _inspect_ios(app: pathlib.Path) -> InspectResult:
    """Inspects an IPA: its `Info.plist` identity and the config of its embedded runtime framework."""
    with tempfile.TemporaryDirectory(prefix="rasp-inspect-") as workspace:
        bundle = ipa.extract(app, pathlib.Path(workspace))
        runtime_file = (
            bundle.frameworks_dir / macho.RUNTIME_FRAMEWORK / macho.RUNTIME_BINARY
        )
        if runtime_file.is_file() is False:
            return _result(bundle.identity, [], (), platforms.Platform.IOS)
        try:
            slices = runtime_binary.read_config(runtime_file.read_bytes())
        except errors.InvalidRuntimeError as error:
            raise errors.InvalidAppError(
                f"the embedded {macho.RUNTIME_FRAMEWORK} cannot be read: {error}"
            ) from error
    configs: list[_Config] = []
    for json_config in slices:
        config = _parse_config(json_config, platforms.Platform.IOS)
        if config is None:
            raise errors.InvalidAppError(
                f"the embedded {macho.RUNTIME_FRAMEWORK} holds no runtime config"
            )
        configs.append(config)
    return _result(bundle.identity, configs, (), platforms.Platform.IOS)


def _parse_config(json_config: bytes, platform: platforms.Platform) -> _Config | None:
    """Parses a config the packer wrote, or returns None when the bytes are not one.

    The check groups come back from the config's mask, one bit per group in the platform's run order;
    bits past the platform's groups name no group and are left out.
    """
    try:
        fields = json.loads(json_config.decode("utf-8"))
    except ValueError:
        return None
    if isinstance(fields, dict) is False:
        return None
    build_id = fields.get("build_id")
    mask = fields.get("m")
    if isinstance(build_id, str) is False or isinstance(mask, int) is False:
        return None
    if isinstance(mask, bool) is True:
        return None
    order = check_groups.CHECKS[platform]
    enabled = sorted(
        check for index, check in enumerate(order) if mask & (1 << index) != 0
    )
    return _Config(build_id=build_id, checks=tuple(enabled))


def _result(
    app_identity: identity.AppIdentity,
    configs: list[_Config],
    abis: tuple[str, ...],
    platform: platforms.Platform,
) -> InspectResult:
    """Builds the result from the app's identity and every copy of the runtime config it carries.

    Raises:
        InvalidAppError: The copies of the config disagree.
    """
    if len(configs) == 0:
        return InspectResult(
            protected=False,
            package_name=app_identity.package_name,
            version=app_identity.version,
            build_id=None,
            checks=(),
            abis=(),
        )
    if any(config != configs[0] for config in configs) is True:
        raise errors.InvalidAppError(
            f"the {platform} app's runtime copies carry different configs"
        )
    return InspectResult(
        protected=True,
        package_name=app_identity.package_name,
        version=app_identity.version,
        build_id=configs[0].build_id,
        checks=configs[0].checks,
        abis=abis,
    )
