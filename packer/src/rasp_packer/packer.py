"""The packer's entry point: protects a built app (APK, AAB, or IPA)."""

import collections.abc
import dataclasses
import hashlib
import pathlib
import re

from rasp_packer import capabilities
from rasp_packer import checks as check_groups
from rasp_packer import errors
from rasp_packer import identity
from rasp_packer import local_policy as policy_module
from rasp_packer import platforms
from rasp_packer import runtime_config
from rasp_packer.android import packer as android_packer
from rasp_packer.ios import packer as ios_packer

_CONTROL_CHARACTERS = re.compile(r"[\x00-\x1f\x7f]")


@dataclasses.dataclass(frozen=True, slots=True, kw_only=True)
class PackResult:
    """What a pack produced.

    Attributes:
        output: Path to the protected app. It is unsigned: the customer signs it.
        package_name: The app's package name, read from the app: the manifest's package on Android,
            the bundle identifier on iOS.
        version: The app's version, read from the app: the manifest's `android:versionName` on
            Android, the short version string on iOS.
        build_id: The id of the protected build, as written into the app.
        effective_checks: The actual groups written into the runtime config, not execution evidence.
        capability_bindings: Catalogue identities and pristine byte digests of exactly the injected
            native artifacts. None means unknown legacy or mixed capabilities; no current output
            expectations may be inferred. Invalid manifests raise InvalidRuntimeError.
        skipped_checks: The ids of the chosen check groups that are not groups of the platform,
            each once, in the order the caller gave them. The packer skipped them: the protected
            app does not run them.
    """

    output: pathlib.Path
    package_name: str
    version: str
    build_id: str
    skipped_checks: tuple[str, ...]
    effective_checks: tuple[str, ...] = ()
    capability_bindings: tuple[capabilities.Binding, ...] | None = None
    local_policy_bindings: tuple[policy_module.Binding, ...] | None = dataclasses.field(
        default=None, compare=False
    )
    policy_mode: str = dataclasses.field(default="report_only", compare=False)
    policy_sha256: str = dataclasses.field(default="", compare=False)
    effective_config_sha256: str = dataclasses.field(default="", compare=False)


def pack(
    *,
    app: pathlib.Path,
    platform: platforms.Platform,
    output: pathlib.Path,
    build_id: str,
    checks: collections.abc.Sequence[str],
    local_policy: policy_module.Policy | None = None,
) -> PackResult:
    """Protects a built app: adds the runtime and writes the protected app to `output`.

    The protected app is returned unsigned: the customer signs it before shipping it.
    Platform packers verify the serialized protection artifacts before creating the
    output path. Verification is structural; it does not prove installability or
    attack resistance. A failed verification raises VerificationError without output.

    The caller computes the build id. The packer writes it into the app as it is, in the
    runtime's config. The packer does not check the id's format: it only refuses an empty id or
    one with control characters.

    The caller chooses the check groups the protected app runs, from those of the platform in
    `checks.CHECKS`. The packer adds the required ones, `checks.REQUIRED_CHECKS_BY_PLATFORM`, and writes them
    sorted into the runtime's config. An empty choice runs only the required groups. The packer
    skips an id that is not one of the platform's groups and reports it in the result's
    `skipped_checks`, so that a caller still packs when it passes a group that was renamed or
    removed.

    Args:
        app: Path to the built app: an APK or AAB for Android, an IPA for iOS.
        platform: The platform of the app.
        output: Path to write the protected app to. It must not exist.
        build_id: The id of the protected build, written into the runtime's config.
        checks: The ids of the check groups the protected app runs. An empty sequence runs only
            the required groups. An id that is not one of the platform's groups is skipped.

    Returns:
        The protected app, the app's package name and version, the build id, and the skipped
        check ids.

    Raises:
        InvalidBuildIdError: The build id is empty or has control characters.
        OutputExistsError: `output` already exists.
        InvalidAppError: The app file cannot be read.
        Error: The app cannot be packed; see the platform's packer.
    """
    _check_build_id(build_id)
    resolved_checks = check_groups.resolve_checks(platform, checks)
    if local_policy is not None:
        local_policy = policy_module.validate_for(
            local_policy, platform.value, resolved_checks.checks, build_id
        )
    if output.exists() is True:
        raise errors.OutputExistsError(f"{output} already exists")
    config = runtime_config.RuntimeConfig(
        build_id=build_id, checks=resolved_checks.checks, local_policy=local_policy
    )
    packed: identity.AppIdentity
    match platform:
        case platforms.Platform.ANDROID:
            packed = android_packer.pack(app=app, output=output, config=config)
        case platforms.Platform.IOS:
            packed = ios_packer.pack(app=app, output=output, config=config)
    return PackResult(
        output=output,
        package_name=packed.package_name,
        version=packed.version,
        build_id=build_id,
        skipped_checks=resolved_checks.skipped,
        effective_checks=packed.effective_checks,
        capability_bindings=packed.bindings,
        local_policy_bindings=packed.local_policy_bindings,
        policy_mode="report_only" if local_policy is None else local_policy.mode,
        policy_sha256=hashlib.sha256(policy_module.DEFAULT_POLICY).hexdigest()
        if local_policy is None
        else local_policy.sha256,
        effective_config_sha256=policy_module.effective_hash(
            build_id, config.checks, local_policy
        ),
    )


def _check_build_id(build_id: str) -> None:
    """Refuses an empty build id, or one with control characters."""
    if len(build_id) == 0:
        raise errors.InvalidBuildIdError("the build id is empty")
    if _CONTROL_CHARACTERS.search(build_id) is not None:
        raise errors.InvalidBuildIdError(
            f"the build id {build_id!r} has control characters"
        )
