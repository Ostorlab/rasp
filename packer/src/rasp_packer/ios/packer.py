"""Packing of an IPA: adds the runtime framework to the app.

The packer unpacks the IPA, makes the main executable load the runtime, embeds
`RaspRuntime.framework` with the runtime's config written into its binary, removes the app's code
signature, and repacks the IPA. The result is unsigned: the customer signs it.
"""

import dataclasses
import pathlib
import shutil
import tempfile

from rasp_packer import capabilities
from rasp_packer import errors
from rasp_packer import identity
from rasp_packer import local_policy
from rasp_packer import platforms
from rasp_packer import runtime_config
from rasp_packer import verification
from rasp_packer.ios import ipa
from rasp_packer.ios import macho
from rasp_packer.ios import resources
from rasp_packer.ios import runtime_binary

_CODE_SIGNATURE_DIR = "_CodeSignature"


def pack(
    *,
    app: pathlib.Path,
    output: pathlib.Path,
    config: runtime_config.RuntimeConfig,
    runtime: pathlib.Path | None = None,
) -> identity.AppIdentity:
    """Protects an IPA and writes the protected IPA to `output`.

    Args:
        app: Path to the IPA.
        output: Path to write the protected IPA to.
        config: The runtime's config, written into the embedded framework's binary.
        runtime: The `RaspRuntime.framework` to embed. Defaults to the one bundled in the packer.

    Returns:
        The app's identity with additive effective_checks/bindings metadata; identity equality is preserved.

    Raises:
        InvalidRuntimeError: The runtime framework is missing or malformed, or its binary has no
            `__DATA,__rasp_config` section.
        ConfigTooLargeError: The runtime's config does not fit in the framework's binary.
        InvalidAppError: The IPA is malformed.
        UnsupportedBinaryError: The main executable cannot be protected.
        HeaderPaddingError: The new load commands do not fit in the main executable.
        AlreadyProtectedError: The app already loads or embeds the runtime.
    """
    with (
        resources.framework(runtime) as framework_dir,
        tempfile.TemporaryDirectory(prefix="rasp-packer-") as workspace,
    ):
        pristine = (framework_dir / macho.RUNTIME_BINARY).read_bytes()
        binding = capabilities.bind(
            pristine,
            capabilities.read_sidecar(framework_dir / macho.RUNTIME_BINARY),
            "ios",
            macho.RUNTIME_ABI,
        )
        policy_binding = local_policy.bind(
            pristine,
            local_policy.read_support(framework_dir / macho.RUNTIME_BINARY),
            "ios",
            macho.RUNTIME_ABI,
            required=config.local_policy is not None,
        )
        if policy_binding is not None:
            runtime_binary.verify_policy_exports(pristine)
        if config.local_policy is not None and binding is None:
            raise errors.InvalidRuntimeError(
                "local policy requires matching native capability binding"
            )
        bundle = ipa.extract(app, pathlib.Path(workspace))
        embedded = bundle.frameworks_dir / macho.RUNTIME_FRAMEWORK
        if embedded.exists() is True:
            raise errors.AlreadyProtectedError(
                f"the app already embeds {macho.RUNTIME_FRAMEWORK}"
            )
        macho.add_runtime(bundle.executable)
        shutil.rmtree(bundle.app_dir / _CODE_SIGNATURE_DIR, ignore_errors=True)
        shutil.copytree(framework_dir, embedded)
        runtime_file = embedded / macho.RUNTIME_BINARY
        runtime_file.with_name(runtime_file.name + capabilities.SIDECAR_SUFFIX).unlink(
            missing_ok=True
        )
        runtime_file.with_name(runtime_file.name + local_policy.SUPPORT_SUFFIX).unlink(
            missing_ok=True
        )
        runtime_file.write_bytes(runtime_binary.write_config(pristine, config))
        expected = {
            path.relative_to(pathlib.Path(workspace)).as_posix(): path.read_bytes()
            for path in (
                bundle.executable,
                bundle.app_dir / "Info.plist",
                runtime_file,
                embedded / "Info.plist",
            )
        }
        with verification.staged_output(output) as staged:
            ipa.archive(bundle.payload_dir, staged)
            verification.verify(
                app=staged,
                platform=platforms.Platform.IOS,
                config=config,
                expected_entries=expected,
            )
    return dataclasses.replace(
        bundle.identity,
        effective_checks=config.checks,
        bindings=(binding,) if binding is not None else None,
        local_policy_bindings=(policy_binding,) if policy_binding is not None else None,
    )
