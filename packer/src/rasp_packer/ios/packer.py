"""Packing of an IPA: adds the runtime framework to the app.

The packer unpacks the IPA, makes the main executable load the runtime, embeds
`RaspRuntime.framework` with the runtime's config in it, removes the app's code signature, and
repacks the IPA. The result is unsigned: the customer signs it.
"""

import pathlib
import shutil
import tempfile

from rasp_packer import errors
from rasp_packer import identity
from rasp_packer import runtime_config
from rasp_packer.ios import ipa
from rasp_packer.ios import macho
from rasp_packer.ios import resources

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
        config: The runtime's config, written into the embedded framework.
        runtime: The `RaspRuntime.framework` to embed. Defaults to the one bundled in the packer.

    Returns:
        The app's bundle identifier and short version string, from its `Info.plist`.

    Raises:
        InvalidRuntimeError: The runtime framework is missing or malformed.
        InvalidAppError: The IPA is malformed.
        UnsupportedBinaryError: The main executable cannot be protected.
        HeaderPaddingError: The new load commands do not fit in the main executable.
        AlreadyProtectedError: The app already loads or embeds the runtime.
    """
    with (
        resources.framework(runtime) as framework_dir,
        tempfile.TemporaryDirectory(prefix="rasp-packer-") as workspace,
    ):
        bundle = ipa.extract(app, pathlib.Path(workspace))
        embedded = bundle.frameworks_dir / macho.RUNTIME_FRAMEWORK
        if embedded.exists() is True:
            raise errors.AlreadyProtectedError(
                f"the app already embeds {macho.RUNTIME_FRAMEWORK}"
            )
        macho.add_runtime(bundle.executable)
        shutil.rmtree(bundle.app_dir / _CODE_SIGNATURE_DIR, ignore_errors=True)
        shutil.copytree(framework_dir, embedded)
        (embedded / runtime_config.FILE_NAME).write_bytes(config.to_json())
        ipa.archive(bundle.payload_dir, output)
    return bundle.identity
