"""Packing of an IPA: adds the runtime framework to the app.

The packer unpacks the IPA, makes the main executable load the runtime, embeds
`RaspRuntime.framework` with the build identity in its `Info.plist`, removes the app's code
signature, and repacks the IPA. The result is unsigned: the customer signs it.
"""

import pathlib
import plistlib
import shutil
import tempfile

from rasp_packer import build
from rasp_packer import errors
from rasp_packer.ios import ipa
from rasp_packer.ios import macho
from rasp_packer.ios import resources

RASP_APP_ID_KEY = "RaspAppId"
RASP_BUILD_ID_KEY = "RaspBuildId"
_CODE_SIGNATURE_DIR = "_CodeSignature"


def pack(
    *,
    app: pathlib.Path,
    output: pathlib.Path,
    build: build.Build,
    runtime: pathlib.Path | None = None,
) -> None:
    """Protects an IPA and writes the protected IPA to `output`.

    Args:
        app: Path to the IPA.
        output: Path to write the protected IPA to.
        build: The identity of the build, written into the framework's `Info.plist`.
        runtime: The `RaspRuntime.framework` to embed. Defaults to the one bundled in the packer.

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
        _write_build(embedded / "Info.plist", build)
        ipa.archive(bundle.payload_dir, output)


def _write_build(info_plist: pathlib.Path, build: build.Build) -> None:
    content = info_plist.read_bytes()
    plist_format = (
        plistlib.FMT_BINARY
        if content.startswith(b"bplist") is True
        else plistlib.FMT_XML
    )
    info = plistlib.loads(content)
    info[RASP_APP_ID_KEY] = str(build.rasp_app_id)
    info[RASP_BUILD_ID_KEY] = build.build_id
    info_plist.write_bytes(plistlib.dumps(info, fmt=plist_format))
