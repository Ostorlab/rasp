"""Packing of an IPA: adds the runtime framework to the app.

The packer unpacks the IPA, makes the main executable load the runtime, embeds
`RaspRuntime.framework` with the build id in its `Info.plist` and the configs of its plugins,
removes the app's code signature, and repacks the IPA. The result is unsigned: the customer
signs it.
"""

import collections.abc
import pathlib
import plistlib
import shutil
import tempfile

from rasp_packer import errors
from rasp_packer import identity
from rasp_packer import plugin_configs as plugin_configs_module
from rasp_packer.ios import ipa
from rasp_packer.ios import macho
from rasp_packer.ios import resources

RASP_BUILD_ID_KEY = "RaspBuildId"
PLUGIN_CONFIG_DIRECTORY = "plugin-config"
_CODE_SIGNATURE_DIR = "_CodeSignature"


def pack(
    *,
    app: pathlib.Path,
    output: pathlib.Path,
    build_id: str,
    runtime: pathlib.Path | None = None,
    plugin_configs: collections.abc.Sequence[plugin_configs_module.PluginConfig] = (),
) -> identity.AppIdentity:
    """Protects an IPA and writes the protected IPA to `output`.

    Args:
        app: Path to the IPA.
        output: Path to write the protected IPA to.
        build_id: The id of the build, written into the framework's `Info.plist`.
        runtime: The `RaspRuntime.framework` to embed. Defaults to the one bundled in the packer.
        plugin_configs: The configs of the plugins of the runtime, each written into the framework
            as `plugin-config/<name>`.

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
        _write_build_id(embedded / "Info.plist", build_id)
        _write_plugin_configs(embedded, plugin_configs)
        ipa.archive(bundle.payload_dir, output)
    return bundle.identity


def _write_plugin_configs(
    framework: pathlib.Path,
    plugin_configs: collections.abc.Sequence[plugin_configs_module.PluginConfig],
) -> None:
    """Writes each plugin config into the runtime framework, as `plugin-config/<name>`."""
    if len(plugin_configs) == 0:
        return
    directory = framework / PLUGIN_CONFIG_DIRECTORY
    directory.mkdir(exist_ok=True)
    for config in plugin_configs:
        (directory / config.name).write_bytes(config.data)


def _write_build_id(info_plist: pathlib.Path, build_id: str) -> None:
    """Writes the build id into the framework's `Info.plist`, keeping the plist's format."""
    content = info_plist.read_bytes()
    plist_format = (
        plistlib.FMT_BINARY
        if content.startswith(b"bplist") is True
        else plistlib.FMT_XML
    )
    info = plistlib.loads(content)
    info[RASP_BUILD_ID_KEY] = build_id
    info_plist.write_bytes(plistlib.dumps(info, fmt=plist_format))
