"""Packing of an IPA: adds the runtime framework to the app.

The packer unpacks the IPA, makes the main executable load the runtime, embeds
`RaspRuntime.framework` with the build id in its `Info.plist`, embeds the plugins' frameworks
next to it and lists them in it, removes the app's code signature, and repacks the IPA. The
result is unsigned: the customer signs it, the plugins' frameworks included.
"""

import collections.abc
import pathlib
import plistlib
import shutil
import tempfile

from rasp_packer import errors
from rasp_packer import identity
from rasp_packer import plugins as plugins_module
from rasp_packer.ios import ipa
from rasp_packer.ios import macho
from rasp_packer.ios import resources

RASP_BUILD_ID_KEY = "RaspBuildId"
PLUGIN_LIST_FILE = "plugins.list"
PLUGIN_CONFIG_DIRECTORY = "plugin-config"
_CODE_SIGNATURE_DIR = "_CodeSignature"


def pack(
    *,
    app: pathlib.Path,
    output: pathlib.Path,
    build_id: str,
    runtime: pathlib.Path | None = None,
    plugins: collections.abc.Sequence[plugins_module.Plugin] = (),
) -> identity.AppIdentity:
    """Protects an IPA and writes the protected IPA to `output`.

    Args:
        app: Path to the IPA.
        output: Path to write the protected IPA to.
        build_id: The id of the build, written into the framework's `Info.plist`.
        runtime: The `RaspRuntime.framework` to embed. Defaults to the one bundled in the packer.
        plugins: The plugins to add, in load order. Each one's framework goes into the app's
            `Frameworks/`, and the plugin list and the plugins' configs into the runtime framework.

    Returns:
        The app's bundle identifier and short version string, from its `Info.plist`.

    Raises:
        InvalidRuntimeError: The runtime framework is missing or malformed.
        InvalidAppError: The IPA is malformed.
        UnsupportedBinaryError: The main executable cannot be protected.
        HeaderPaddingError: The new load commands do not fit in the main executable.
        AlreadyProtectedError: The app already loads or embeds the runtime.
        InvalidPluginError: A plugin has no iOS build, or the app already embeds a framework
            with its name.
    """
    _check_ios_builds(plugins)
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
        _add_plugins(bundle.frameworks_dir, embedded, plugins)
        ipa.archive(bundle.payload_dir, output)
    return bundle.identity


def _check_ios_builds(plugins: collections.abc.Sequence[plugins_module.Plugin]) -> None:
    """Refuses plugins without an iOS build."""
    missing = [plugin.name for plugin in plugins if plugin.ios_framework is None]
    if len(missing) > 0:
        raise errors.InvalidPluginError(
            f"plugins without an iOS build: {', '.join(missing)}"
        )


def _add_plugins(
    frameworks_dir: pathlib.Path,
    runtime: pathlib.Path,
    plugins: collections.abc.Sequence[plugins_module.Plugin],
) -> None:
    """Copies each plugin's framework into `frameworks_dir`, and writes the plugin list and configs into `runtime`."""
    if len(plugins) == 0:
        return
    for plugin in plugins:
        assert plugin.ios_framework is not None
        destination = frameworks_dir / plugins_module.ios_framework_name(plugin.name)
        if destination.exists() is True:
            raise errors.InvalidPluginError(
                f"the app already embeds {destination.name}"
            )
        shutil.copytree(plugin.ios_framework, destination)
        if len(plugin.config) > 0:
            config = runtime / PLUGIN_CONFIG_DIRECTORY / plugin.name
            config.parent.mkdir(exist_ok=True)
            config.write_bytes(plugin.config)
    (runtime / PLUGIN_LIST_FILE).write_bytes(plugins_module.plugin_list(plugins))


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
