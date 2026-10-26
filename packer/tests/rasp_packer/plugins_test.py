"""Tests of reading and checking plugin bundles."""

import collections.abc
import json
import pathlib
import re

import pytest

from rasp_packer import errors
from rasp_packer import plugins

_PLUGIN_HEADER = (
    pathlib.Path(__file__).resolve().parents[3]
    / "runtime"
    / "core"
    / "include"
    / "rasp"
    / "plugin.h"
)

type MakePlugin = collections.abc.Callable[..., pathlib.Path]


def testPluginApiVersion_whenComparedWithTheRuntimeHeader_isTheSame() -> None:
    match = re.search(
        r"^#define RASP_PLUGIN_API_VERSION (\d+)$",
        _PLUGIN_HEADER.read_text(),
        re.MULTILINE,
    )

    assert match is not None
    assert int(match.group(1)) == plugins.PLUGIN_API_VERSION


def testLoad_whenTheBundleIsComplete_readsEveryPart(make_plugin: MakePlugin) -> None:
    directory = make_plugin(abis=("arm64-v8a", "x86_64"), config=b"\x00key=value")

    plugin = plugins.load(directory)

    assert plugin == plugins.Plugin(
        name="example",
        version="1.0.0",
        api_version=1,
        android_libraries={
            "arm64-v8a": b"example arm64-v8a",
            "x86_64": b"example x86_64",
        },
        ios_framework=directory / "ios" / "rasp_plugin_example.framework",
        config=b"\x00key=value",
    )


def testLoad_whenTheBundleHasOnlyAnAndroidBuild_hasNoIosFramework(
    make_plugin: MakePlugin,
) -> None:
    plugin = plugins.load(make_plugin(ios=False))

    assert plugin.ios_framework is None
    assert plugin.config == b""


def testLoad_whenTheBundleHasOnlyAnIosBuild_hasNoAndroidLibrary(
    make_plugin: MakePlugin,
) -> None:
    plugin = plugins.load(make_plugin(abis=()))

    assert plugin.android_libraries == {}


def testLoad_whenTheBundleHasNoBuild_raisesInvalidPluginError(
    make_plugin: MakePlugin,
) -> None:
    with pytest.raises(errors.InvalidPluginError, match="no Android or iOS build"):
        plugins.load(make_plugin(abis=(), ios=False))


def testLoad_whenTheDirectoryDoesNotExist_raisesInvalidPluginError(
    tmp_path: pathlib.Path,
) -> None:
    with pytest.raises(errors.InvalidPluginError, match="not a directory"):
        plugins.load(tmp_path / "missing")


def testLoad_whenPluginJsonIsMissing_raisesInvalidPluginError(
    make_plugin: MakePlugin,
) -> None:
    directory = make_plugin()
    (directory / "plugin.json").unlink()

    with pytest.raises(
        errors.InvalidPluginError, match=re.escape("plugin.json not found")
    ):
        plugins.load(directory)


def testLoad_whenPluginJsonIsNotJson_raisesInvalidPluginError(
    make_plugin: MakePlugin,
) -> None:
    directory = make_plugin()
    (directory / "plugin.json").write_text("{name")

    with pytest.raises(errors.InvalidPluginError, match="cannot read"):
        plugins.load(directory)


@pytest.mark.parametrize(
    "manifest",
    [
        ["example", "1.0.0", 1],
        {"name": "example", "version": "1.0.0"},
        {"name": "example", "version": "1.0.0", "api_version": 1, "extra": True},
    ],
)
def testLoad_whenPluginJsonHasOtherKeys_raisesInvalidPluginError(
    make_plugin: MakePlugin, manifest: object
) -> None:
    directory = make_plugin()
    (directory / "plugin.json").write_text(json.dumps(manifest))

    with pytest.raises(errors.InvalidPluginError):
        plugins.load(directory)


@pytest.mark.parametrize(
    "name",
    ["", "Example", "2fa", "_example", "my-plugin", "a" * 33, "../x", 7, None],
)
def testLoad_whenTheNameIsInvalid_raisesInvalidPluginError(
    make_plugin: MakePlugin, name: object
) -> None:
    directory = make_plugin(
        manifest={"name": name, "version": "1.0.0", "api_version": 1}
    )

    with pytest.raises(errors.InvalidPluginError, match="doesn't match"):
        plugins.load(directory)


@pytest.mark.parametrize("version", ["", "1\n0", "v" * 129, 1, None])
def testLoad_whenTheVersionIsInvalid_raisesInvalidPluginError(
    make_plugin: MakePlugin, version: object
) -> None:
    directory = make_plugin(
        manifest={"name": "example", "version": version, "api_version": 1}
    )

    with pytest.raises(errors.InvalidPluginError, match="version"):
        plugins.load(directory)


@pytest.mark.parametrize(
    "api_version", [0, plugins.PLUGIN_API_VERSION + 1, True, "1", 1.0]
)
def testLoad_whenTheApiVersionIsNotSupported_raisesInvalidPluginError(
    make_plugin: MakePlugin, api_version: object
) -> None:
    directory = make_plugin(
        manifest={"name": "example", "version": "1.0.0", "api_version": api_version}
    )

    with pytest.raises(errors.InvalidPluginError, match="API version"):
        plugins.load(directory)


def testLoad_whenAnAndroidLibraryIsMisnamed_raisesInvalidPluginError(
    make_plugin: MakePlugin,
) -> None:
    directory = make_plugin()
    abi = directory / "android" / "arm64-v8a"
    (abi / "librasp_plugin_example.so").rename(abi / "libexample.so")

    with pytest.raises(
        errors.InvalidPluginError,
        match=re.escape("must hold only the file librasp_plugin_example.so"),
    ):
        plugins.load(directory)


def testLoad_whenAnAbiFolderHoldsAnotherFile_raisesInvalidPluginError(
    make_plugin: MakePlugin,
) -> None:
    directory = make_plugin()
    (directory / "android" / "arm64-v8a" / "libother.so").write_bytes(b"other")

    with pytest.raises(errors.InvalidPluginError, match="must hold only"):
        plugins.load(directory)


def testLoad_whenTheAndroidFolderHoldsNoAbi_raisesInvalidPluginError(
    make_plugin: MakePlugin,
) -> None:
    directory = make_plugin(abis=())
    (directory / "android").mkdir()

    with pytest.raises(errors.InvalidPluginError, match="holds no ABI"):
        plugins.load(directory)


def testLoad_whenTheIosFrameworkIsMisnamed_raisesInvalidPluginError(
    make_plugin: MakePlugin,
) -> None:
    directory = make_plugin()
    ios = directory / "ios"
    (ios / "rasp_plugin_example.framework").rename(ios / "Example.framework")

    with pytest.raises(
        errors.InvalidPluginError,
        match=re.escape("must hold only the framework rasp_plugin_example.framework"),
    ):
        plugins.load(directory)


@pytest.mark.parametrize("missing", ["rasp_plugin_example", "Info.plist"])
def testLoad_whenTheIosFrameworkIsIncomplete_raisesInvalidPluginError(
    make_plugin: MakePlugin, missing: str
) -> None:
    directory = make_plugin()
    (directory / "ios" / "rasp_plugin_example.framework" / missing).unlink()

    with pytest.raises(errors.InvalidPluginError, match=f"has no {missing}"):
        plugins.load(directory)


def testLoad_whenTheIosFrameworkHoldsASymbolicLink_raisesInvalidPluginError(
    make_plugin: MakePlugin,
) -> None:
    directory = make_plugin()
    framework = directory / "ios" / "rasp_plugin_example.framework"
    (framework / "Current").symlink_to(framework / "Info.plist")

    with pytest.raises(errors.InvalidPluginError, match="symbolic links"):
        plugins.load(directory)


def testLoad_whenTheConfigIsTheLargestAllowed_readsIt(make_plugin: MakePlugin) -> None:
    config = b"c" * plugins.MAX_CONFIG_SIZE

    assert plugins.load(make_plugin(config=config)).config == config


def testLoad_whenTheConfigIsTooLarge_raisesInvalidPluginError(
    make_plugin: MakePlugin,
) -> None:
    directory = make_plugin(config=b"c" * (plugins.MAX_CONFIG_SIZE + 1))

    with pytest.raises(errors.InvalidPluginError, match="larger than"):
        plugins.load(directory)


def testLoadAll_whenBundlesAreGiven_keepsTheirOrder(make_plugin: MakePlugin) -> None:
    loaded = plugins.load_all(
        [make_plugin(name="zeta"), make_plugin(name="alpha"), make_plugin(name="mid")]
    )

    assert [plugin.name for plugin in loaded] == ["zeta", "alpha", "mid"]


def testLoadAll_whenTwoBundlesShareAName_raisesInvalidPluginError(
    make_plugin: MakePlugin,
) -> None:
    with pytest.raises(errors.InvalidPluginError, match="more than once: example"):
        plugins.load_all([make_plugin(), make_plugin()])


def testLoadAll_whenThereAreTooManyBundles_raisesInvalidPluginError(
    tmp_path: pathlib.Path,
) -> None:
    directories = [tmp_path / str(index) for index in range(plugins.MAX_PLUGINS + 1)]

    with pytest.raises(errors.InvalidPluginError, match="at most 16"):
        plugins.load_all(directories)


def testPluginList_whenGivenPlugins_namesThemOnePerLineInOrder(
    make_plugin: MakePlugin,
) -> None:
    loaded = plugins.load_all([make_plugin(name="zeta"), make_plugin(name="alpha")])

    assert plugins.plugin_list(loaded) == b"zeta\nalpha\n"


def testNames_whenGivenAPluginName_followTheConvention() -> None:
    assert plugins.android_library_name("example") == "librasp_plugin_example.so"
    assert plugins.ios_framework_name("example") == "rasp_plugin_example.framework"
    assert plugins.ios_binary_name("example") == "rasp_plugin_example"
