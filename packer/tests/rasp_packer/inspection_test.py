"""Tests of inspecting a built app."""

import collections.abc
import hashlib
import pathlib
import random
import zipfile

import pytest

from rasp_packer import checks as check_groups
from rasp_packer import errors
from rasp_packer import inspection
from rasp_packer import platforms
from rasp_packer import runtime_config
from rasp_packer.android import packer as android_packer
from rasp_packer.android import resources
from rasp_packer.android import runtime_library
from rasp_packer.android import self_encrypt
from rasp_packer.android import slots
from rasp_packer.android import split
from rasp_packer.ios import packer as ios_packer
from tests.rasp_packer import conftest

_BUILD_ID = "rasp-build/v1:" + "ab" * 32
_TESTS = pathlib.Path(__file__).parent
_APK_MANIFEST = (
    _TESTS
    / "android"
    / "apk"
    / "fixtures"
    / "manifest_with_application_and_version.bin"
)
_AAB_FIXTURE = _TESTS.parent / "apps" / "android" / "InsecureBankv2.aab"
_ARM64_SO = (conftest.RUNTIME_CONFIG_DATA / "librasp.so").read_bytes()
_ANDROID_CHECKS = ("debugger", "identity")
_IOS_CHECKS = ("hooks", "identity", "jailbreak")


def _config(
    platform: platforms.Platform, checks: tuple[str, ...]
) -> runtime_config.RuntimeConfig:
    """Returns the config the packer writes for the build id and the check groups."""
    return runtime_config.RuntimeConfig(
        build_id=_BUILD_ID,
        checks=checks,
        checks_mask=check_groups.checks_mask(platform, checks),
    )


def _artifacts() -> resources.Artifacts:
    """Returns the stub and a runtime library for two ABIs."""
    return resources.Artifacts(
        stub_dex=conftest.STUB_DEX.read_bytes(),
        libraries={"arm64-v8a": _ARM64_SO, "x86_64": _ARM64_SO},
    )


def _split(*_: object) -> split.Split:
    """Splits any app into one framework dex and one business dex."""
    return split.Split(
        framework=(b"framework dex",),
        business=(
            split.BusinessDex(
                path="business/0.dex", data=b"business dex", classes=("a.B",)
            ),
        ),
    )


def _make_apk(
    path: pathlib.Path, libraries: collections.abc.Mapping[str, bytes]
) -> pathlib.Path:
    """Writes an APK with the fixture manifest, a dex and the given native libraries."""
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("AndroidManifest.xml", _APK_MANIFEST.read_bytes())
        archive.writestr("classes.dex", b"app dex")
        for name, data in libraries.items():
            archive.writestr(name, data)
    return path


def _make_aab(path: pathlib.Path) -> pathlib.Path:
    """Writes an AAB with the fixture's proto manifest, a dex and an arm64 native library."""
    with zipfile.ZipFile(_AAB_FIXTURE) as fixture:
        manifest = fixture.read("base/manifest/AndroidManifest.xml")
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("BundleConfig.pb", b"\x0a\x08\x22\x06" + b"1.15.0")
        archive.writestr("base/manifest/AndroidManifest.xml", manifest)
        archive.writestr("base/dex/classes.dex", b"app dex")
        archive.writestr("base/lib/arm64-v8a/libapp.so", b"app native code")
    return path


def _pack_android(app: pathlib.Path, output: pathlib.Path) -> pathlib.Path:
    """Packs an Android app with the test runtime and returns the protected app."""
    splitter: collections.abc.Callable[..., split.Split] = _split
    android_packer.pack(
        app=app,
        output=output,
        config=_config(platforms.Platform.ANDROID, _ANDROID_CHECKS),
        artifacts=_artifacts(),
        splitter=splitter,
        aab_splitter=splitter,
    )
    return output


def testInspect_whenApkIsProtected_reportsTheConfigTheIdentityAndTheAbis(
    tmp_path: pathlib.Path,
) -> None:
    """A packed APK reports the packer's build id and checks, its identity and both runtime ABIs."""
    app = _make_apk(
        tmp_path / "app.apk",
        {
            "lib/arm64-v8a/libapp.so": b"app native code",
            "lib/x86_64/libapp.so": b"app native code",
        },
    )
    protected = _pack_android(app, tmp_path / "protected.apk")

    result = inspection.inspect(
        app=protected, platform=platforms.Platform.ANDROID, artifacts=_artifacts()
    )

    assert result == inspection.InspectResult(
        protected=True,
        package_name="com.example.withapp",
        version="2.4.1",
        build_id=_BUILD_ID,
        checks=_ANDROID_CHECKS,
        abis=("arm64-v8a", "x86_64"),
    )


def testInspect_whenAabIsProtected_reportsTheConfigTheIdentityAndTheAbis(
    tmp_path: pathlib.Path,
) -> None:
    """A packed AAB reports the packer's build id and checks, its identity and the runtime's ABI."""
    protected = _pack_android(
        _make_aab(tmp_path / "app.aab"), tmp_path / "protected.aab"
    )

    result = inspection.inspect(
        app=protected, platform=platforms.Platform.ANDROID, artifacts=_artifacts()
    )

    assert result.protected is True
    assert result.package_name == "com.android.insecurebankv2"
    assert result.build_id == _BUILD_ID
    assert result.checks == _ANDROID_CHECKS
    assert result.abis == ("arm64-v8a",)


@pytest.mark.parametrize(
    "libraries",
    [
        {},
        {"lib/arm64-v8a/libapp.so": b"app native code"},
        {"lib/arm64-v8a/librasp.so": _ARM64_SO},
    ],
)
def testInspect_whenApkCarriesNoPackedRuntime_reportsItUnprotectedWithItsIdentity(
    tmp_path: pathlib.Path, libraries: dict[str, bytes]
) -> None:
    """An APK without a runtime library holding a packed config is reported unprotected."""
    app = _make_apk(tmp_path / "app.apk", libraries)

    result = inspection.inspect(
        app=app, platform=platforms.Platform.ANDROID, artifacts=_artifacts()
    )

    assert result == inspection.InspectResult(
        protected=False,
        package_name="com.example.withapp",
        version="2.4.1",
        build_id=None,
        checks=(),
        abis=(),
    )


def _library_with(build_id: str) -> bytes:
    """Returns a packed runtime library whose slots carry the given build id."""
    layout = slots.locate(_ARM64_SO)
    values = slots.Values(
        build_id=build_id,
        checks_mask=check_groups.checks_mask(
            platforms.Platform.ANDROID, _ANDROID_CHECKS
        ),
        program=bytes(slots.PROGRAM.size),
        text_digest=hashlib.sha256(runtime_library.text_region(_ARM64_SO)).digest(),
    )
    written = slots.write(_ARM64_SO, layout, values, random.Random(0))
    return self_encrypt.encrypt_library(written)


def testInspect_whenAbiDirectoriesCarryDifferentConfigs_raisesInvalidAppError(
    tmp_path: pathlib.Path,
) -> None:
    """Two ABI directories whose runtime libraries carry different configs are rejected."""
    app = _make_apk(
        tmp_path / "app.apk",
        {
            "lib/arm64-v8a/librasp.so": _library_with("build-a"),
            "lib/x86_64/librasp.so": _library_with("build-b"),
        },
    )

    with pytest.raises(errors.InvalidAppError):
        inspection.inspect(
            app=app, platform=platforms.Platform.ANDROID, artifacts=_artifacts()
        )


def testInspect_whenOneAbiDirectoryCarriesTwoDifferentConfigs_raisesInvalidAppError(
    tmp_path: pathlib.Path,
) -> None:
    """Two runtime libraries with different configs in the same ABI directory are rejected."""
    app = _make_apk(
        tmp_path / "app.apk",
        {
            "lib/arm64-v8a/liba.so": _library_with("build-a"),
            "lib/arm64-v8a/libb.so": _library_with("build-b"),
        },
    )

    with pytest.raises(errors.InvalidAppError):
        inspection.inspect(
            app=app, platform=platforms.Platform.ANDROID, artifacts=_artifacts()
        )


def testInspect_whenIpaIsProtected_reportsTheConfigAndTheIdentity(
    ipa_file: pathlib.Path, runtime: pathlib.Path, tmp_path: pathlib.Path
) -> None:
    """A packed IPA reports the packer's build id and checks and its identity."""
    protected = tmp_path / "protected.ipa"
    ios_packer.pack(
        app=ipa_file,
        output=protected,
        runtime=runtime,
        config=_config(platforms.Platform.IOS, _IOS_CHECKS),
    )

    result = inspection.inspect(app=protected, platform=platforms.Platform.IOS)

    assert result == inspection.InspectResult(
        protected=True,
        package_name=conftest.PACKAGE_NAME,
        version=conftest.VERSION,
        build_id=_BUILD_ID,
        checks=_IOS_CHECKS,
        abis=(),
    )


def testInspect_whenIpaIsNotProtected_reportsItUnprotectedWithItsIdentity(
    ipa_file: pathlib.Path,
) -> None:
    """An IPA without the runtime framework is reported unprotected."""
    result = inspection.inspect(app=ipa_file, platform=platforms.Platform.IOS)

    assert result == inspection.InspectResult(
        protected=False,
        package_name=conftest.PACKAGE_NAME,
        version=conftest.VERSION,
        build_id=None,
        checks=(),
        abis=(),
    )


def testInspect_whenIpaEmbedsARuntimeWithoutConfig_raisesInvalidAppError(
    make_ipa: collections.abc.Callable[..., pathlib.Path],
) -> None:
    """An IPA embedding a runtime whose config space is empty is refused."""
    app = make_ipa(
        extra_entries={
            "Payload/Demo.app/Frameworks/RaspRuntime.framework/RaspRuntime": (
                conftest.RUNTIME_CONFIG_DATA / "RaspRuntime"
            ).read_bytes()
        }
    )

    with pytest.raises(errors.InvalidAppError, match="holds no runtime config"):
        inspection.inspect(app=app, platform=platforms.Platform.IOS)


@pytest.mark.parametrize(
    ("platform", "error"),
    [
        (platforms.Platform.ANDROID, errors.InvalidApkError),
        (platforms.Platform.IOS, errors.InvalidAppError),
    ],
)
def testInspect_whenFileIsNotAnApp_raisesThePlatformsError(
    tmp_path: pathlib.Path, platform: platforms.Platform, error: type[errors.Error]
) -> None:
    """A file that is not a zip archive raises the platform's invalid app error."""
    app = tmp_path / "app"
    app.write_bytes(b"not a zip")

    with pytest.raises(error):
        inspection.inspect(app=app, platform=platform)
