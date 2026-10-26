"""Tests of the packer's entry point."""

import collections.abc
import pathlib

import pytest

from rasp_packer import errors
from rasp_packer import identity
from rasp_packer import packer
from rasp_packer import platforms
from rasp_packer import plugins
from rasp_packer.android import packer as android_packer
from rasp_packer.ios import packer as ios_packer

_BUILD_ID = "a" * 64
_IDENTITY = identity.AppIdentity(package_name="dev.ostorlab.demo", version="1.2.3")


def testPack_whenIosApp_packsWithTheGivenBuildId(
    ipa_file: pathlib.Path, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: dict[str, object] = {}

    def fake_pack(
        *, app: pathlib.Path, output: pathlib.Path, build_id: object, **_: object
    ) -> identity.AppIdentity:
        calls["app"] = app
        calls["output"] = output
        calls["build_id"] = build_id
        return _IDENTITY

    monkeypatch.setattr(ios_packer, "pack", fake_pack)
    packer.pack(
        app=ipa_file,
        platform=platforms.Platform.IOS,
        output=tmp_path / "out.ipa",
        build_id=_BUILD_ID,
    )

    assert calls == {
        "app": ipa_file,
        "output": tmp_path / "out.ipa",
        "build_id": _BUILD_ID,
    }


def testPack_whenIosApp_returnsTheProtectedAppItsIdentityAndTheBuildId(
    ipa_file: pathlib.Path, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(ios_packer, "pack", lambda **_: _IDENTITY)

    result = packer.pack(
        app=ipa_file,
        platform=platforms.Platform.IOS,
        output=tmp_path / "out.ipa",
        build_id=_BUILD_ID,
    )

    assert result == packer.PackResult(
        output=tmp_path / "out.ipa",
        package_name="dev.ostorlab.demo",
        version="1.2.3",
        build_id=_BUILD_ID,
    )


def testPack_whenBuildIdHasAnyFormat_packsItAsGiven(
    ipa_file: pathlib.Path, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(ios_packer, "pack", lambda **_: _IDENTITY)

    result = packer.pack(
        app=ipa_file,
        platform=platforms.Platform.IOS,
        output=tmp_path / "out.ipa",
        build_id="build-1",
    )

    assert result.build_id == "build-1"


@pytest.mark.parametrize(
    ("build_id", "message"),
    [("", "empty"), ("build\n1", "control characters")],
)
def testPack_whenBuildIdCannotBeWritten_raisesInvalidBuildIdError(
    ipa_file: pathlib.Path, tmp_path: pathlib.Path, build_id: str, message: str
) -> None:
    with pytest.raises(errors.InvalidBuildIdError, match=message):
        packer.pack(
            app=ipa_file,
            platform=platforms.Platform.IOS,
            output=tmp_path / "out.ipa",
            build_id=build_id,
        )


def testPack_whenOutputExists_raisesOutputExistsError(tmp_path: pathlib.Path) -> None:
    output = tmp_path / "out.ipa"
    output.write_bytes(b"")

    with pytest.raises(errors.OutputExistsError):
        packer.pack(
            app=tmp_path / "app.ipa",
            platform=platforms.Platform.IOS,
            output=output,
            build_id=_BUILD_ID,
        )


def testPack_whenAndroidApp_packsWithTheGivenBuildId(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    app = tmp_path / "app.apk"
    app.write_bytes(b"an apk")
    calls: dict[str, object] = {}

    def fake_pack(
        *, app: pathlib.Path, output: pathlib.Path, build_id: object, **_: object
    ) -> identity.AppIdentity:
        calls["app"] = app
        calls["output"] = output
        calls["build_id"] = build_id
        return _IDENTITY

    monkeypatch.setattr(android_packer, "pack", fake_pack)
    packer.pack(
        app=app,
        platform=platforms.Platform.ANDROID,
        output=tmp_path / "out.apk",
        build_id=_BUILD_ID,
    )

    assert calls == {
        "app": app,
        "output": tmp_path / "out.apk",
        "build_id": _BUILD_ID,
    }


def testPack_whenAndroidApp_returnsTheProtectedAppItsIdentityAndTheBuildId(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    app = tmp_path / "app.apk"
    app.write_bytes(b"an apk")
    monkeypatch.setattr(android_packer, "pack", lambda **_: _IDENTITY)

    result = packer.pack(
        app=app,
        platform=platforms.Platform.ANDROID,
        output=tmp_path / "out.apk",
        build_id=_BUILD_ID,
    )

    assert result == packer.PackResult(
        output=tmp_path / "out.apk",
        package_name="dev.ostorlab.demo",
        version="1.2.3",
        build_id=_BUILD_ID,
    )


@pytest.mark.parametrize(
    ("platform", "packer_module"),
    [
        (platforms.Platform.IOS, ios_packer),
        (platforms.Platform.ANDROID, android_packer),
    ],
)
def testPack_whenPluginsAreGiven_passesTheLoadedBundlesInOrder(
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    make_plugin: collections.abc.Callable[..., pathlib.Path],
    platform: platforms.Platform,
    packer_module: object,
) -> None:
    bundles = [make_plugin(name="zeta"), make_plugin(name="alpha")]
    received: list[collections.abc.Sequence[plugins.Plugin]] = []

    def fake_pack(
        *, plugins: collections.abc.Sequence[plugins.Plugin], **_: object
    ) -> identity.AppIdentity:
        received.append(plugins)
        return _IDENTITY

    monkeypatch.setattr(packer_module, "pack", fake_pack)
    packer.pack(
        app=tmp_path / "app",
        platform=platform,
        output=tmp_path / "out",
        build_id=_BUILD_ID,
        plugins=bundles,
    )

    assert [[plugin.name for plugin in given] for given in received] == [
        ["zeta", "alpha"]
    ]


def testPack_whenAPluginBundleIsInvalid_raisesInvalidPluginError(
    tmp_path: pathlib.Path,
) -> None:
    with pytest.raises(errors.InvalidPluginError):
        packer.pack(
            app=tmp_path / "app.ipa",
            platform=platforms.Platform.IOS,
            output=tmp_path / "out.ipa",
            build_id=_BUILD_ID,
            plugins=[tmp_path / "missing"],
        )
