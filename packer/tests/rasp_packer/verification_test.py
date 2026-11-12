"""Verification against actual packed archives and prepared injection bytes."""

from __future__ import annotations

import collections.abc
import errno
import os
import pathlib
import tempfile
import zipfile

import pytest

from rasp_packer import errors
from rasp_packer import platforms
from rasp_packer import runtime_config
from rasp_packer import verification
from rasp_packer.android import cipher
from rasp_packer.android import packer as android_packer
from rasp_packer.android import resources
from rasp_packer.android import split
from rasp_packer.android.aab import manifest as aab_manifest
from rasp_packer.android.apk import archive as apk_archive
from rasp_packer.android.apk import manifest as apk_manifest
from rasp_packer.ios import packer as ios_packer
from tests.rasp_packer import conftest
from tests.rasp_packer.android import packer_test as apk_tests
from tests.rasp_packer.android.aab import packer_test as aab_tests

_CONFIG = runtime_config.RuntimeConfig(build_id="build-1", checks=("identity",))
type Packed = tuple[pathlib.Path, platforms.Platform, dict[str, bytes]]


@pytest.fixture(params=["apk", "aab", "ipa"])
def packed(
    request: pytest.FixtureRequest,
    tmp_path: pathlib.Path,
    ipa_file: pathlib.Path,
    runtime: pathlib.Path,
) -> Packed:
    kind = request.param
    app = tmp_path / f"input.{kind}"
    output = tmp_path / f"protected.{kind}"
    platform = platforms.Platform.ANDROID
    if kind == "ipa":
        platform = platforms.Platform.IOS
        ios_packer.pack(app=ipa_file, output=output, runtime=runtime, config=_CONFIG)
    else:
        if kind == "apk":
            apk_tests._make_apk(app)
        else:
            aab_tests._make_aab(app)
        android_packer.pack(
            app=app,
            output=output,
            config=_CONFIG,
            artifacts=resources.Artifacts(
                stub_dex=b"fixture stub",
                libraries={
                    "arm64-v8a": (
                        conftest.RUNTIME_CONFIG_DATA / "librasp.so"
                    ).read_bytes()
                },
            ),
            splitter=lambda *_: split.Split(
                framework=(),
                business=(
                    split.BusinessDex(
                        path="business/0.dex",
                        data=b"fixture DEX",
                        classes=("example.App",),
                    ),
                ),
            ),
            aab_splitter=lambda *_: split.Split(
                framework=(),
                business=(
                    split.BusinessDex(
                        path="business/0.dex",
                        data=b"fixture DEX",
                        classes=("example.App",),
                    ),
                ),
            ),
        )
    with zipfile.ZipFile(output) as archive:
        expected = {
            info.filename: archive.read(info)
            for info in archive.infolist()
            if info.is_dir() is False
        }
    return output, platform, expected


def _rewrite(path: pathlib.Path, entries: collections.abc.Mapping[str, bytes]) -> None:
    if path.suffix == ".apk":
        apk_archive.Apk([]).write(path, replace={}, add=entries, remove=set())
    else:
        with zipfile.ZipFile(path) as source:
            infos = {info.filename: info for info in source.infolist()}
        with zipfile.ZipFile(path, "w") as archive:
            for name, data in entries.items():
                archive.writestr(infos.get(name, zipfile.ZipInfo(name)), data)


def testVerify_whenPackedArchive_returnsExplicitStructuralResult(
    packed: Packed,
) -> None:
    path, platform, expected = packed
    result = verification.verify(
        app=path, platform=platform, config=_CONFIG, expected_entries=expected
    )
    assert result.artifact_format == path.suffix[1:]
    assert len(result.runtime_entries) == 1
    assert result.config == _CONFIG


@pytest.mark.parametrize("artifact", ["runtime", "loader", "payload", "config"])
@pytest.mark.parametrize("replace", [False, True])
def testVerify_whenProtectionArtifactMissingOrReplaced_rejects(
    packed: Packed, artifact: str, replace: bool
) -> None:
    path, platform, expected = packed
    if artifact == "payload" and platform == platforms.Platform.IOS:
        pytest.skip("IPA has no encrypted DEX payload")
    if platform == platforms.Platform.IOS:
        target = {
            "runtime": "Payload/Demo.app/Frameworks/RaspRuntime.framework/RaspRuntime",
            "config": "Payload/Demo.app/Frameworks/RaspRuntime.framework/RaspRuntime",
            "loader": "Payload/Demo.app/Demo",
        }[artifact]
    else:
        prefix = "base/" if path.suffix == ".aab" else ""
        target = {
            "runtime": prefix + "lib/arm64-v8a/librasp.so",
            "config": prefix + "lib/arm64-v8a/librasp.so",
            "payload": prefix + "assets/business/0.dex",
            "loader": prefix + ("dex/" if prefix != "" else "") + "classes.dex",
        }[artifact]
    changed = dict(expected)
    if replace is True:
        changed[target] = b"replaced"
    else:
        del changed[target]
    _rewrite(path, changed)
    with pytest.raises(errors.VerificationError):
        verification.verify(
            app=path, platform=platform, config=_CONFIG, expected_entries=expected
        )


def testVerify_whenPlatformMismatches_rejects(packed: Packed) -> None:
    path, platform, expected = packed
    other = (
        platforms.Platform.IOS
        if platform == platforms.Platform.ANDROID
        else platforms.Platform.ANDROID
    )
    with pytest.raises(errors.VerificationError):
        verification.verify(
            app=path, platform=other, config=_CONFIG, expected_entries=expected
        )


@pytest.mark.parametrize(
    "name",
    [
        "../escape",
        "assets/./rasp/key.bin",
        "assets//rasp/key.bin",
        "assets\\rasp\\key.bin",
        "/absolute",
    ],
)
def testVerify_whenArchivePathConfused_rejects(packed: Packed, name: str) -> None:
    path, platform, expected = packed
    _rewrite(path, {**expected, name: b"ambiguous"})
    with pytest.raises(errors.VerificationError, match="path"):
        verification.verify(
            app=path, platform=platform, config=_CONFIG, expected_entries=expected
        )


@pytest.mark.parametrize("damage", ["zip", "duplicate", "manifest", "config"])
def testVerify_whenArchiveOrConfigurationMalformed_rejects(
    packed: Packed, damage: str
) -> None:
    path, platform, expected = packed
    changed = dict(expected)
    if damage == "zip":
        path.write_bytes(b"not a ZIP")
    elif damage == "duplicate":
        name = next(iter(expected))
        with (
            zipfile.ZipFile(path, "a") as archive,
            pytest.warns(UserWarning, match="Duplicate"),
        ):
            archive.writestr(name, expected[name])
    else:
        if damage == "manifest":
            name = (
                "Payload/Demo.app/Info.plist"
                if platform == platforms.Platform.IOS
                else (
                    "base/manifest/AndroidManifest.xml"
                    if path.suffix == ".aab"
                    else "AndroidManifest.xml"
                )
            )
            changed[name] = b"malformed manifest"
        else:
            name = next(
                name
                for name in expected
                if name.endswith(("librasp.so", "/RaspRuntime"))
            )
            changed[name] = expected[name].replace(b'{"build_id"', b'["build_id"', 1)
        _rewrite(path, changed)
    with pytest.raises(errors.VerificationError):
        verification.verify(
            app=path, platform=platform, config=_CONFIG, expected_entries=changed
        )


@pytest.mark.parametrize("damage", ["abi", "map", "key", "tag", "factory", "sdk"])
def testVerify_whenAndroidArtifactsIncoherent_rejects(
    packed: Packed, damage: str
) -> None:
    path, platform, expected = packed
    if platform == platforms.Platform.IOS:
        pytest.skip("Android-specific artifact contract")
    prefix = "base/" if path.suffix == ".aab" else ""
    changed = dict(expected)
    if damage == "abi":
        name = prefix + "lib/arm64-v8a/librasp.so"
        library = bytearray(expected[name])
        library[18:20] = (62).to_bytes(2, "little")
        changed[name] = bytes(library)
    elif damage in {"factory", "sdk"}:
        name = (
            "base/manifest/AndroidManifest.xml"
            if prefix != ""
            else "AndroidManifest.xml"
        )
        if prefix != "":
            changed[name] = aab_tests._proto_manifest()
        else:
            changed[name] = (
                pathlib.Path(apk_tests.__file__).parent
                / "apk/fixtures/manifest_with_application_and_version.bin"
            ).read_bytes()
        if damage == "sdk":
            manifest_module = aab_manifest if prefix != "" else apk_manifest
            changed[name] = manifest_module.set_app_component_factory(
                changed[name], resources.STUB_FACTORY_CLASS
            )
    elif damage == "map":
        changed[prefix + "assets/rasp/map.bin"] = cipher.encrypt(
            expected[prefix + "assets/rasp/key.bin"], b"example.App,business/9.dex\n"
        )
    elif damage == "key":
        changed[prefix + "assets/rasp/key.bin"] = b"too short"
    else:
        name = prefix + "assets/business/0.dex"
        changed[name] = expected[name][:-1] + bytes([expected[name][-1] ^ 1])
    _rewrite(path, changed)
    with pytest.raises(errors.VerificationError):
        verification.verify(
            app=path, platform=platform, config=_CONFIG, expected_entries=changed
        )


def testVerify_whenUnalignedApk_rejects(packed: Packed) -> None:
    path, platform, expected = packed
    if path.suffix != ".apk":
        pytest.skip("AAB and IPA have no APK alignment contract")
    with zipfile.ZipFile(path, "w") as archive:
        for name, data in expected.items():
            archive.writestr(name, data)
    with pytest.raises(errors.VerificationError, match="align"):
        verification.verify(
            app=path, platform=platform, config=_CONFIG, expected_entries=expected
        )


def testVerify_whenPayloadCompressedInApk_rejects(packed: Packed) -> None:
    path, platform, expected = packed
    if path.suffix != ".apk":
        pytest.skip("APK runtime reads stored payload members")
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in expected.items():
            archive.writestr(name, data)
    with pytest.raises(errors.VerificationError, match="stored"):
        verification.verify(
            app=path, platform=platform, config=_CONFIG, expected_entries=expected
        )


def testVerify_whenAabHasFeatureDeliveryAndCompressedAssets_accepts(
    packed: Packed,
) -> None:
    path, platform, expected = packed
    if path.suffix != ".aab":
        pytest.skip("AAB feature delivery contract")
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in {
            **expected,
            "feature/dex/classes.dex": b"feature",
            "feature/lib/x86_64/libfeature.so": b"feature ABI",
            "feature/assets/data.bin": b"asset",
        }.items():
            archive.writestr(name, data)
    assert (
        verification.verify(
            app=path, platform=platform, config=_CONFIG, expected_entries=expected
        ).artifact_format
        == "aab"
    )


def testVerify_whenMapUsesCarriageReturnRatherThanRuntimeNewline_rejects(
    packed: Packed,
) -> None:
    path, platform, expected = packed
    if platform == platforms.Platform.IOS:
        pytest.skip("Android class-map parsing")
    prefix = "base/" if path.suffix == ".aab" else ""
    changed = dict(expected)
    changed[prefix + "assets/rasp/map.bin"] = cipher.encrypt(
        expected[prefix + "assets/rasp/key.bin"], b"example.App,business/0.dex\r\n"
    )
    _rewrite(path, changed)
    with pytest.raises(errors.VerificationError, match="class-map"):
        verification.verify(
            app=path, platform=platform, config=_CONFIG, expected_entries=changed
        )


@pytest.mark.parametrize("damage", ["runtimeType", "executableMode"])
def testVerify_whenIosMetadataInvalid_rejects(packed: Packed, damage: str) -> None:
    path, platform, expected = packed
    if platform != platforms.Platform.IOS:
        pytest.skip("IPA binary metadata")
    changed = dict(expected)
    if damage == "runtimeType":
        name = "Payload/Demo.app/Frameworks/RaspRuntime.framework/RaspRuntime"
        data = bytearray(changed[name])
        data[12:16] = (2).to_bytes(4, "little")
        changed[name] = bytes(data)
        _rewrite(path, changed)
    else:
        with zipfile.ZipFile(path) as source:
            infos = {info.filename: info for info in source.infolist()}
        infos["Payload/Demo.app/Demo"].external_attr = 0o100644 << 16
        with zipfile.ZipFile(path, "w") as archive:
            for name, content in changed.items():
                archive.writestr(infos[name], content)
    with pytest.raises(errors.VerificationError):
        verification.verify(
            app=path, platform=platform, config=_CONFIG, expected_entries=changed
        )


def testStagedOutput_whenDestinationAppears_preservesExistingFile(
    tmp_path: pathlib.Path,
) -> None:
    output = tmp_path / "protected.apk"

    def publish() -> None:
        with verification.staged_output(output) as staged:
            staged.write_bytes(b"verified")
            output.write_bytes(b"another caller")

    with pytest.raises(errors.OutputExistsError):
        publish()
    assert output.read_bytes() == b"another caller"
    assert list(tmp_path.glob(".rasp-*")) == []


@pytest.mark.parametrize("parent_kind", ["missing", "file"])
def testStagedOutput_whenParentIsUnusable_raisesCleanErrorWithoutOutput(
    tmp_path: pathlib.Path, parent_kind: str
) -> None:
    parent = tmp_path / parent_kind
    if parent_kind == "file":
        parent.write_bytes(b"keep")
    output = parent / "protected.apk"
    with (
        pytest.raises(errors.Error, match="cannot create output staging directory"),
        verification.staged_output(output),
    ):
        pytest.fail("packing must not start without staging")
    assert output.exists() is False
    assert list(tmp_path.glob(".rasp-*")) == []
    if parent_kind == "file":
        assert parent.read_bytes() == b"keep"


def testStagedOutput_whenParentIsNotWritable_raisesCleanError(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def denied(*args: object, **kwargs: object) -> None:
        raise PermissionError(errno.EACCES, "staging denied")

    monkeypatch.setattr(tempfile, "TemporaryDirectory", denied)
    with (
        pytest.raises(errors.Error, match="cannot create output staging directory"),
        verification.staged_output(tmp_path / "protected.apk"),
    ):
        pytest.fail("packing must not start without staging")
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize(
    "error_number", [errno.EOPNOTSUPP, errno.EACCES, errno.EPERM, errno.EXDEV]
)
@pytest.mark.parametrize("racing_output", [False, True])
def testStagedOutput_whenHardLinkFails_raisesCleanErrorAndNeverOverwrites(
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
    error_number: int,
    racing_output: bool,
) -> None:
    output = tmp_path / "protected.apk"

    def fail_link(source: pathlib.Path, destination: pathlib.Path) -> None:
        assert source.read_bytes() == b"verified"
        assert destination == output
        if racing_output is True:
            destination.write_bytes(b"another caller")
        raise OSError(error_number, "hard link denied")

    monkeypatch.setattr(os, "link", fail_link)
    with (
        pytest.raises(
            errors.Error, match=r"cannot publish.*atomically with a hard link"
        ),
        verification.staged_output(output) as staged,
    ):
        staged.write_bytes(b"verified")
    assert list(tmp_path.glob(".rasp-*")) == []
    if racing_output is True:
        assert output.read_bytes() == b"another caller"
    else:
        assert output.exists() is False
