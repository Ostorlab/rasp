"""Tests of unpacking and repacking an IPA."""

import collections.abc
import pathlib
import stat
import zipfile

import pytest

from rasp_packer import errors
from rasp_packer import identity
from rasp_packer.ios import ipa
from tests.rasp_packer import conftest


def _extract(path: pathlib.Path, tmp_path: pathlib.Path) -> ipa.AppBundle:
    destination = tmp_path / "out"
    destination.mkdir(exist_ok=True)
    return ipa.extract(path, destination)


def testExtract_whenValidIpa_findsTheAppBundle(
    ipa_file: pathlib.Path, tmp_path: pathlib.Path
) -> None:
    bundle = _extract(ipa_file, tmp_path)

    assert bundle.app_dir == tmp_path / "out" / "Payload" / "Demo.app"
    assert bundle.executable == bundle.app_dir / "Demo"
    assert bundle.frameworks_dir == bundle.app_dir / "Frameworks"


def testExtract_whenValidIpa_readsTheAppIdentity(
    ipa_file: pathlib.Path, tmp_path: pathlib.Path
) -> None:
    bundle = _extract(ipa_file, tmp_path)

    assert bundle.identity == identity.AppIdentity(
        package_name=conftest.PACKAGE_NAME, version=conftest.VERSION
    )


@pytest.mark.parametrize(
    "key", ["CFBundleExecutable", "CFBundleIdentifier", "CFBundleShortVersionString"]
)
def testExtract_whenInfoPlistLacksAKey_raisesInvalidAppError(
    make_ipa: collections.abc.Callable[..., pathlib.Path],
    tmp_path: pathlib.Path,
    key: str,
) -> None:
    info = {name: value for name, value in conftest.APP_INFO.items() if name != key}

    with pytest.raises(errors.InvalidAppError, match=key):
        _extract(make_ipa(info=info), tmp_path)


def testExtract_whenExecutableIsExecutable_keepsItsMode(
    ipa_file: pathlib.Path, tmp_path: pathlib.Path
) -> None:
    bundle = _extract(ipa_file, tmp_path)

    assert stat.S_IMODE(bundle.executable.stat().st_mode) == 0o755


def testArchive_whenRepacked_keepsTheExecutableMode(
    ipa_file: pathlib.Path, tmp_path: pathlib.Path
) -> None:
    bundle = _extract(ipa_file, tmp_path)
    output = tmp_path / "repacked.ipa"

    ipa.archive(bundle.payload_dir, output)

    with zipfile.ZipFile(output) as archive:
        entry = archive.getinfo("Payload/Demo.app/Demo")
    assert stat.S_IMODE(entry.external_attr >> 16) == 0o755


def testExtract_whenNotAZip_raisesInvalidAppError(tmp_path: pathlib.Path) -> None:
    path = tmp_path / "Demo.ipa"
    path.write_text("not a zip")

    with pytest.raises(errors.InvalidAppError, match="not a zip archive"):
        _extract(path, tmp_path)


def testExtract_whenFileIsMissing_raisesInvalidAppError(tmp_path: pathlib.Path) -> None:
    with pytest.raises(errors.InvalidAppError, match="cannot read"):
        _extract(tmp_path / "Demo.ipa", tmp_path)


@pytest.mark.parametrize(
    ("entries", "message"),
    [
        ({"Payload/Other.app/Info.plist": b""}, "2 app bundles"),
        ({"../escape": b""}, "outside the archive root"),
    ],
)
def testExtract_whenArchiveIsMalformed_raisesInvalidAppError(
    make_ipa: collections.abc.Callable[..., pathlib.Path],
    tmp_path: pathlib.Path,
    entries: dict[str, bytes],
    message: str,
) -> None:
    path = make_ipa(extra_entries=entries)

    with pytest.raises(errors.InvalidAppError, match=message):
        _extract(path, tmp_path)


def testExtract_whenEntryIsASymbolicLink_raisesInvalidAppError(
    ipa_file: pathlib.Path, tmp_path: pathlib.Path
) -> None:
    with zipfile.ZipFile(ipa_file, "a") as archive:
        link = zipfile.ZipInfo("Payload/Demo.app/link")
        link.external_attr = (stat.S_IFLNK | 0o777) << 16
        archive.writestr(link, "Demo")

    with pytest.raises(errors.InvalidAppError, match="symbolic links"):
        _extract(ipa_file, tmp_path)


def testExtract_whenDestinationPayloadSymlinksOutside_rejectsWithoutExternalWrite(
    ipa_file: pathlib.Path, tmp_path: pathlib.Path
) -> None:
    destination = tmp_path / "destination"
    destination.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (destination / "Payload").symlink_to(outside, target_is_directory=True)

    with pytest.raises(errors.InvalidAppError, match="outside the archive root"):
        ipa.extract(ipa_file, destination)

    assert list(outside.iterdir()) == []


def testExtract_whenNoPayload_raisesInvalidAppError(tmp_path: pathlib.Path) -> None:
    path = tmp_path / "Demo.ipa"
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("Demo.app/Info.plist", b"")

    with pytest.raises(errors.InvalidAppError, match="no Payload"):
        _extract(path, tmp_path)
