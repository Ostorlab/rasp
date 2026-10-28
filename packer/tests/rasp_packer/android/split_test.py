"""Tests of the dex-splitter seam.

These cover reading a recorded splitter output directory, which needs no tool, and resolving the
tool to run. Running the bundled splitter itself (``split.split``) is covered end to end against a
device, not here.
"""

import pathlib

import pytest

from rasp_packer.android import split


def testSplit_whenOverrideIsNotAFile_raisesSplitError(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(split.SPLIT_DEX_ENV, str(tmp_path / "no-such-split-dex"))
    with pytest.raises(split.SplitError):
        split.split(tmp_path / "app.apk", "com.example")


def _write_output(
    out: pathlib.Path,
    *,
    sets: str,
    index: str,
    dex_files: dict[str, bytes],
) -> None:
    (out / "sets.csv").write_text("file,set\n" + sets, encoding="utf-8")
    (out / "index.csv").write_text("class,file\n" + index, encoding="utf-8")
    for name, data in dex_files.items():
        (out / name).write_bytes(data)


def testReadOutput_whenBusinessAndFramework_groupsAndReindexesThem(
    tmp_path: pathlib.Path,
) -> None:
    _write_output(
        tmp_path,
        sets="0.dex,business\n1.dex,framework\n2.dex,business\n",
        index=(
            "Lcom/example/A;,0.dex\n"
            "Lcom/example/B;,0.dex\n"
            "Landroidx/core/X;,1.dex\n"
            "Lcom/example/sub/C;,2.dex\n"
        ),
        dex_files={"0.dex": b"BIZ0", "1.dex": b"FW", "2.dex": b"BIZ2"},
    )
    result = split.read_output(tmp_path)
    assert result.framework == (b"FW",)
    assert result.business == (
        split.BusinessDex(
            path="business/0.dex",
            data=b"BIZ0",
            classes=("com.example.A", "com.example.B"),
        ),
        split.BusinessDex(
            path="business/1.dex", data=b"BIZ2", classes=("com.example.sub.C",)
        ),
    )


def testReadOutput_whenFileMissing_raisesSplitError(tmp_path: pathlib.Path) -> None:
    (tmp_path / "sets.csv").write_text("file,set\n0.dex,business\n", encoding="utf-8")
    with pytest.raises(split.SplitError):
        split.read_output(tmp_path)


def testReadOutput_whenHeaderUnexpected_raisesSplitError(
    tmp_path: pathlib.Path,
) -> None:
    (tmp_path / "sets.csv").write_text("name,group\n0.dex,business\n", encoding="utf-8")
    (tmp_path / "index.csv").write_text("class,file\n", encoding="utf-8")
    with pytest.raises(split.SplitError):
        split.read_output(tmp_path)


def testReadOutput_whenDescriptorMalformed_raisesSplitError(
    tmp_path: pathlib.Path,
) -> None:
    _write_output(
        tmp_path,
        sets="0.dex,business\n",
        index="com.example.A,0.dex\n",
        dex_files={"0.dex": b"BIZ0"},
    )
    with pytest.raises(split.SplitError):
        split.read_output(tmp_path)


# ── split_from_dex_entries ───────────────────────────────────


def testSplitFromDexEntries_whenEmpty_raisesSplitError() -> None:
    with pytest.raises(split.SplitError, match="no DEX entries"):
        split.split_from_dex_entries({}, "com.example")


def testSplitFromDexEntries_whenOverrideIsNotAFile_raisesSplitError(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(split.SPLIT_DEX_ENV, str(tmp_path / "no-such-split-dex"))
    with pytest.raises(split.SplitError):
        split.split_from_dex_entries({"classes.dex": b"dex"}, "com.example")
