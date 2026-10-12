"""Tests of the payload container."""

from rasp_packer.android import cipher
from rasp_packer.android import payload


def testBuildParse_roundTrips() -> None:
    key = cipher.new_key()
    dexes = [
        payload.Dex(name="classes.dex", data=b"primary dex"),
        payload.Dex(name="classes2.dex", data=b"secondary dex"),
    ]
    assert payload.parse(key, payload.build(key, dexes)) == dexes


def testBuildParse_emptyList_roundTrips() -> None:
    key = cipher.new_key()
    assert payload.parse(key, payload.build(key, [])) == []


def testBuild_isEncrypted() -> None:
    key = cipher.new_key()
    frame = payload.build(key, [payload.Dex(name="classes.dex", data=b"secret code")])
    assert b"secret code" not in frame
