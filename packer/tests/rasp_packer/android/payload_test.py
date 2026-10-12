"""Tests of the payload container."""

from rasp_packer.android import cipher
from rasp_packer.android import payload

# The payload the native runtime's tests unpack (runtime/tests/android/payload/payload_test.cpp).
_RUNTIME_KEY = bytes.fromhex(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
)
_RUNTIME_PAYLOAD = bytes.fromhex(
    "000102030405060708090a0b89fb08022917a54bd4ef5e80eb787d4dad15cae75174a2fda3cf02b507a9cb5d9ef901c3"
    "d62fb198373e15b404e7fc460db687109850b89b12a89d42c862edb31a17d2a9846655c4f624e056ce59e1b5f8c08278"
    "cb9333815322"
)


def testParse_whenGivenBuildOutput_returnsTheDexes() -> None:
    key = cipher.new_key()
    dexes = [
        payload.Dex(name="classes.dex", data=b"primary dex"),
        payload.Dex(name="classes2.dex", data=b"secondary dex"),
    ]
    assert payload.parse(key, payload.build(key, dexes)) == dexes


def testParse_whenNoDexes_returnsAnEmptyList() -> None:
    key = cipher.new_key()
    assert payload.parse(key, payload.build(key, [])) == []


def testBuild_whenCalled_encryptsTheDexes() -> None:
    key = cipher.new_key()
    frame = payload.build(key, [payload.Dex(name="classes.dex", data=b"secret code")])
    assert b"secret code" not in frame


def testParse_whenGivenTheRuntimesTestPayload_returnsItsDexFiles() -> None:
    assert payload.parse(_RUNTIME_KEY, _RUNTIME_PAYLOAD) == [
        payload.Dex(name="classes.dex", data=b"DEX-primary-001"),
        payload.Dex(name="classes2.dex", data=b"DEX-secondary-22"),
    ]
