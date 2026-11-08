"""Tests of the key schedule, with the fixed vectors the native runtime's tests share.

The vectors below (runtime/tests/android/payload/key_schedule_test.cpp) pin the packer side of the
schedule: the same fixed root, shares, nonces and plaintexts must give the same keys and frames. When
the schedule changes on either side, these tests fail on both.
"""

import pathlib

import pytest

from rasp_packer import runtime_config
from rasp_packer.android import cipher
from rasp_packer.android import key_schedule
from rasp_packer.android import runtime_library
from tests.rasp_packer import conftest

_ROOT = bytes.fromhex(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
)
_SHARE_ASSET = bytes.fromhex(
    "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
)
_MAP_NONCE = bytes.fromhex("000102030405060708090a0b")
_DEX0_NONCE = bytes.fromhex("101112131415161718191a1b")
_DEX1_NONCE = bytes.fromhex("202122232425262728292a2b")

_MAP_KEY = bytes.fromhex(
    "3cd614f94a393fbc968ce0b09feafec71d164971476e62353ffa7fc913b3a6f7"
)
_MAP_FRAME = bytes.fromhex(
    "000102030405060708090a0bfa778ca58fe9a3129eb01f255c3f58b75132615e4a4fbdce9a57a5c9b8f2ddc5099d30eff"
    "a98d3c123c032a7f98fcc8164af6e17296abe4fea2f1ac70ef47c9e378a9380aabc9acffdd578afe2236448884315803"
    "1b90902b5c6641af81ce706f994da417c658b0406c21eea5c9236bb6aa18798a655a86776437e8309fda8c48c154b2128"
    "77a652cd3963fa7c0d59c8b620aa"
)
_MASTER = bytes.fromhex(
    "0c3ee85700c0bc074d37b2fbc19ce5e1b908074cb788797fb922a1b3a47addbe"
)
_DEX0_FRAME = bytes.fromhex(
    "101112131415161718191a1b8b1ee9ab64248cd5df0472dcf17e727a38b00d8eb15b986e4c67ab8fb78952634d1d96305"
    "5ec9a7f04b5f4d27b99c6080c34b0001e76661051ca19978ffbaa862837613153b36f311592744af503ee"
)
_DEX1_FRAME = bytes.fromhex(
    "202122232425262728292a2ba2851fa4da0a9d8ff2ababc947146ff64a8c8516c66ee54311f1721f9dd1b6a3ee"
)
_SHARE_LIB = bytes.fromhex(
    "da36643e1969de042320709105f0f188332bb3caab836c521f811aafe47fefe7"
)

_MAP_ENTRY = "assets/rasp/map.bin"
_DEX0_ENTRY = "assets/business/0.dex"
_DEX1_ENTRY = "assets/business/1.dex"
_MAP_TEXT = (
    b"com.example.Alpha,business/0.dex\n"
    b"com.example.Beta,business/0.dex\n"
    b"com.example.Gamma,business/1.dex\n"
    b"com.example.Alpha,business/1.dex\n"
)
_DEX0_PLAINTEXT = b"business dex zero: bytes that decrypt_dex must return verbatim\n"
_DEX1_PLAINTEXT = b"business dex one\n"

_LIBRARY = (conftest.RUNTIME_CONFIG_DATA / "librasp.so").read_bytes()
_CONFIG = runtime_config.RuntimeConfig(
    build_id="rasp-build/v1:" + "ab" * 32, checks=("identity",)
)


def testFold_whenGivenTwoParts_returnsTheirBytewiseXor() -> None:
    left = bytes(range(32))
    right = bytes(range(32, 64))

    folded = key_schedule.fold(left, right)

    assert folded == bytes(a ^ b for a, b in zip(left, right, strict=True))


def testFold_whenGivenOnePart_returnsIt() -> None:
    part = bytes(range(32))

    assert key_schedule.fold(part) == part


def testFold_whenAPartIsTheWrongSize_raisesValueError() -> None:
    with pytest.raises(ValueError, match="32 bytes"):
        key_schedule.fold(bytes(32), bytes(31))


def testFold_whenThereIsNoPart_raisesValueError() -> None:
    with pytest.raises(ValueError, match="32 bytes"):
        key_schedule.fold()


def testGateBlock_whenCleanDevice_isTheCleanGates() -> None:
    clean = key_schedule.gate_block(
        java_environment=True, no_tracer=True, installed_under_data=True
    )

    assert clean == key_schedule.CLEAN_GATES
    assert clean[0:3] == b"\x01\x01\x01"
    assert clean[3:] == bytes(29)


def testGateBlock_whenAFactFails_flipsItsByte() -> None:
    dirty = key_schedule.gate_block(
        java_environment=True, no_tracer=False, installed_under_data=True
    )

    assert dirty != key_schedule.CLEAN_GATES
    assert dirty[1] == 0


def testShareFor_whenFoldedByRootKey_recoversTheRoot() -> None:
    config_binding = bytes(range(64, 96))
    text_binding = bytes(range(96, 128))

    share = key_schedule.share_for(
        _ROOT, _SHARE_ASSET, config_binding, text_binding, key_schedule.CLEAN_GATES
    )
    recovered = key_schedule.root_key(
        share, _SHARE_ASSET, config_binding, text_binding, key_schedule.CLEAN_GATES
    )

    assert recovered == _ROOT


def testRootKey_whenAnyPartChanges_changes() -> None:
    parts = (
        _SHARE_LIB,
        _SHARE_ASSET,
        bytes(range(64, 96)),
        bytes(range(96, 128)),
        key_schedule.CLEAN_GATES,
    )
    root = key_schedule.root_key(*parts)
    for index in range(len(parts)):
        tampered = list(parts)
        tampered[index] = bytes(
            b ^ (1 if i == 0 else 0) for i, b in enumerate(tampered[index])
        )
        assert key_schedule.root_key(*tampered) != root


def testFrameKey_whenGivenTheVectorInputs_matchesTheVectorKey() -> None:
    assert key_schedule.frame_key(_ROOT, _MAP_NONCE, _MAP_ENTRY) == _MAP_KEY


def testFrameKey_whenEntryDiffers_derivesADifferentKey() -> None:
    assert key_schedule.frame_key(_ROOT, _MAP_NONCE, _DEX0_ENTRY) != _MAP_KEY


def testFrameKey_whenNonceDiffers_derivesADifferentKey() -> None:
    assert key_schedule.frame_key(_ROOT, _DEX0_NONCE, _MAP_ENTRY) != _MAP_KEY


def testFrameKey_whenMasterDiffers_derivesADifferentKey() -> None:
    assert key_schedule.frame_key(_MASTER, _MAP_NONCE, _MAP_ENTRY) != _MAP_KEY


def testFrameKey_whenMasterIsTheWrongSize_raisesValueError() -> None:
    with pytest.raises(ValueError, match="32 bytes"):
        key_schedule.frame_key(bytes(31), _MAP_NONCE, _MAP_ENTRY)


def testFrameKey_whenNonceIsTheWrongSize_raisesValueError() -> None:
    with pytest.raises(ValueError, match="12 bytes"):
        key_schedule.frame_key(_ROOT, bytes(11), _MAP_ENTRY)


def testDexMaster_whenGivenTheVectorInputs_matchesTheVectorMaster() -> None:
    assert key_schedule.dex_master(_ROOT, _MAP_FRAME) == _MASTER


def testDexMaster_whenTheMapFrameChanges_changes() -> None:
    tampered = bytearray(_MAP_FRAME)
    tampered[-1] ^= 0x01

    assert key_schedule.dex_master(_ROOT, bytes(tampered)) != _MASTER


def testMapFrame_whenSealedUnderTheVectorKey_matchesTheVectorFrame() -> None:
    assert cipher.encrypt(_MAP_KEY, _MAP_NONCE, _MAP_TEXT) == _MAP_FRAME


def testDexFrames_whenSealedUnderTheVectorKeys_matchTheVectorFrames() -> None:
    dex0_key = key_schedule.frame_key(_MASTER, _DEX0_NONCE, _DEX0_ENTRY)
    dex1_key = key_schedule.frame_key(_MASTER, _DEX1_NONCE, _DEX1_ENTRY)

    assert cipher.encrypt(dex0_key, _DEX0_NONCE, _DEX0_PLAINTEXT) == _DEX0_FRAME
    assert cipher.encrypt(dex1_key, _DEX1_NONCE, _DEX1_PLAINTEXT) == _DEX1_FRAME


def testVectorLibrary_whenRecoveredLikeTheRuntime_givesTheVectorRoot() -> None:
    configured = runtime_library.write_config(_LIBRARY, _CONFIG)
    config_binding = key_schedule.bind_config(runtime_library.config_region(configured))
    text_binding = key_schedule.bind_text(runtime_library.text_region(configured))
    share = key_schedule.share_for(
        _ROOT, _SHARE_ASSET, config_binding, text_binding, key_schedule.CLEAN_GATES
    )
    library = runtime_library.write_keystore(configured, share)

    assert share == _SHARE_LIB
    recovered = key_schedule.root_key(
        runtime_library.keystore(library),
        _SHARE_ASSET,
        key_schedule.bind_config(runtime_library.config_region(library)),
        key_schedule.bind_text(runtime_library.text_region(library)),
        key_schedule.CLEAN_GATES,
    )
    assert recovered == _ROOT


def testNewRootAndShare_whenCalled_returnFreshValues() -> None:
    assert key_schedule.new_root() != key_schedule.new_root()
    assert key_schedule.new_share() != key_schedule.new_share()
    assert len(key_schedule.new_root()) == key_schedule.KEY_SIZE
    assert len(key_schedule.new_share()) == key_schedule.KEY_SIZE


def testShareEntry_isUnderTheRaspAssets() -> None:
    assert key_schedule.SHARE_ENTRY.startswith("assets/rasp/")
    assert pathlib.PurePosixPath(key_schedule.SHARE_ENTRY).name == "s.bin"
