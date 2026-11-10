"""Tests of the key schedule's fold: the program, the chains, the guard, and the fixed vectors the native runtime's tests share.

The vectors below (runtime/tests/android/payload/key_schedule_test.cpp) pin the packer side of the schedule: the same fixed program, root, shares and plaintexts must give the same keys and frames. When the schedule changes on either side, these tests fail on both.
"""

import collections.abc
import hashlib
import io
import random

import lief
import pytest

from rasp_packer import runtime_config
from rasp_packer.android import cipher
from rasp_packer.android import java_program
from rasp_packer.android import key_schedule
from rasp_packer.android import runtime_library
from tests.rasp_packer import conftest
from tests.rasp_packer.android import schedule_recovery

_ROOT = bytes.fromhex(
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
)
_SHARE = bytes.fromhex(
    "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
)
_CONSTANT = bytes.fromhex(
    "404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f"
)
_DECOY0 = bytes.fromhex(
    "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f"
)
_DECOY1 = bytes.fromhex(
    "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
)

_MASK = bytes(range(16))
_MAP_NONCE = bytes.fromhex("000102030405060708090a0b")
_DEX0_NONCE = bytes.fromhex("101112131415161718191a1b")
_DEX1_NONCE = bytes.fromhex("202122232425262728292a2b")

_PROGRAM_HEX = (
    "000102030405060708090a0b0c0d0e0f030104030405060708090a0b0d0d0c0f00010203"
    "060546076c090a0b080d0e0f000102030705060708090a0b0a0d0e0f0001020301050607"
    "08090a0b0b0d0e0f000102030305070708090a0b0c0d0e0f000102030405060708090a0b"
    "0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f"
    "00010203444444444c4c4c4c444444444c4c4c4c545454545c5c5c5c545454545c5c5c5c"
    "0405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f0001020304050607"
    "08090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b"
    "0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f"
    "000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f00010203"
    "0405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f0001020304050607"
    "08090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b"
    "0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f"
    "000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f00010203"
    "0405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f0001020304050607"
    "08090a0b0c0d0e0f"
)
_A_STATE = bytes.fromhex(
    "80f696036977bec443168ac195612f3bbef55acceddbccc100170f56d18053b4"
)
_S_STATE = bytes.fromhex(
    "5f6e5fd1da465bfe922ee0a6fba6b1eae4cef96b3ddd0bd0e6a3a84c966cf2a8"
)
_MAP_KEY = bytes.fromhex(
    "5148f4c03d5c379482f5e656dfe3ede4a139f570175a397308ae1213c43b014e"
)
_MAP_FRAME = bytes.fromhex(
    "000102030405060708090a0bde978b4c0bf489db7f49fe2d7443b65923f17ec4ec53367633"
    "fcb37d50a6ac53509eac1971608f2803a46e0c45224480474a4b73650209f23787a7f57c44"
    "75153a88f127977732363fb99424c2bc83c778eac5def57c814214af0155fd95594d36df73"
    "8bba5c17f86dcfb6a37a27e96ba26c14031d02d10a3a731fa9a2b7d8f8241f07ab51dba377"
    "cd24e3c78d0439271208f1"
)
_SEED = bytes.fromhex(
    "8bc6daaea6969e5ad8b4dbab11d077a62c08b90d094aed686908845c1de0fbf7"
)
_GUARD = bytes.fromhex(
    "196ae89c970ab84648efc8630c95216615a5404a9e7c638b9b574331a59daac4"
)
_DIRTY_GUARD = bytes.fromhex(
    "9ff998abcda62f7f473405529d58187c579c8210cd64455ffa869744f71607a1"
)
_DEX0_FRAME = bytes.fromhex(
    "101112131415161718191a1ba9c7420e1659ad1489903bc83dc62c7078e47eee15fb6b1c2050b7ececdf8b32cbd75824883b7098698563d5c6e8e55e4254fecd0557bbe69acfe8419d8bf714f3953433d3e11094062769b5c0e328"
)
_DEX1_FRAME = bytes.fromhex(
    "202122232425262728292a2b08f788d56388474256841b85c393ef0a18f0708b07c0db658083e9557b87f71087"
)

# The fixed Java program the vectors' app ships: two hierarchy walks and two resolutions, in a fixed order. Its
# share — what the stub yields on a runtime that resolves as the packer predicted — is the vector below, and the
# dex frames are sealed under the armed master that share derives.
_JAVA_PROGRAM = java_program.Program(
    steps=(
        java_program.Step(
            kind=java_program.KIND_SUPERS, name="java.util.ArrayList", depth=3
        ),
        java_program.Step(
            kind=java_program.KIND_RESOLVE, name="java.lang.String", depth=0
        ),
        java_program.Step(
            kind=java_program.KIND_RESOLVE, name="co.ostorlab.rasp.RaspStub", depth=0
        ),
        java_program.Step(
            kind=java_program.KIND_SUPERS, name="java.lang.Exception", depth=2
        ),
    )
)
_JAVA_PROGRAM_ENTRY = "assets/rasp/j.bin"
_JAVA_NONCE = bytes.fromhex("303132333435363738393a3b")
_JAVA_FRAME = bytes.fromhex(
    "303132333435363738393a3b6e4d4bbca466657713459031be2d98b30172d467d4f16b5f4b00e02717cc7ea271d3c909c4cff1b0452dc435fc29be838f6a92f61d172f4b94ba1aa469b47b8535e3b2d813bfadd77532e2af989efca6a479380fb39f17044aa4a79f5a59edd71ea5f318d06b69febd60c2dd2ef04a9b43"
)
_JAVA_SHARE = bytes.fromhex(
    "063f7eca0167a1c524f862d0f1fd64d44ee47f502dcf8c97fbb4dc7ef16e631a"
)
_ARMED = bytes.fromhex(
    "27ff73c243df33f85ab17a91a3caede3ceb67c79ee2355f2488870dd0d78535b"
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
    build_id="rasp-build/v1:" + "ab" * 32, checks=("identity",), checks_mask=32
)
# The SHA-256 of the fixture's plaintext `.text`, which the packer writes before the fold's inputs are gathered so
# the region digest binds the sensor guard's expectation into the root.
_TEXT_DIGEST = hashlib.sha256(runtime_library.text_region(_LIBRARY)).digest()

_FIXED_PROGRAM = key_schedule.FoldProgram(
    mask=_MASK,
    chain_a=(
        key_schedule.FoldRecord(kind=key_schedule.KIND_TEXT),
        key_schedule.FoldRecord(kind=key_schedule.KIND_SECTION, param=2),
        key_schedule.FoldRecord(kind=key_schedule.KIND_RANGE, param=64, param32=100),
    ),
    chain_s=(
        key_schedule.FoldRecord(kind=key_schedule.KIND_REGION),
        key_schedule.FoldRecord(kind=key_schedule.KIND_SHARE),
        key_schedule.FoldRecord(kind=key_schedule.KIND_CONSTANT, param=0),
        key_schedule.FoldRecord(kind=key_schedule.KIND_GATES),
        key_schedule.FoldRecord(kind=key_schedule.KIND_ENTRY, param=0),
        key_schedule.FoldRecord(kind=key_schedule.KIND_ENTRY, param=1),
    ),
    constants=(_CONSTANT,),
)
# The app's package name, which the fold program folds in as its package record's input.
_PACKAGE = b"com.example.fold"

# The stub dex's bytes, which the fold program folds in as its stub record's input.
_STUB_DEX = b"stub dex bytes"

# The APK's stored entries, which the fold program folds in as the APK digest.
_APK_ENTRIES: dict[str, tuple[bytes, int, int]] = {}

_FIXED_ENTRIES = {
    key_schedule.SHARE_ENTRY: _SHARE,
    key_schedule.decoy_entry_name(0): _DECOY0,
    key_schedule.decoy_entry_name(1): _DECOY1,
}


def _configured_library() -> bytes:
    """Builds the vectors' library with its config, fold program and text digest, before the keystore."""
    return runtime_library.write_text_digest(
        runtime_library.write_program(
            runtime_library.write_config(_LIBRARY, _CONFIG), bytes.fromhex(_PROGRAM_HEX)
        ),
        _TEXT_DIGEST,
    )


def _fixed_library() -> bytes:
    """Builds the vectors' final library: the fixture with the fixed program, digest and keystore."""
    return runtime_library.write_keystore(
        _configured_library(), key_schedule.fold(_A_STATE, _S_STATE, _ROOT)
    )


def _gather(
    library: bytes,
    entries: collections.abc.Mapping[str, bytes],
    constants: tuple[bytes, ...] = _FIXED_PROGRAM.constants,
) -> collections.abc.Callable[[key_schedule.FoldRecord], bytes]:
    """Returns the gatherer of a program's inputs, over the given library and entries."""

    def resolve(record: key_schedule.FoldRecord) -> bytes:
        if record.kind == key_schedule.KIND_TEXT:
            return hashlib.sha256(runtime_library.text_region(library)).digest()
        if record.kind == key_schedule.KIND_SECTION:
            return hashlib.sha256(
                runtime_library.section_region(
                    library, key_schedule.SECTION_NAMES[record.param]
                )
            ).digest()
        if record.kind == key_schedule.KIND_RANGE:
            return hashlib.sha256(
                library[record.param32 : record.param32 + record.param]
            ).digest()
        if record.kind == key_schedule.KIND_SHARE:
            return entries[key_schedule.SHARE_ENTRY]
        if record.kind == key_schedule.KIND_REGION:
            return hashlib.sha256(runtime_library.config_region(library)).digest()
        if record.kind == key_schedule.KIND_GATES:
            return key_schedule.CLEAN_GATES
        if record.kind == key_schedule.KIND_CONSTANT:
            return constants[record.param]
        if record.kind == key_schedule.KIND_PACKAGE:
            return hashlib.sha256(_PACKAGE).digest()
        if record.kind == key_schedule.KIND_STUB:
            return hashlib.sha256(_STUB_DEX).digest()
        if record.kind == key_schedule.KIND_APK:
            return key_schedule.apk_digest(_APK_ENTRIES)
        return hashlib.sha256(
            entries[key_schedule.decoy_entry_name(record.param)]
        ).digest()

    return resolve


def testEncodeProgram_whenGivenTheFixedProgram_matchesTheVectorProgram() -> None:
    assert key_schedule.encode_program(_FIXED_PROGRAM) == bytes.fromhex(_PROGRAM_HEX)


def testDecodeProgram_whenGivenTheVectorProgram_givesTheFixedProgram() -> None:
    assert key_schedule.decode_program(bytes.fromhex(_PROGRAM_HEX)) == _FIXED_PROGRAM


def testEncodeDecode_whenGivenRandomPrograms_roundTrip() -> None:
    sections = runtime_library.fold_sections(_LIBRARY)
    for seed in range(20):
        generator = random.Random(seed)
        program = key_schedule.build_program(
            generator, sections=sections, library_size=len(_LIBRARY)
        )
        assert (
            key_schedule.decode_program(key_schedule.encode_program(program)) == program
        )


def testDecodeProgram_whenTheBlobIsTheWrongSize_raisesValueError() -> None:
    with pytest.raises(ValueError, match="512 bytes"):
        key_schedule.decode_program(bytes(64))


def testEncodeProgram_whenARecordNamesAMissingConstant_raisesValueError() -> None:
    program = key_schedule.FoldProgram(
        mask=_MASK,
        chain_a=(),
        chain_s=(key_schedule.FoldRecord(kind=key_schedule.KIND_CONSTANT, param=5),),
    )
    with pytest.raises(ValueError, match="does not hold"):
        key_schedule.encode_program(program)


def testRunChain_whenGivenTheFixedInputs_matchesTheVectorStates() -> None:
    gather = _gather(_configured_library(), _FIXED_ENTRIES)

    a_state = key_schedule.run_chain(
        bytes(key_schedule.KEY_SIZE), _FIXED_PROGRAM.chain_a, gather, "a"
    )
    s_state = key_schedule.run_chain(
        bytes(key_schedule.KEY_SIZE), _FIXED_PROGRAM.chain_s, gather, "s"
    )

    assert a_state == _A_STATE
    assert s_state == _S_STATE


def testRunChain_whenTheStepsAreReordered_changesTheState() -> None:
    gather = _gather(_configured_library(), _FIXED_ENTRIES)
    reordered = _FIXED_PROGRAM.chain_s[1:] + _FIXED_PROGRAM.chain_s[:1]

    assert (
        key_schedule.run_chain(bytes(key_schedule.KEY_SIZE), reordered, gather, "s")
        != _S_STATE
    )


def testRootKey_whenFoldedWithTheVectorStatesAndKeystore_givesTheVectorRoot() -> None:
    library = _fixed_library()

    assert (
        key_schedule.root_key(_A_STATE, _S_STATE, runtime_library.keystore(library))
        == _ROOT
    )


def testRecovery_whenGivenTheFixedLibraryAndEntries_givesTheVectorRoot() -> None:
    library = _fixed_library()

    root = schedule_recovery.recover_root(
        library, _FIXED_ENTRIES, key_schedule.CLEAN_GATES, _PACKAGE, _STUB_DEX
    )

    assert root == _ROOT


def testRecovery_whenAnyInputIsTampered_derivesADifferentRoot() -> None:
    library = _fixed_library()

    # A byte inside the fold program.
    program_offset = library.index(bytes.fromhex(_PROGRAM_HEX[:64]))
    tampered_program = bytearray(library)
    tampered_program[program_offset + 100] ^= 1
    assert (
        schedule_recovery.recover_root(
            bytes(tampered_program),
            _FIXED_ENTRIES,
            key_schedule.CLEAN_GATES,
            _PACKAGE,
            _STUB_DEX,
        )
        != _ROOT
    )

    # The library's code.
    elf = lief.ELF.parse(io.BytesIO(library))
    assert elf is not None
    text = elf.get_section(runtime_library.TEXT_SECTION)
    assert text is not None
    tampered_text = bytearray(library)
    tampered_text[text.offset] ^= 1
    assert (
        schedule_recovery.recover_root(
            bytes(tampered_text),
            _FIXED_ENTRIES,
            key_schedule.CLEAN_GATES,
            _PACKAGE,
            _STUB_DEX,
        )
        != _ROOT
    )

    # A decoy entry.
    without_decoy1 = {
        name: data
        for name, data in _FIXED_ENTRIES.items()
        if not name.endswith("r1.bin")
    }
    assert (
        schedule_recovery.recover_root(
            library, without_decoy1, key_schedule.CLEAN_GATES, _PACKAGE, _STUB_DEX
        )
        is None
    )

    # The asset share.
    wrong_share = dict(_FIXED_ENTRIES)
    wrong_share[key_schedule.SHARE_ENTRY] = bytes(key_schedule.KEY_SIZE)
    assert (
        schedule_recovery.recover_root(
            library, wrong_share, key_schedule.CLEAN_GATES, _PACKAGE, _STUB_DEX
        )
        != _ROOT
    )

    # The expected text digest: a patched expectation in the shipped file breaks the fold, so the sensor
    # guard can never be aimed at patched code by editing the file it reads its expectation from.
    patched_expectation = runtime_library.write_text_digest(
        _configured_library(), bytes(key_schedule.KEY_SIZE)
    )
    assert (
        schedule_recovery.recover_root(
            runtime_library.write_keystore(
                patched_expectation, key_schedule.fold(_A_STATE, _S_STATE, _ROOT)
            ),
            _FIXED_ENTRIES,
            key_schedule.CLEAN_GATES,
            _PACKAGE,
            _STUB_DEX,
        )
        != _ROOT
    )

    # The gates: a traced or emulated environment.
    traced = key_schedule.gate_block(
        java_environment=True,
        no_tracer=False,
        installed_under_data=True,
        counter_frequency_plausible=True,
        cpu_identity_plausible=True,
    )
    assert (
        schedule_recovery.recover_root(
            library, _FIXED_ENTRIES, traced, _PACKAGE, _STUB_DEX
        )
        != _ROOT
    )


def testRecovery_whenBuiltWithRandomPrograms_recoversOnEveryLibrary() -> None:
    sections = runtime_library.fold_sections(_LIBRARY)
    for seed in range(10):
        generator = random.Random(seed)
        program = key_schedule.build_program(
            generator,
            sections=sections,
            library_size=len(_LIBRARY),
            keystore_spans=(runtime_library.keystore_span(_LIBRARY),),
            include_apk_digest=True,
        )
        entries = {
            key_schedule.SHARE_ENTRY: _SHARE,
            **{
                key_schedule.decoy_entry_name(index): key_schedule.new_decoy_entry()
                for index in program.decoy_entries
            },
        }
        root = key_schedule.new_root()
        libraries = []
        for _ in range(2):
            with_program = runtime_library.write_program(
                runtime_library.write_config(_LIBRARY, _CONFIG),
                key_schedule.encode_program(program),
            )
            gather = _gather(with_program, entries, program.constants)
            a_state = key_schedule.run_chain(
                bytes(key_schedule.KEY_SIZE), program.chain_a, gather, "a"
            )
            s_state = key_schedule.run_chain(
                bytes(key_schedule.KEY_SIZE), program.chain_s, gather, "s"
            )
            libraries.append(
                runtime_library.write_keystore(
                    with_program, key_schedule.fold(a_state, s_state, root)
                )
            )

        for library in libraries:
            assert (
                schedule_recovery.recover_root(
                    library, entries, key_schedule.CLEAN_GATES, _PACKAGE, _STUB_DEX
                )
                == root
            )
            assert (
                schedule_recovery.recover_root(
                    library,
                    entries,
                    key_schedule.CLEAN_GATES,
                    b"com.example.other",
                    _STUB_DEX,
                )
                != root
            )


def testGateBlock_whenCleanDevice_isTheCleanGates() -> None:
    clean = key_schedule.gate_block(
        java_environment=True,
        no_tracer=True,
        installed_under_data=True,
        counter_frequency_plausible=True,
        cpu_identity_plausible=True,
    )

    assert clean == key_schedule.CLEAN_GATES
    assert clean[0:5] == b"\x01\x01\x01\x01\x01"
    assert clean[5:] == bytes(27)


def testSensorBlock_whenCleanProcess_isTheCleanSensors() -> None:
    clean = key_schedule.sensor_block(
        no_tracer=True,
        text_intact=True,
        no_framework_maps=True,
        no_rwx_regions=True,
        no_framework_threads=True,
        no_foreign_libraries=True,
    )

    assert clean == key_schedule.CLEAN_SENSORS
    assert clean[0:6] == b"\x01\x01\x01\x01\x01\x01"
    assert clean[6:] == bytes(26)


def testSensorBlock_whenAFactFails_flipsItsByte() -> None:
    dirty = key_schedule.sensor_block(
        no_tracer=False,
        text_intact=True,
        no_framework_maps=True,
        no_rwx_regions=True,
        no_framework_threads=True,
        no_foreign_libraries=True,
    )

    assert dirty[0] == 0
    assert dirty != key_schedule.CLEAN_SENSORS


def testFrameKey_whenGivenTheVectorInputs_matchesTheVectorMapKey() -> None:
    assert key_schedule.frame_key(_ROOT, _MAP_NONCE, _MAP_ENTRY) == _MAP_KEY


def testFrameKey_whenEntryDiffers_derivesADifferentKey() -> None:
    assert key_schedule.frame_key(_ROOT, _MAP_NONCE, _DEX0_ENTRY) != _MAP_KEY


def testSeedFrom_whenGivenTheVectorInputs_matchesTheVectorSeed() -> None:
    assert key_schedule.seed_from(_ROOT, _MAP_FRAME) == _SEED


def testSeedFrom_whenTheMapFrameIsTampered_changes() -> None:
    tampered = bytearray(_MAP_FRAME)
    tampered[-1] ^= 1

    assert key_schedule.seed_from(_ROOT, bytes(tampered)) != _SEED


def testGuardedMaster_whenTheProcessIsClean_matchesTheVectorGuard() -> None:
    assert key_schedule.guarded_master(_SEED, key_schedule.CLEAN_SENSORS) == _GUARD


def testGuardedMaster_whenASensorFails_derivesADifferentMaster() -> None:
    dirty = key_schedule.sensor_block(
        no_tracer=False,
        text_intact=True,
        no_framework_maps=True,
        no_rwx_regions=True,
        no_framework_threads=True,
        no_foreign_libraries=True,
    )

    assert key_schedule.guarded_master(_SEED, dirty) == _DIRTY_GUARD


def testArmedMaster_whenGivenTheVectorSeedAndShare_matchesTheVectorArmed() -> None:
    assert key_schedule.armed_master(_SEED, _JAVA_SHARE) == _ARMED


def testArmedMaster_whenTheShareDiffers_derivesADifferentMaster() -> None:
    wrong = bytes(key_schedule.KEY_SIZE)

    assert key_schedule.armed_master(_SEED, wrong) != _ARMED


def testJavaShare_whenTheReferenceRunsTheVectorProgram_matchesTheVectorShare() -> None:
    assert java_program.run_reference(_JAVA_PROGRAM) == _JAVA_SHARE


def testJavaShare_whenAStepIsAnsweredDifferently_changes() -> None:
    # An emulated runtime that resolves one step differently — walking a shorter hierarchy, or echoing a name —
    # yields a different share, and every dex frame's tag fails.
    answered = java_program.Program(
        steps=(
            java_program.Step(
                kind=java_program.KIND_SUPERS, name="java.util.ArrayList", depth=2
            ),
            *_JAVA_PROGRAM.steps[1:],
        )
    )

    assert java_program.run_reference(answered) != _JAVA_SHARE


def testJavaFrame_whenSealedUnderTheVectorKey_matchesTheVectorFrame() -> None:
    key = key_schedule.frame_key(_ROOT, _JAVA_NONCE, _JAVA_PROGRAM_ENTRY)

    assert cipher.encrypt(
        key, _JAVA_NONCE, java_program.encode_program(_JAVA_PROGRAM)
    ) == (_JAVA_FRAME)


def testMapFrame_whenSealedUnderTheVectorKey_matchesTheVectorFrame() -> None:
    assert cipher.encrypt(_MAP_KEY, _MAP_NONCE, _MAP_TEXT) == _MAP_FRAME


def testDexFrames_whenSealedUnderTheVectorArmedGuard_matchTheVectorFrames() -> None:
    guard = key_schedule.guarded_master(
        key_schedule.armed_master(_SEED, _JAVA_SHARE),
        key_schedule.CLEAN_SENSORS,
    )

    assert (
        cipher.encrypt(
            key_schedule.frame_key(guard, _DEX0_NONCE, _DEX0_ENTRY),
            _DEX0_NONCE,
            _DEX0_PLAINTEXT,
        )
        == _DEX0_FRAME
    )
    assert (
        cipher.encrypt(
            key_schedule.frame_key(guard, _DEX1_NONCE, _DEX1_ENTRY),
            _DEX1_NONCE,
            _DEX1_PLAINTEXT,
        )
        == _DEX1_FRAME
    )


def testDexFrame_whenTheShareIsWrong_doesNotDecryptUnderTheArmedKey() -> None:
    guard = key_schedule.guarded_master(
        key_schedule.armed_master(_SEED, bytes(key_schedule.KEY_SIZE)),
        key_schedule.CLEAN_SENSORS,
    )

    key = key_schedule.frame_key(guard, _DEX0_NONCE, _DEX0_ENTRY)
    assert cipher.encrypt(key, _DEX0_NONCE, _DEX0_PLAINTEXT) != _DEX0_FRAME
    with pytest.raises(cipher.CipherError):
        cipher.decrypt(key, _DEX0_FRAME)


def testDexFrame_whenTheGuardIsDirty_doesNotDecryptUnderTheCleanKey() -> None:
    dirty = key_schedule.sensor_block(
        no_tracer=False,
        text_intact=True,
        no_framework_maps=True,
        no_rwx_regions=True,
        no_framework_threads=True,
        no_foreign_libraries=True,
    )
    guard = key_schedule.guarded_master(
        key_schedule.armed_master(_SEED, _JAVA_SHARE), dirty
    )

    key = key_schedule.frame_key(guard, _DEX0_NONCE, _DEX0_ENTRY)
    assert cipher.encrypt(key, _DEX0_NONCE, _DEX0_PLAINTEXT) != _DEX0_FRAME
    with pytest.raises(cipher.CipherError):
        cipher.decrypt(key, _DEX0_FRAME)


def testFold_whenPartsAreTheKeySize_returnsTheirXor() -> None:
    left = bytes(range(32))
    right = bytes(range(32, 64))

    assert key_schedule.fold(left, right) == bytes(
        a ^ b for a, b in zip(left, right, strict=True)
    )


def testFold_whenAPartIsTheWrongSize_raisesValueError() -> None:
    with pytest.raises(ValueError, match="32 bytes"):
        key_schedule.fold(bytes(32), bytes(31))


def testNewRootAndShare_whenCalled_returnFreshValues() -> None:
    assert key_schedule.new_root() != key_schedule.new_root()
    assert key_schedule.new_share() != key_schedule.new_share()
    assert len(key_schedule.new_root()) == key_schedule.KEY_SIZE
    assert len(key_schedule.new_decoy_entry()) == key_schedule.KEY_SIZE


def testDecoyEntryName_whenGivenAnIndex_namesThePrefix() -> None:
    assert key_schedule.decoy_entry_name(3) == "assets/rasp/r3.bin"
