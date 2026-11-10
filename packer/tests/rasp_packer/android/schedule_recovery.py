"""The reference recovery of the key schedule's root key, the runtime's recovery mirrored in the tests.

The tests use it the way an attacker would, and the way the runtime does: it reads a packed library's fold program,
gathers the inputs the program names from the library and the APK's entries, runs the chains, and folds the keystore
share in. The native side (runtime/android/src/payload/key_schedule.cpp) does the same in C++, and both check the same
fixed vectors, so a disagreement between the two shows up as a test failure on one side or the other.
"""

import collections.abc
import hashlib

from rasp_packer.android import key_schedule
from rasp_packer.android import runtime_library


def recover_root(
    library: bytes,
    entries: collections.abc.Mapping[str, bytes],
    gates: bytes,
    package: bytes,
    stub_dex: bytes,
    apk_entries: dict[str, tuple[bytes, int, int]] | None = None,
    module_dexes: dict[str, bytes] | None = None,
) -> bytes | None:
    """Recovers the root key of a packed library from the library and its APK's stored entries.

    Args:
        library: The content of a packed `librasp.so`, with its config, fold program and keystore
            share.
        entries: The APK's stored entries by name, which hold the asset share and the decoy entries
            the fold program names.
        gates: The gate block of the environment the recovery folds in, the clean device's
            key_schedule.CLEAN_GATES to mirror a clean run.
        package: The app's package name, which the fold program folds in as the package record's
            input, the way the runtime reads it from its APK's install path.
        stub_dex: The stub dex's bytes, which the fold program folds in as the stub record's input,
            the way the runtime reads the highest-numbered `classesN.dex` entry.
        module_dexes: The base module's class dexes by entry name, for an AAB pack's dex record.

    Returns:
        The root key. Nothing when the library's fold program or any input it names cannot be read,
        which the runtime serves as no business class, exactly as for a corrupt APK.
    """
    try:
        return _recover(
            library, entries, gates, package, stub_dex, apk_entries, module_dexes
        )
    except KeyError, IndexError, ValueError:
        return None


def _recover(
    library: bytes,
    entries: collections.abc.Mapping[str, bytes],
    gates: bytes,
    package: bytes,
    stub_dex: bytes,
    apk_entries: dict[str, tuple[bytes, int, int]] | None = None,
    module_dexes: dict[str, bytes] | None = None,
) -> bytes:
    """Recovers the root key, raising on any input that cannot be gathered."""
    program = key_schedule.decode_program(runtime_library.program(library))
    keystore = runtime_library.keystore(library)
    # The APK digest skips the runtime's own libraries, the way the runtime skips them: it derives
    # their filename from its own load path. The library this recovery reads is one of them, so the
    # entries that hold its content give the filename, which covers every ABI the pack shipped under
    # the same per-app name.
    library_filenames = frozenset(
        name.rpartition("/")[2]
        for name, (data, _method, _size) in (apk_entries or {}).items()
        if data == library
    )

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
            end = record.param32 + record.param
            if end > len(library):
                raise ValueError("the fold program names a range outside the library")
            return hashlib.sha256(library[record.param32 : end]).digest()
        if record.kind == key_schedule.KIND_SHARE:
            share = entries[key_schedule.SHARE_ENTRY]
            if len(share) != key_schedule.KEY_SIZE:
                raise ValueError("the asset share has the wrong size")
            return share
        if record.kind == key_schedule.KIND_REGION:
            return hashlib.sha256(runtime_library.config_region(library)).digest()
        if record.kind == key_schedule.KIND_GATES:
            return gates
        if record.kind == key_schedule.KIND_CONSTANT:
            return program.constants[record.param]
        if record.kind == key_schedule.KIND_PACKAGE:
            return hashlib.sha256(package).digest()
        if record.kind == key_schedule.KIND_STUB:
            return hashlib.sha256(stub_dex).digest()
        if record.kind == key_schedule.KIND_APK:
            return key_schedule.apk_digest(apk_entries or {}, library_filenames)
        if record.kind == key_schedule.KIND_SPLITS:
            # The pack ships alone; the fixtures model a clean install, whose set beside the base is empty.
            return key_schedule.splits_digest()
        if record.kind == key_schedule.KIND_DEXES:
            # The fixtures model the store's install: the base module's dexes as the packer wrote them.
            return key_schedule.dex_digest(module_dexes or {})
        if record.kind == key_schedule.KIND_DEXLESS_SPLITS:
            # The fixtures model a clean store install: no APK beside the base holds a class dex.
            return key_schedule.dexless_splits()
        return hashlib.sha256(
            entries[key_schedule.decoy_entry_name(record.param)]
        ).digest()

    a_state = key_schedule.run_chain(
        bytes(key_schedule.KEY_SIZE), program.chain_a, resolve, "a"
    )
    s_state = key_schedule.run_chain(
        bytes(key_schedule.KEY_SIZE), program.chain_s, resolve, "s"
    )
    return key_schedule.root_key(a_state, s_state, keystore)
