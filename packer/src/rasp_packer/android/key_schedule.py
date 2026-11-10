"""The key schedule that protects the payload: no key ships in the app, and no input stands alone.

The schedule replaces the single clear key the packer once shipped as an APK entry. Nothing in the package is "the key", and no single input, and no proper subset of them, is enough: the payload's root key is the output of two HKDF chains whose inputs are gathered from all over the shipped app, listed by a per-app recipe, the fold program, that the packer writes into the library's ``.rasp_config`` section:

- chain A, per ABI, over the library's own content: the digest of its ``.text``, and the digests of sections and byte ranges the recipe names — so patching the library's code or data breaks the chain silently.
- chain S, shared by every ABI, over the app's shipped artifacts and the environment: the asset share (the stored ``assets/rasp/s.bin`` entry), the digest of the config region (the section's content up to the keystore share), the gate block of the environment the recovery observes, and whatever decoys the recipe lists: random constants inside the program, digests of stored decoy entries (``assets/rasp/r<i>.bin``), or any of the same sources again in another position.

Every input, real or decoy, is just the salt of one HKDF step, and the chains are order-sensitive: the recipe's steps cannot be reordered, and dropping, altering or adding any one of them changes the root. The decoys are indistinguishable from the real inputs to anything short of a full reversal of the runtime, so there is no "the one that matters" to aim at: the fold is a forest, not a line.

``root = A XOR S XOR keystore``. The packer draws the root at random and writes each ABI's keystore share (the trailing bytes of the section) so that that ABI's chains cancel out and every ABI recovers the same root. The runtime mirrors this in ``runtime/android/src/payload/key_schedule.cpp``, and the tests of both sides check the same fixed vectors.

The root itself never decrypts a frame. The class map is sealed under a key derived from the root over its nonce, and every business dex under a key derived from the dex seed — the root bound to the map frame as shipped — and, on every decryption, from the sensor guard: the runtime re-observes the process (``TracerPid``, and the library's ``.text`` in memory against its file) and folds what it sees into the key. A process that holds — a clean device — folds the same block every time; a debugger attached between loads, or a hook patched into the library's code, folds a different one, and the frame's tag fails with no branch anywhere that says why. The startup gates (a JNI environment, no tracer, the library under ``/data``) are one input of chain S: the runtime gathers them live at recovery, so an emulation without a real Android runtime derives a wrong root, and the failure looks like a corrupt frame, not like a detection.
"""

import collections.abc
import hashlib
import os
import random
import struct
import zlib
from dataclasses import dataclass
from dataclasses import field

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from rasp_packer.android import cipher

KEY_SIZE = 32

# The APK entry that holds the asset share, stored: 32 random bytes that are one input of the
# chain, not the key.
SHARE_ENTRY = "assets/rasp/s.bin"

# The APK entries that hold the decoys the fold program can name, stored: random bytes whose
# digests are inputs of the chain. Named "<prefix>r<i>.bin", with i the record's parameter.
DECOY_ENTRY_PREFIX = "assets/rasp/r"

# The fold program: the per-app recipe of the chains, written into the `.rasp_config` section
# between the config's zero padding and the keystore share. Its bytes are masked, and its layout
# is fixed and mirrored by the runtime's interpreter.
PROGRAM_SIZE = 512
MASK_SIZE = 16
MAX_RECORDS = 16
RECORD_SIZE = 8
CONSTANT_SLOTS = 11
COUNT_OFFSET = MASK_SIZE
RECORDS_OFFSET = COUNT_OFFSET + 4
CONSTANTS_OFFSET = RECORDS_OFFSET + MAX_RECORDS * RECORD_SIZE

# The section names a record can name, by index. The packer picks only names the library has.
SECTION_NAMES = (
    ".rodata",
    ".dynstr",
    ".rela.dyn",
    ".eh_frame",
    ".plt",
    ".data.rel.ro",
    ".got",
)

# The record kinds, and the chain each belongs to: A for the library's own content, S for the
# shared artifacts and the environment.
KIND_TEXT = 0
KIND_SECTION = 1
KIND_RANGE = 2
KIND_SHARE = 3
KIND_REGION = 4
KIND_GATES = 5
KIND_CONSTANT = 6
KIND_ENTRY = 7
KIND_PACKAGE = 8
KIND_STUB = 9
KIND_APK = 10

# The prefixes of APK entries the fold's APK digest excludes: the signing step's own entries, the fold's own
# outputs, and the runtime library itself (chain A already covers its bytes).
_APK_DIGEST_EXCLUDED_PREFIXES = ("META-INF/", "assets/rasp/", "assets/business/")
_APK_DIGEST_EXCLUDED_SUFFIX = "librasp.so"

# The gate block of a clean device at recovery: a JNI environment, no tracer, the library under
# /data. The packer folds this in; the runtime folds in what it observes.
CLEAN_GATES = bytes((1, 1, 1, 1, 1)) + bytes(KEY_SIZE - 5)

# The sensor block of a clean process at decryption: no tracer, and the library's code in memory
# matching its file. The packer folds this in; the runtime re-observes it on every decryption.
CLEAN_SENSORS = bytes((1, 1, 1, 1, 1, 1)) + bytes(KEY_SIZE - 6)


def new_root() -> bytes:
    """Returns a fresh random root key, the master of the payload's first stage."""
    return os.urandom(KEY_SIZE)


def new_share() -> bytes:
    """Returns a fresh random share, one input of the fold."""
    return os.urandom(KEY_SIZE)


def new_decoy_entry() -> bytes:
    """Returns the random bytes of one decoy entry, whose digest a chain folds in."""
    return os.urandom(KEY_SIZE)


def decoy_entry_name(index: int) -> str:
    """Returns the APK entry name of the decoy a record's parameter names.

    Args:
        index: The record's parameter, the decoy's index.

    Returns:
        The entry name, ``assets/rasp/r<i>.bin``.
    """
    return f"{DECOY_ENTRY_PREFIX}{index}.bin"


def _digest(data: bytes) -> bytes:
    """Returns the SHA-256 of `data`."""
    return hashlib.sha256(data).digest()


def apk_digest(entries: dict[str, tuple[bytes, int, int]]) -> bytes:
    """Computes the digest over the APK's entries, the way the runtime does at recovery.

    The runtime walks the APK's central directory and feeds each qualifying entry's name, compression
    method, CRC-32, compressed size, uncompressed size, and — for a stored entry — its content into one
    SHA-256, sorted by name. Deflated entries contribute their metadata: an entry added, removed,
    recompressed or whose content changed produces a different CRC-32 or size, and the digest changes.
    Both sides skip `META-INF/` (the signing step adds those), `assets/rasp/` and `assets/business/`
    (the fold's own outputs), and `lib/*/librasp.so` (chain A already covers its bytes).

    Args:
        entries: The APK's entries by name, each a (data, method, compressed_size) triple: the
            uncompressed bytes, the ZIP compression method (0 for stored, 8 for deflated), and the
            size of the compressed bytes in the APK.

    Returns:
        The 32-byte digest.
    """
    digest = hashlib.sha256()
    for name in sorted(entries):
        if name.startswith(_APK_DIGEST_EXCLUDED_PREFIXES) or name.endswith(
            _APK_DIGEST_EXCLUDED_SUFFIX
        ):
            continue
        data, method, _compressed_size = entries[name]
        crc32 = zlib.crc32(data)
        # The compressed size varies by zlib version and build tool, so the digest does not
        # bind it. The CRC-32 catches content changes and the uncompressed size catches
        # truncation; the compression detail adds no security.
        blob = name.encode("utf-8") + struct.pack("<III", method, crc32, len(data))
        if method == 0:
            blob += data
        digest.update(blob)
    return digest.digest()


def _hkdf(secret: bytes, salt: bytes, info: bytes) -> bytes:
    """Returns 32 bytes of HKDF-SHA256, as RFC 5869 defines it."""
    return HKDF(
        algorithm=hashes.SHA256(), length=KEY_SIZE, salt=salt, info=info
    ).derive(secret)


def fold(*parts: bytes) -> bytes:
    """Returns the bytewise XOR of the parts.

    Args:
        parts: The 32-byte values to combine. At least one.

    Returns:
        Their XOR, 32 bytes.

    Raises:
        ValueError: A part is not 32 bytes, or there is no part.
    """
    if len(parts) == 0 or any(len(part) != KEY_SIZE for part in parts):
        raise ValueError(f"every part must be {KEY_SIZE} bytes")
    folded = bytearray(KEY_SIZE)
    for part in parts:
        for index in range(KEY_SIZE):
            folded[index] ^= part[index]
    return bytes(folded)


def gate_block(
    *,
    java_environment: bool,
    no_tracer: bool,
    installed_under_data: bool,
    counter_frequency_plausible: bool,
    cpu_identity_plausible: bool,
) -> bytes:
    """Returns the gate block of an environment, one input of chain S.

    Args:
        java_environment: A JNI environment exists and reports a JNI 1.x version.
        no_tracer: ``TracerPid`` in ``/proc/self/status`` is 0.
        installed_under_data: The library is loaded from a path under ``/data``.
        counter_frequency_plausible: The system counter frequency is in the range a real mobile SoC
            reports, 1–100 MHz. QEMU and unicorn default to 1 GHz or 0.
        cpu_identity_plausible: The CPU identity register is non-zero, as a real CPU always reports.

    Returns:
        The block, 32 bytes: one fact per byte at the start, then zeros.
    """
    block = bytearray(KEY_SIZE)
    block[0] = 1 if java_environment else 0
    block[1] = 1 if no_tracer else 0
    block[2] = 1 if installed_under_data else 0
    block[3] = 1 if counter_frequency_plausible else 0
    block[4] = 1 if cpu_identity_plausible else 0
    return bytes(block)


def sensor_block(
    *,
    no_tracer: bool,
    text_intact: bool,
    no_framework_maps: bool,
    no_rwx_regions: bool,
    no_framework_threads: bool,
    no_foreign_libraries: bool,
) -> bytes:
    """Returns the sensor block of a process, folded into every decryption's key.

    Args:
        no_tracer: ``TracerPid`` in ``/proc/self/status`` is 0.
        text_intact: The library's ``.text`` in memory matches its file.
        no_framework_maps: No mapping in the process's memory map names a known instrumentation framework.
        no_rwx_regions: No mapping is both writable and executable.
        no_framework_threads: No thread carries the name a hooking framework gives its own threads.
        no_foreign_libraries: No shared library is loaded from outside the expected directories.

    Returns:
        The block, 32 bytes: one fact per byte at the start, then zeros.
    """
    block = bytearray(KEY_SIZE)
    block[0] = 1 if no_tracer else 0
    block[1] = 1 if text_intact else 0
    block[2] = 1 if no_framework_maps else 0
    block[3] = 1 if no_rwx_regions else 0
    block[4] = 1 if no_framework_threads else 0
    block[5] = 1 if no_foreign_libraries else 0
    return bytes(block)


@dataclass(frozen=True, slots=True, kw_only=True)
class FoldRecord:
    """One step of a fold chain: a source to gather and fold in as the step's salt.

    Attributes:
        kind: The source's kind, one of the KIND_* constants.
        param: The 16-bit parameter: a section-name index, a constant index, a range length or a
            decoy-entry index, 0 when the kind needs none.
        param32: The 32-bit parameter: a range's offset in the library file, 0 otherwise.
    """

    kind: int
    param: int = 0
    param32: int = 0


@dataclass(frozen=True, slots=True, kw_only=True)
class FoldProgram:
    """The per-app recipe of the fold: which inputs, and in which order, each chain folds in.

    Attributes:
        mask: The 16 bytes the program's bytes are masked with.
        chain_a: The library-side chain's records, in order.
        chain_s: The shared-side chain's records, in order.
        constants: The 32-byte constants a KIND_CONSTANT record can name, by index.
    """

    mask: bytes
    chain_a: tuple[FoldRecord, ...]
    chain_s: tuple[FoldRecord, ...]
    constants: tuple[bytes, ...] = field(default=())

    @property
    def decoy_entries(self) -> tuple[int, ...]:
        """The indices of the decoy entries this program names, unique, in order."""
        return tuple(
            dict.fromkeys(
                record.param for record in self.chain_s if record.kind == KIND_ENTRY
            )
        )


def encode_program(program: FoldProgram) -> bytes:
    """Encodes a fold program into its PROGRAM_SIZE bytes, masked.

    Args:
        program: The program to encode.

    Returns:
        The encoded program: the mask, then the counts, the records and the constants, each byte
        after the mask XORed with the mask at its position.

    Raises:
        ValueError: The program does not fit: too many records or constants.
    """
    records = program.chain_a + program.chain_s
    if len(records) > MAX_RECORDS or len(program.constants) > CONSTANT_SLOTS:
        raise ValueError("the fold program does not fit")
    for record in records:
        if record.kind == KIND_CONSTANT and record.param >= len(program.constants):
            raise ValueError("the fold program names a constant it does not hold")
    blob = bytearray(PROGRAM_SIZE)
    blob[:MASK_SIZE] = program.mask
    struct.pack_into(
        "<HH", blob, COUNT_OFFSET, len(program.chain_a), len(program.chain_s)
    )
    for index, record in enumerate(records):
        offset = RECORDS_OFFSET + index * RECORD_SIZE
        struct.pack_into(
            "<BBHI", blob, offset, record.kind, 0, record.param, record.param32
        )
    for index, constant in enumerate(program.constants):
        offset = CONSTANTS_OFFSET + index * KEY_SIZE
        blob[offset : offset + KEY_SIZE] = constant
    for index in range(MASK_SIZE, PROGRAM_SIZE):
        blob[index] ^= program.mask[index % MASK_SIZE]
    return bytes(blob)


def decode_program(blob: bytes) -> FoldProgram:
    """Decodes a fold program from its bytes, the runtime's parse mirrored for the tests.

    Args:
        blob: The PROGRAM_SIZE encoded program bytes.

    Returns:
        The program, with every constant slot decoded.

    Raises:
        ValueError: The blob is the wrong size or names too many records.
    """
    if len(blob) != PROGRAM_SIZE:
        raise ValueError(f"the fold program must be {PROGRAM_SIZE} bytes")
    unmasked = bytearray(blob)
    mask = bytes(unmasked[:MASK_SIZE])
    for index in range(MASK_SIZE, PROGRAM_SIZE):
        unmasked[index] ^= mask[index % MASK_SIZE]
    count_a, count_s = struct.unpack_from("<HH", unmasked, COUNT_OFFSET)
    if count_a + count_s > MAX_RECORDS:
        raise ValueError("the fold program names too many records")
    records: list[FoldRecord] = []
    for index in range(count_a + count_s):
        offset = RECORDS_OFFSET + index * RECORD_SIZE
        kind, _flags, param, param32 = struct.unpack_from("<BBHI", unmasked, offset)
        records.append(FoldRecord(kind=kind, param=param, param32=param32))
    named = max(
        (record.param + 1 for record in records if record.kind == KIND_CONSTANT),
        default=0,
    )
    constants: list[bytes] = []
    for index in range(named):
        offset = CONSTANTS_OFFSET + index * KEY_SIZE
        constants.append(bytes(unmasked[offset : offset + KEY_SIZE]))
    return FoldProgram(
        mask=mask,
        chain_a=tuple(records[:count_a]),
        chain_s=tuple(records[count_a:]),
        constants=tuple(constants),
    )


def build_program(
    generator: random.Random,
    *,
    sections: tuple[str, ...] = (),
    library_size: int = 0,
    keystore_spans: tuple[tuple[int, int], ...] = (),
    include_apk_digest: bool = False,
) -> FoldProgram:
    """Builds a random fold program: the real inputs, in a random order, among random decoys.

    The program always folds in the real inputs — chain A holds the ``.text`` digest, chain S holds the asset share, the config region digest, the environment gates and the app's package name — and hides them among decoys the recipe invents: random constants, digests of the library's sections, digests of library byte ranges, and digests of decoy APK entries, which the packer then writes as ``assets/rasp/r<i>.bin``. Which decoys, of which kinds, how many, and where in each chain's order, is the generator's choice, so no two apps fold the same way.

    Args:
        generator: The source of randomness, seeded by the caller.
        sections: The library's section names that a section decoy can name.
        library_size: The smallest library's size in bytes, the bound of the range decoys.
        keystore_spans: Where each ABI's keystore share lives in its library file, as
            (offset, length): a range decoy must not cover those bytes, because they are written
            after the fold's inputs are gathered.

    Returns:
        The program.

    Raises:
        ValueError: The random recipe does not fit, which the caller's bounds make impossible.
    """
    name_index = {name: index for index, name in enumerate(SECTION_NAMES)}
    usable = [name_index[name] for name in sections if name in name_index]

    decoy_kinds: list[int] = [KIND_CONSTANT, KIND_ENTRY]
    if usable:
        decoy_kinds.append(KIND_SECTION)
    if library_size > 256:
        decoy_kinds.append(KIND_RANGE)

    chain_a: list[FoldRecord] = [FoldRecord(kind=KIND_TEXT)]
    chain_s: list[FoldRecord] = [
        FoldRecord(kind=KIND_SHARE),
        FoldRecord(kind=KIND_REGION),
        FoldRecord(kind=KIND_GATES),
        FoldRecord(kind=KIND_PACKAGE),
        FoldRecord(kind=KIND_STUB),
    ]
    if include_apk_digest:
        # The APK digest binds the whole APK's stored content: only an APK pack knows the installed entry set.
        chain_s.append(FoldRecord(kind=KIND_APK))
    constants: list[bytes] = []
    entry_indices: list[int] = []
    for _ in range(generator.randint(3, 6)):
        kind = generator.choice(decoy_kinds)
        if kind == KIND_CONSTANT:
            constants.append(os.urandom(KEY_SIZE))
            chain_s.insert(
                generator.randint(0, len(chain_s)),
                FoldRecord(kind=KIND_CONSTANT, param=len(constants) - 1),
            )
        elif kind == KIND_SECTION:
            chain_a.insert(
                generator.randint(0, len(chain_a)),
                FoldRecord(kind=KIND_SECTION, param=generator.choice(usable)),
            )
        elif kind == KIND_RANGE:
            length = generator.randint(32, 256)
            offset = _range_offset(generator, length, library_size, keystore_spans)
            chain_a.insert(
                generator.randint(0, len(chain_a)),
                FoldRecord(kind=KIND_RANGE, param=length, param32=offset),
            )
        else:
            index = len(entry_indices)
            entry_indices.append(index)
            chain_s.insert(
                generator.randint(0, len(chain_s)),
                FoldRecord(kind=KIND_ENTRY, param=index),
            )
    generator.shuffle(chain_a)
    generator.shuffle(chain_s)
    return FoldProgram(
        mask=os.urandom(MASK_SIZE),
        chain_a=tuple(chain_a),
        chain_s=tuple(chain_s),
        constants=tuple(constants),
    )


def _range_offset(
    generator: random.Random,
    length: int,
    library_size: int,
    keystore_spans: tuple[tuple[int, int], ...],
) -> int:
    """Returns a range offset that avoids the keystore spans and stays inside the library.

    Args:
        generator: The source of randomness.
        length: The range's length.
        library_size: The smallest library's size.
        keystore_spans: The (offset, length) spans a range must not cover.

    Returns:
        The range's offset.
    """
    bound = max(0, library_size - length)
    for _attempt in range(64):
        offset = generator.randint(0, bound)
        if all(
            offset + length <= start or offset >= start + span_length
            for start, span_length in keystore_spans
        ):
            return offset
    return 0


def run_chain(
    state: bytes,
    records: tuple[FoldRecord, ...],
    resolve: collections.abc.Callable[[FoldRecord], bytes],
    tag: str,
) -> bytes:
    """Folds `records`' inputs into `state`, one HKDF step per record, in order.

    Each step derives the next state from the current one, with the gathered input as the step's salt and the record's position in the info, so the chain is order-sensitive: reordering, dropping or adding a step changes the result.

    Args:
        state: The state to start from, 32 bytes.
        records: The chain's records, in order.
        resolve: Returns the 32 bytes each record's source holds.
        tag: The chain's tag, "a" or "s", which goes into each step's info.

    Returns:
        The chain's final state, 32 bytes.
    """
    for index, record in enumerate(records):
        state = _hkdf(
            state, salt=resolve(record), info=f"rasp.v2.fold.{tag}/{index}".encode()
        )
    return state


def root_key(a_state: bytes, s_state: bytes, keystore: bytes) -> bytes:
    """Returns the root key recovered from the two chains and the keystore share.

    Args:
        a_state: Chain A's final state, over the library's own content.
        s_state: Chain S's final state, over the shared artifacts and the environment.
        keystore: The keystore share read from the library's section, which the packer wrote to
            cancel its ABI's chains.

    Returns:
        The root key.

    Raises:
        ValueError: An argument is not 32 bytes.
    """
    return fold(a_state, s_state, keystore)


def frame_key(master: bytes, nonce: bytes, entry: str) -> bytes:
    """Returns the key of one frame: HKDF-SHA256 of its stage's master.

    Args:
        master: The stage's master key: the root for the class map, the guarded master for a
            business dex.
        nonce: The frame's nonce, 12 bytes.
        entry: The frame's full APK entry name, such as ``assets/rasp/map.bin``.

    Returns:
        The frame key, 32 bytes.

    Raises:
        ValueError: The master is not 32 bytes, or the nonce is not 12 bytes.
    """
    if len(master) != KEY_SIZE:
        raise ValueError(f"the master must be {KEY_SIZE} bytes")
    if len(nonce) != cipher.NONCE_SIZE:
        raise ValueError(f"the nonce must be {cipher.NONCE_SIZE} bytes")
    return _hkdf(master, salt=nonce, info=f"rasp.v2.frame/{entry}".encode())


def seed_from(root: bytes, map_frame: bytes) -> bytes:
    """Returns the dex seed: the root bound to the map frame as shipped.

    Args:
        root: The root key.
        map_frame: The encrypted class map, the whole frame as shipped.

    Returns:
        The seed, 32 bytes.

    Raises:
        ValueError: The root is not 32 bytes.
    """
    if len(root) != KEY_SIZE:
        raise ValueError(f"the root must be {KEY_SIZE} bytes")
    return _hkdf(root, salt=_digest(map_frame), info=b"rasp.v2.seed")


def armed_master(seed: bytes, j_share: bytes) -> bytes:
    """Returns the armed master: the seed under the Java share the stub's program produced.

    The share comes from a per-app program of resolution steps the stub executes through the real Android runtime
    (android/java_program.py), so the dex master needs the native fold *and* a runtime that resolves the program's
    classes the way the packer predicted. An emulated runtime that answers one step differently derives a different
    master, and every frame's tag fails, with no branch anywhere that says why.

    Args:
        seed: The dex seed.
        j_share: The Java share, 32 bytes.

    Returns:
        The armed master, 32 bytes.

    Raises:
        ValueError: An argument is not 32 bytes.
    """
    if len(seed) != KEY_SIZE or len(j_share) != KEY_SIZE:
        raise ValueError(f"the seed and share must be {KEY_SIZE} bytes")
    return _hkdf(seed, salt=j_share, info=b"rasp.v2.armed")


def guarded_master(seed: bytes, sensors: bytes) -> bytes:
    """Returns the master of the next decryption: the seed under the observed sensor guard.

    The runtime re-observes the process on every decryption and derives through what it sees, so a debugger attached between loads, or a hook patched into the library's code, changes the master and the frame's tag fails, with no branch anywhere that says why.

    Args:
        seed: The armed master the Java share produced, or the dex seed for the vectors before the Java arm.
        sensors: The sensor block observed now, 32 bytes.

    Returns:
        The guarded master, 32 bytes.

    Raises:
        ValueError: An argument is not 32 bytes.
    """
    if len(seed) != KEY_SIZE or len(sensors) != KEY_SIZE:
        raise ValueError(f"the seed and sensors must be {KEY_SIZE} bytes")
    return _hkdf(seed, salt=sensors, info=b"rasp.v2.guard")
