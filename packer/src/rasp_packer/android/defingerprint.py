"""Removes the packer's visible fingerprints from the shipped app.

The stub dex names its classes ``co.ostorlab.rasp.*``, loads a library named ``rasp``, and may carry a
source filename in its debug info. An attacker reads those strings with ``aapt`` and ``strings`` and
identifies the product and the vendor, whose source is public. This module patches the prebuilt stub
dex with per-app random names of the same length, so no offset in the dex moves and no table needs
rebuilt:

- the library name: ``rasp`` (4 bytes) → a random 4-character name
- the stub class: ``Lco/ostorlab/rasp/RaspStub;`` (27 bytes) → a random same-length descriptor
- the arm class: ``Lco/ostorlab/rasp/JArm;`` (23 bytes) → a random same-length descriptor
- the source filename: ``RaspStub.java`` (13 bytes) → a random same-length name, when the build kept it

The dex's string table is sorted, and the runtime verifier rejects a dex whose strings fall out of
order, so every replacement is drawn to keep its string between the neighbours the original sits
between: each name is sampled from the range its position allows, and the patched table is verified
sorted before the patch returns. After the patch, the dex checksum (Adler-32) and signature (SHA-1)
are recomputed.

The packer renames the library entry in the app to match the new library name, points the manifest's
``appComponentFactory`` at the new stub class, and writes the new class into the runtime's config,
which the runtime reads to bind its native entry points on the class the manifest names — so the
renamed class binds and decrypts.
"""

import dataclasses
import hashlib
import random
import struct
import zlib

from rasp_packer.android import resources as resources_module

# The strings this module patches, as they appear in the prebuilt stub dex.
_LIBRARY_STRING = b"\x04rasp\x00"
_STUB_CLASS = b"Lco/ostorlab/rasp/RaspStub;"
_ARM_CLASS = b"Lco/ostorlab/rasp/JArm;"
_SOURCE_FILE = b"RaspStub.java"

# No vendor or product string survives the patch.
_BANNED_STRINGS = (b"ostorlab", b"rasp", b"Rasp")

# The dex header's string table: the counts live at offset 56, the offsets at 60.
_DEX_STRING_IDS_SIZE = 56
_DEX_STRING_IDS_OFFSET = 60

# The tries a bounded sampler may draw before it gives up.
_SAMPLE_TRIES = 256


@dataclasses.dataclass(frozen=True, slots=True, kw_only=True)
class AppNames:
    """The per-app random names that replace the packer's visible fingerprints.

    Attributes:
        library_name: The 4-character replacement for ``rasp``, for ``System.loadLibrary``.
        library_filename: The library's filename in the app, ``lib<name>.so``.
        stub_class: The stub class's descriptor name without ``L`` and ``;``, with ``/`` separators.
        stub_class_dotted: The stub class's name with ``.`` separators, for the manifest and the config.
        arm_class: The arm class's descriptor name, same form.
        source_file: The replacement for the source filename ``RaspStub.java`` in the dex's debug info.
    """

    library_name: str
    library_filename: str
    stub_class: str
    stub_class_dotted: str
    arm_class: str
    source_file: str


@dataclasses.dataclass(frozen=True, slots=True)
class _Range:
    """The strings one patched string must stay between to keep the dex's table sorted.

    Attributes:
        lower: The string at the previous index, or None at the table's start.
        upper: The string at the next index, or None at the table's end.
    """

    lower: str | None
    upper: str | None


def _read_uleb128(data: bytes, offset: int) -> tuple[int, int]:
    """Reads one ULEB128 value and the offset past it.

    Args:
        data: The bytes to read from.
        offset: Where the value starts.

    Returns:
        The value and the offset past it.
    """
    result = 0
    shift = 0
    while True:
        byte = data[offset]
        offset += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, offset
        shift += 7


def dex_strings(dex: bytes) -> list[str]:
    """Reads the strings of a dex's string table, in table order.

    Args:
        dex: The dex's bytes.

    Returns:
        The strings, in the order the table holds them, which the dex format requires sorted.

    Raises:
        ValueError: The dex is too short to hold the header it declares.
    """
    if len(dex) < 64:
        raise ValueError(
            f"the stub dex holds {len(dex)} bytes, too few for a dex header"
        )
    size, offsets = struct.unpack_from("<II", dex, _DEX_STRING_IDS_SIZE)
    strings: list[str] = []
    for index in range(size):
        (data_offset,) = struct.unpack_from("<I", dex, offsets + index * 4)
        _length, start = _read_uleb128(dex, data_offset)
        end = dex.index(b"\x00", start)
        strings.append(dex[start:end].decode("utf-8", errors="replace"))
    return strings


def _string_ranges(dex: bytes) -> dict[str, _Range]:
    """Finds the sorted-table range of each string this module patches.

    Args:
        dex: The prebuilt stub dex.

    Returns:
        The range of each patchable string that is present, keyed by the string itself. A string
        absent from the dex (a stub built without debug information carries no source filename)
        has no range and no entry.
    """
    strings = dex_strings(dex)
    ranges: dict[str, _Range] = {}
    for target in (
        _STUB_CLASS.decode("utf-8"),
        _ARM_CLASS.decode("utf-8"),
        _SOURCE_FILE.decode("utf-8"),
        "rasp",
    ):
        index = strings.index(target) if target in strings else -1
        if index >= 0:
            ranges[target] = _Range(
                lower=strings[index - 1] if index > 0 else None,
                upper=strings[index + 1] if index + 1 < len(strings) else None,
            )
    return ranges


def _sample_between(
    generator: random.Random,
    length: int,
    alphabet: str,
    lower: str | None,
    upper: str | None,
) -> str:
    """Draws a random string of exactly ``length`` characters, strictly inside its range.

    A dex's string table is sorted, so a patched string must keep its position between the strings
    it sits between. The sampler builds the string one character at a time, keeping the choices
    open: while the string built so far is still a prefix of a bound, the next character must not
    cross it, and once the string has diverged inside the range the rest is free. Both bounds are
    optional, which leaves the matching positions free.

    Args:
        generator: The source of randomness.
        length: The string's length, in characters.
        alphabet: The characters the string may hold.
        lower: The string it must sort after, or None.
        upper: The string it must sort before, or None.

    Returns:
        The string, of exactly ``length`` characters, strictly between the bounds.

    Raises:
        ValueError: No string of the length fits the range.
    """
    if lower is None and upper is None:
        return "".join(generator.choice(alphabet) for _ in range(length))
    for _ in range(_SAMPLE_TRIES):
        # The bounds drop out once the string built so far has passed them; the positions they
        # leave behind are free. An upper bound the string grows past while matching it, or a
        # position no allowed character fits, ends the try.
        low: str | None = lower
        high: str | None = upper
        characters: list[str] = []
        for position in range(length):
            if low is not None and position >= len(low):
                low = None
            if high is not None and position >= len(high):
                characters = []
                break
            allowed = [
                character
                for character in alphabet
                if (low is None or character >= low[position])
                and (high is None or character <= high[position])
            ]
            if not allowed:
                characters = []
                break
            character = generator.choice(allowed)
            if low is not None and character > low[position]:
                low = None
            if high is not None and character < high[position]:
                high = None
            characters.append(character)
        if not characters:
            continue
        candidate = "".join(characters)
        if (lower is None or candidate > lower) and (
            upper is None or candidate < upper
        ):
            return candidate
    raise ValueError(
        "no string of the requested length fits between the neighbouring strings"
    )


def generate_library_name(
    generator: random.Random, lower: str | None = None, upper: str | None = None
) -> str:
    """Generates a 4-character name for the native library, the same length as ``rasp``.

    The name keeps its string's position in the dex's sorted table: it is drawn strictly between
    the strings the original sits between.

    Args:
        generator: The source of randomness.
        lower: The string the name must sort after, or None.
        upper: The string the name must sort before, or None.

    Returns:
        The name, 4 lowercase letters and digits, not containing ``rasp``.
    """
    while True:
        name = _sample_between(
            generator, 4, "abcdefghijklmnopqrstuvwxyz0123456789", lower, upper
        )
        if "rasp" not in name:
            return name


def generate_source_file_name(
    generator: random.Random, lower: str | None = None, upper: str | None = None
) -> str:
    """Generates the replacement for the source filename in the dex's debug info.

    Args:
        generator: The source of randomness.
        lower: The string the name must sort after, or None.
        upper: The string the name must sort before, or None.

    Returns:
        The name, as many bytes as ``RaspStub.java``, keeping its position in the table.
    """
    return _sample_between(
        generator, len(_SOURCE_FILE), "abcdefghijklmnopqrstuvwxyz", lower, upper
    )


def generate_names(
    generator: random.Random,
    taken_filenames: frozenset[str] = frozenset(),
    dex: bytes | None = None,
) -> AppNames:
    """Generates the per-app random names that replace the packer's visible fingerprints.

    Args:
        generator: The source of randomness, seeded by the caller for reproducible builds.
        taken_filenames: The filenames already in use under the app's library directories; the
            generated library name stays clear of them.
        dex: The prebuilt stub dex, whose sorted string table bounds each name to its position.
            None draws the names without the table's bounds.

    Returns:
        The names.

    Raises:
        ValueError: The dex's strings leave no room for a name in a position.
    """
    ranges = _string_ranges(dex) if dex is not None else {}
    stub_range = ranges.get(_STUB_CLASS.decode("utf-8"), _Range(lower=None, upper=None))
    arm_range = ranges.get(_ARM_CLASS.decode("utf-8"), _Range(lower=None, upper=None))
    library_range = ranges.get("rasp", _Range(lower=None, upper=None))
    source_range = ranges.get(
        _SOURCE_FILE.decode("utf-8"), _Range(lower=None, upper=None)
    )
    while True:
        library_name = generate_library_name(
            generator, library_range.lower, library_range.upper
        )
        if f"lib{library_name}.so" not in taken_filenames:
            break
    stub_class, arm_class = _class_pair(generator, stub_range, arm_range)
    return AppNames(
        library_name=library_name,
        library_filename=f"lib{library_name}.so",
        stub_class=stub_class,
        stub_class_dotted=stub_class.replace("/", "."),
        arm_class=arm_class,
        source_file=generate_source_file_name(
            generator, source_range.lower, source_range.upper
        ),
    )


def _class_pair(
    generator: random.Random, stub_range: _Range, arm_range: _Range
) -> tuple[str, str]:
    """Draws the stub and arm class names, in one package, keeping the table's order.

    The stub calls the arm class's package-private static method, so the two renamed classes must
    land in one package for the call to resolve; the arm's class part then sorts before the stub's,
    which also keeps the pair's order in the dex's sorted table, where the two are neighbours: the
    arm before the stub, both inside the unpatched strings around the pair. When they are not
    neighbours, each keeps its own range, and the shared package holds.

    Args:
        generator: The source of randomness.
        stub_range: The stub descriptor's range in the prebuilt table.
        arm_range: The arm descriptor's range in the prebuilt table.

    Returns:
        The stub and the arm class names.

    Raises:
        ValueError: The table leaves no room for the pair.
    """
    alphabet = "abcdefghijklmnopqrstuvwxyz"
    upper_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    adjacent = arm_range.upper == _STUB_CLASS.decode(
        "utf-8"
    ) and stub_range.lower == _ARM_CLASS.decode("utf-8")
    low = arm_range.lower if adjacent else None
    high = stub_range.upper if adjacent else None
    # The position's range constrains the package's first character: the descriptor's first
    # character is the fixed ``L``, the second is the package's first.
    firsts = [
        character
        for character in alphabet
        if (low is None or character >= low[1])
        and (high is None or character <= high[1])
    ]
    for _ in range(_SAMPLE_TRIES):
        for package_parts in (1, 2, 3):
            first = generator.choice(firsts if firsts else alphabet)
            package = first + "".join(
                generator.choice(alphabet) for _ in range(2 * package_parts - 1)
            )
            package = "/".join(package[i : i + 2] for i in range(0, len(package), 2))
            arm_length = len(_ARM_CLASS) - 2 - len(package) - 1
            stub_length = len(_STUB_CLASS) - 2 - len(package) - 1
            if arm_length < 3 or stub_length < 3:
                continue
            if adjacent:
                # The arm's class part sorts first, and leaves the stub a later first character.
                arm_first = generator.choice(upper_alphabet[:-1])
                stub_first = generator.choice(
                    upper_alphabet[upper_alphabet.index(arm_first) + 1 :]
                )
            else:
                arm_first = generator.choice(upper_alphabet)
                stub_first = generator.choice(upper_alphabet)
            arm = (
                f"{package}/"
                + arm_first
                + "".join(generator.choice(alphabet) for _ in range(arm_length - 1))
            )
            stub = (
                f"{package}/"
                + stub_first
                + "".join(generator.choice(alphabet) for _ in range(stub_length - 1))
            )
            if len(arm.encode("utf-8")) != len(_ARM_CLASS) - 2:
                continue
            if len(stub.encode("utf-8")) != len(_STUB_CLASS) - 2:
                continue
            arm_descriptor = f"L{arm};"
            stub_descriptor = f"L{stub};"
            if adjacent:
                if low is not None and not arm_descriptor > low:
                    continue
                if high is not None and not stub_descriptor < high:
                    continue
            elif not _inside(arm_descriptor, arm_range) or not _inside(
                stub_descriptor, stub_range
            ):
                continue
            if any(
                banned.decode("utf-8") in name
                for banned in _BANNED_STRINGS
                for name in (package, arm, stub)
            ):
                continue
            return stub, arm
    raise ValueError("the table leaves no room for the stub and arm class names")


def _inside(candidate: str, bounds: _Range) -> bool:
    """Whether a descriptor sits strictly inside its range.

    Args:
        candidate: The descriptor.
        bounds: The strings it must sort between, either of which may be absent.

    Returns:
        Whether the candidate is inside.
    """
    return (bounds.lower is None or candidate > bounds.lower) and (
        bounds.upper is None or candidate < bounds.upper
    )


def fingerprint_free_artifacts(
    artifacts: resources_module.Artifacts,
    generator: random.Random,
    taken_filenames: frozenset[str] = frozenset(),
) -> tuple[resources_module.Artifacts, AppNames]:
    """Patches the prebuilt stub dex with per-app random names.

    Args:
        artifacts: The prebuilt resources (stub dex and libraries).
        generator: The source of randomness, seeded by the caller.
        taken_filenames: The filenames already in use under the app's library directories.

    Returns:
        The patched artifacts and the per-app names.
    """
    names = generate_names(generator, taken_filenames, artifacts.stub_dex)
    patched_dex = patch_stub_dex(
        artifacts.stub_dex,
        library_name=names.library_name,
        stub_class=names.stub_class,
        arm_class=names.arm_class,
        source_file=names.source_file,
    )
    patched = resources_module.Artifacts(
        stub_dex=patched_dex, libraries=artifacts.libraries
    )
    return patched, names


def _fix_dex_header(dex: bytearray) -> None:
    """Recomputes the dex's checksum (Adler-32) and signature (SHA-1) after a byte-level patch.

    The checksum is the Adler-32 of everything after the checksum field itself; the signature is the
    SHA-1 of everything after the signature field.

    Args:
        dex: The dex bytes, modified in place.
    """
    signature = hashlib.sha1(bytes(dex[32:])).digest()
    dex[12:32] = signature
    checksum = zlib.adler32(bytes(dex[12:])) & 0xFFFFFFFF
    struct.pack_into("<I", dex, 8, checksum)


def patch_stub_dex(
    dex: bytes,
    library_name: str,
    stub_class: str,
    arm_class: str,
    source_file: str,
) -> bytes:
    """Patches the prebuilt stub dex with per-app random names.

    Each replacement is the same length as the original, so no dex offset moves and no table needs
    rebuilding. Only the strings change; the dex's type_id table, method references and class
    definitions all point through the same string indices and follow automatically. The source
    filename is optional: a stub built without debug information carries none, and the patch skips
    it then. The patched string table is verified still sorted, the dex format's requirement, so a
    name drawn outside its range fails the pack instead of shipping a dex the runtime rejects.

    Args:
        dex: The prebuilt stub dex.
        library_name: The 4-character replacement for ``rasp`` (the loadLibrary argument).
        stub_class: The replacement for ``co/ostorlab/rasp/RaspStub``, in ``a/b/ClassName`` form,
            without ``L`` and ``;``, the same byte length.
        arm_class: The replacement for ``co/ostorlab/rasp/JArm``, same form and length.
        source_file: The replacement for ``RaspStub.java``, the same byte length.

    Returns:
        The patched dex.

    Raises:
        ValueError: A replacement has the wrong length, a required original string is absent from
            the dex, a vendor string remains after the patch, or the patched string table is not
            sorted.
    """
    if len(library_name.encode("utf-8")) != 4:
        raise ValueError(
            f"the library name must be 4 bytes, not {len(library_name.encode('utf-8'))}"
        )
    for name, length in [
        (stub_class, len(_STUB_CLASS) - 2),
        (arm_class, len(_ARM_CLASS) - 2),
        (source_file, len(_SOURCE_FILE)),
    ]:
        if len(name.encode("utf-8")) != length:
            raise ValueError(
                f"the replacement must be {length} bytes, not {len(name.encode('utf-8'))}"
            )

    patched = bytearray(dex)
    replacements = [
        (_STUB_CLASS, f"L{stub_class};".encode()),
        (_ARM_CLASS, f"L{arm_class};".encode()),
        (_SOURCE_FILE, source_file.encode("utf-8")),
        (_LIBRARY_STRING, b"\x04" + library_name.encode("utf-8") + b"\x00"),
    ]
    for old, new in replacements:
        count = patched.count(old)
        if count == 0:
            if old == _SOURCE_FILE:
                # A stub built without debug information carries no source filename.
                continue
            raise ValueError(f"the string {old!r} is not in the stub dex")
        if len(new) != len(old):
            raise ValueError(
                f"the replacement for {old!r} has length {len(new)}, not {len(old)}"
            )
        patched = bytearray(bytes(patched).replace(old, new))

    # No vendor or product string remains.
    for banned in _BANNED_STRINGS:
        if banned in patched:
            raise ValueError(f"the string {banned!r} remains in the patched dex")

    # The dex format requires the string table sorted; a name drawn outside its range breaks it.
    strings = dex_strings(bytes(patched))
    if strings != sorted(strings):
        raise ValueError(
            "the patched string table is not sorted; a name left its range"
        )

    _fix_dex_header(patched)
    return bytes(patched)
