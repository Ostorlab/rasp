"""The Java arm of the key schedule: a per-app program the stub executes through the real Android runtime.

The fold's root recovers natively, from the shipped library and APK, so an emulator that executes the native side
alone recovers it too. This module adds a stage the native side cannot complete by itself: the packer invents a
per-app program of steps — which classes to resolve through the app's base class loader, whose hierarchies to walk —
and the stub executes it on the device, through ART, to produce the Java share. The dex frames are sealed under the
seed *and* that share, so decrypting them needs the native fold *and* a runtime that resolves the program's classes
the way the packer predicted. A wrong share derives a wrong master and every frame's tag fails, with nothing that
says why — the same silent failure the fold gives.

Every step names a class whose resolution the packer can predict without parsing dex: the core classes in CORE_STEPS,
whose hierarchies the platform contract fixes, and the stub's own class. App-class structure steps — fields, methods,
per-app hierarchies — need a dex reader on the packer side and are the next depth of this arm.
"""

import random

from rasp_packer.android import key_schedule

# The APK entry the encrypted program ships as.
PROGRAM_ENTRY = "assets/rasp/j.bin"

# The size of a share, a step's kind and depth fields.
KEY_SIZE = key_schedule.KEY_SIZE

# A step resolves its class through the base class loader.
KIND_RESOLVE = 1
# A step walks its class's superclass chain a number of hops, as ART reports it.
KIND_SUPERS = 2

# The classes a program can name, each with the ordered names of its superclass chain as the platform defines it.
# The runtime resolves and walks them through real ART; the packer predicts the walk from this table. Only
# java.* classes whose hierarchies the Android API contract (31 and later) fixes belong here.
CORE_STEPS: dict[str, tuple[str, ...]] = {
    "java.lang.Object": (),
    "java.lang.String": ("java.lang.Object",),
    "java.lang.Exception": ("java.lang.Throwable", "java.lang.Object"),
    "java.lang.StringBuilder": ("java.lang.AbstractStringBuilder", "java.lang.Object"),
    "java.util.ArrayList": (
        "java.util.AbstractList",
        "java.util.AbstractCollection",
        "java.lang.Object",
    ),
    "java.util.LinkedList": (
        "java.util.AbstractSequentialList",
        "java.util.AbstractList",
        "java.util.AbstractCollection",
        "java.lang.Object",
    ),
    "java.util.HashMap": ("java.util.AbstractMap", "java.lang.Object"),
    "java.util.TreeMap": ("java.util.AbstractMap", "java.lang.Object"),
    "java.util.HashSet": (
        "java.util.AbstractSet",
        "java.util.AbstractCollection",
        "java.lang.Object",
    ),
    "java.util.ArrayDeque": ("java.util.AbstractCollection", "java.lang.Object"),
    "java.util.concurrent.ConcurrentHashMap": (
        "java.util.AbstractMap",
        "java.lang.Object",
    ),
}

# The stub's own class, which the base class loader defines from the stub dex.
STUB_CLASS = "co.ostorlab.rasp.RaspStub"

# The bound on one program: at most this many steps.
MAX_STEPS = 16


class ProgramError(Exception):
    """A Java program cannot be built, encoded, decoded, or run."""


class Step:
    """One step of a Java program: resolve a class, and how many superclass hops to walk over it."""

    __slots__ = ("depth", "kind", "name")

    def __init__(self, kind: int, name: str, depth: int) -> None:
        self.kind = kind
        self.name = name
        self.depth = depth

    def __eq__(self, other: object) -> bool:
        return (
            isinstance(other, Step)
            and self.kind == other.kind
            and self.name == other.name
            and self.depth == other.depth
        )

    def __repr__(self) -> str:
        return f"Step(kind={self.kind}, name={self.name!r}, depth={self.depth})"


class Program:
    """A per-app program of resolution steps, in chain order."""

    __slots__ = ("steps",)

    def __init__(self, steps: tuple[Step, ...]) -> None:
        self.steps = steps

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Program) and self.steps == other.steps

    def __repr__(self) -> str:
        return f"Program(steps={self.steps!r})"


def build_program(generator: random.Random, stub_class: str = STUB_CLASS) -> Program:
    """Invents a fresh program: which classes to resolve, and how deep to walk, in which order.

    Args:
        generator: The source of randomness, seeded by the caller.
        stub_class: The name of the app's stub class, which the program may resolve the way the runtime
            resolves it through the base class loader. The packer predicts every step's observation from
            the name it passes here, so a pack that renamed the stub must pass the renamed name.

    Returns:
        The program.
    """
    names = [*sorted(CORE_STEPS), stub_class]
    steps = [
        Step(
            kind=KIND_SUPERS if generator.randrange(2) == 0 else KIND_RESOLVE,
            name=generator.choice(names),
            depth=0,
        )
        for _ in range(generator.randint(4, 7))
    ]
    for step in steps:
        if step.kind == KIND_SUPERS:
            chain = CORE_STEPS.get(step.name, ())
            step.depth = generator.randint(1, len(chain)) if chain else 0
            if not chain:
                step.kind = KIND_RESOLVE
    return Program(steps=tuple(steps))


def encode_program(program: Program) -> bytes:
    """Encodes a program: a step count, then each step's kind, depth, and class name.

    Args:
        program: The program to encode.

    Returns:
        The encoded program.

    Raises:
        ProgramError: A step names an empty class or the program holds too many steps.
    """
    if not 1 <= len(program.steps) <= MAX_STEPS:
        raise ProgramError(
            f"a program holds 1 to {MAX_STEPS} steps, not {len(program.steps)}"
        )
    out = bytearray(len(program.steps).to_bytes(2, "little"))
    for step in program.steps:
        name = step.name.encode("utf-8")
        if not 1 <= len(name) <= 0xFFFF:
            raise ProgramError(
                f"a step's class name must be 1 to 65535 bytes, not {len(name)}"
            )
        out.append(step.kind)
        out.append(step.depth)
        out.extend(len(name).to_bytes(2, "little"))
        out.extend(name)
    return bytes(out)


def decode_program(blob: bytes) -> Program:
    """Decodes a program the packer encoded.

    Args:
        blob: The encoded program.

    Returns:
        The program.

    Raises:
        ProgramError: The blob is truncated, a count or length is out of bounds, or a step's kind is unknown.
    """
    view = memoryview(blob)
    if len(view) < 2:
        raise ProgramError("a program blob holds a step count")
    count = int.from_bytes(view[:2], "little")
    if not 1 <= count <= MAX_STEPS:
        raise ProgramError(f"a program holds 1 to {MAX_STEPS} steps, not {count}")
    offset = 2
    steps: list[Step] = []
    for _ in range(count):
        if len(view) - offset < 4:
            raise ProgramError("a step is truncated")
        kind = view[offset]
        depth = view[offset + 1]
        name_len = int.from_bytes(view[offset + 2 : offset + 4], "little")
        offset += 4
        if name_len == 0 or len(view) - offset < name_len:
            raise ProgramError("a step's class name is truncated")
        name = bytes(view[offset : offset + name_len]).decode("utf-8")
        offset += name_len
        if kind not in (KIND_RESOLVE, KIND_SUPERS):
            raise ProgramError(f"a step's kind is unknown: {kind}")
        steps.append(Step(kind=kind, name=name, depth=depth))
    if offset != len(view):
        raise ProgramError("a program blob holds trailing bytes")
    return Program(steps=tuple(steps))


def run_reference(program: Program) -> bytes:
    """Runs the reference of a program: the share a real Android runtime must produce.

    Each step's input is what the runtime observes through ART — the resolved class's own name, or the names its
    superclass chain yields, joined — and the chain folds the inputs with the same HKDF construction the fold's
    chains use, under this arm's own info.

    Args:
        program: The program to run.

    Returns:
        The Java share, 32 bytes.
    """
    state = bytes(KEY_SIZE)
    for index, step in enumerate(program.steps):
        state = key_schedule._hkdf(
            state, salt=_step_input(step), info=f"rasp.v2.j/{index}".encode()
        )
    return state


def _step_input(step: Step) -> bytes:
    """Returns the bytes one step contributes: the runtime's observation of it.

    Args:
        step: The step.

    Returns:
        The step's input. A resolve step contributes the class's own name; a supers step the names of the first
        `depth` hops of its superclass chain, joined by NUL, exactly what walking `getSuperclass` yields.
    """
    if step.kind == KIND_RESOLVE:
        return step.name.encode("utf-8")
    chain = CORE_STEPS.get(step.name, ())
    hops = chain[: step.depth] if step.depth <= len(chain) else chain
    return b"\0".join(hop.encode("utf-8") for hop in hops)
