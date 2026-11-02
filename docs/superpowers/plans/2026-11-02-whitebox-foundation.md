# Offline White-box Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Delegate only when the user or applicable instructions authorize it.

**Goal:** Establish the exact v2 payload format and an independent trusted-host correctness oracle for the offline white-box research implementation.

**Architecture:** A standalone `whitebox/` package owns the research format and reference AES-GCM implementation. The future compiler and native runtime must match this oracle. This milestone does not implement white-box protection or change existing app packing.

**Tech Stack:** Python 3.14, cryptography 50.0.2, pytest 9.1.1, Ruff 0.16.10, mypy 2.4.0; versions match the existing packer.

**Design:** [Complete implementation design](../specs/2026-11-02-whitebox-design.md). Subsequent stages M1-M6 are defined there with research gates. This plan deliberately covers the fully specified M0 contract; it does not substitute invented code for unresolved masking or active-fault research.

## Scope and file map

Create exactly these project files, then generate `whitebox/uv.lock` with `uv lock`:

| File | Responsibility |
|---|---|
| `whitebox/pyproject.toml` | Isolated research dependency and check configuration |
| `whitebox/src/rasp_whitebox/__init__.py` | Package marker and security scope |
| `whitebox/src/rasp_whitebox/frame.py` | Header, resource limits, reference encryption and authentication |
| `whitebox/tests/rasp_whitebox/frame_test.py` | Executable format, mutation, boundary and nonce rules |

No production import from `rasp_whitebox` is permitted in M0. The raw-key API is intentional on the trusted build/evaluation host; it must never become the generated runtime API. `BuildContext` is single-threaded and belongs to one build transaction. Explicit key construction is for research fixtures; deployment builds use `new_context()` and never resume or clone the context.

## Task 1: Establish the research package

**Files:** Create `whitebox/pyproject.toml` and `whitebox/src/rasp_whitebox/__init__.py`.

- [ ] Read `AGENT.md` and the design's format and stage sections. Verify a clean tracked workspace and use a dedicated development branch.
- [ ] Create `whitebox/pyproject.toml` with this exact content:

```toml
[project]
name = "rasp-whitebox"
version = "0.0.0"
description = "Offline white-box research compiler and evaluation tools"
requires-python = ">=3.14"
dependencies = ["cryptography==50.0.2"]

[dependency-groups]
dev = ["mypy==2.4.0", "pytest==9.1.1", "ruff==0.16.10"]

[build-system]
requires = ["hatchling==1.29.0"]
build-backend = "hatchling.build"

[tool.ruff]
target-version = "py314"

[tool.ruff.lint]
select = ["B", "C4", "E", "F", "I", "PT", "RUF", "SIM", "UP", "W"]
ignore = ["E501"]

[tool.ruff.lint.isort]
force-single-line = true

[tool.mypy]
python_version = "3.14"
strict = true
files = ["src", "tests"]
mypy_path = "src"
warn_unreachable = true
enable_error_code = ["ignore-without-code", "redundant-expr", "truthy-bool"]

[tool.pytest.ini_options]
testpaths = ["tests"]
pythonpath = ["src"]
python_files = ["*_test.py"]
python_functions = ["test*"]
addopts = ["--import-mode=importlib", "--strict-config", "--strict-markers"]
xfail_strict = true
filterwarnings = ["error"]
```

- [ ] Create `whitebox/src/rasp_whitebox/__init__.py`:

```python
"""Research tools; no production white-box security claim."""
```

- [ ] From `whitebox/`, run `uv lock` and `uv sync --locked`. Expected: the pinned dependencies resolve and the editable package installs. Keep the generated lockfile; do not copy an unrelated environment's lockfile.
- [ ] From `whitebox/`, run `uv run python -c 'import rasp_whitebox'`. Expected: exit status 0.

## Task 2: Write the executable format contract before the codec

**File:** Create `whitebox/tests/rasp_whitebox/frame_test.py`.

The mutation tests enumerate every byte of a concrete record and every truncated prefix. They cover header fields, ciphertext, and the authentication tag. Length-limit tests exercise real encryption rather than mocked calls. Canonical-header bytes are an independently written wire-format assertion, rather than packing and unpacking through the same helper.

- [ ] Create the test file with this complete content:

```python
"""Executable contract for v2 payload framing and authentication."""

import pytest
from cryptography.hazmat.primitives.ciphers import aead

from rasp_whitebox import frame


@pytest.fixture
def context() -> frame.BuildContext:
    """Return an independent known-key fixture for each test."""
    return frame.BuildContext(
        key=bytes(16), build_id=bytes(range(16)), nonce_prefix=b"\x01" * 8
    )


@pytest.mark.parametrize("size", [0, 1, 15, 16, 17, 1024])
@pytest.mark.parametrize("payload_id", [0, 1, 65535])
def testSeal_whenValidInput_matchesIndependentAead(
    context: frame.BuildContext, size: int, payload_id: int
) -> None:
    plaintext = b"x" * size
    encoded = context.seal(payload_id, plaintext)
    assert len(encoded) == 80 + size
    assert (
        aead.AESGCM(context.key).decrypt(
            context.nonce_prefix + payload_id.to_bytes(4, "big"),
            encoded[64:],
            encoded[:64],
        )
        == plaintext
    )
    assert (
        frame.open_frame(
            encoded,
            key=context.key,
            build_id=context.build_id,
            payload_id=payload_id,
            nonce_prefix=context.nonce_prefix,
        )
        == plaintext
    )


def testSeal_whenKnownInput_matchesCanonicalHeader(context: frame.BuildContext) -> None:
    encoded = context.seal(1, b"DEX\x00example")
    assert encoded[:64].hex() == (
        "5241535057424f58"
        "0002"
        "0001"
        "000102030405060708090a0b0c0d0e0f"
        "00000001"
        "000000000000000b"
        "000000000000000b"
        "010101010101010100000001"
        "00000000"
    )


def testSeal_whenIdReused_rejectsNonceReuse(context: frame.BuildContext) -> None:
    context.seal(1, b"first")
    with pytest.raises(frame.FrameError, match="already used"):
        context.seal(1, b"different")


@pytest.mark.parametrize("offset", range(91))
def testOpen_whenAnyRecordByteChanges_rejectsRecord(
    context: frame.BuildContext, offset: int
) -> None:
    encoded = bytearray(context.seal(1, b"DEX\x00example"))
    encoded[offset] ^= 1
    with pytest.raises(frame.FrameError):
        frame.open_frame(
            bytes(encoded),
            key=context.key,
            build_id=context.build_id,
            payload_id=1,
            nonce_prefix=context.nonce_prefix,
        )


@pytest.mark.parametrize("length", range(91))
def testOpen_whenTruncated_rejectsRecord(
    context: frame.BuildContext, length: int
) -> None:
    encoded = context.seal(1, b"DEX\x00example")[:length]
    with pytest.raises(frame.FrameError):
        frame.open_frame(
            encoded,
            key=context.key,
            build_id=context.build_id,
            payload_id=1,
            nonce_prefix=context.nonce_prefix,
        )


def testOpen_whenTrailingData_rejectsRecord(context: frame.BuildContext) -> None:
    encoded = context.seal(1, b"payload") + b"extra"
    with pytest.raises(frame.FrameError, match="length mismatch"):
        frame.open_frame(
            encoded,
            key=context.key,
            build_id=context.build_id,
            payload_id=1,
            nonce_prefix=context.nonce_prefix,
        )


def testOpen_whenWrongPayloadId_rejectsSwap(context: frame.BuildContext) -> None:
    encoded = context.seal(1, b"payload")
    with pytest.raises(frame.FrameError, match="identity mismatch"):
        frame.open_frame(
            encoded,
            key=context.key,
            build_id=context.build_id,
            payload_id=2,
            nonce_prefix=context.nonce_prefix,
        )


def testOpen_whenWrongBuild_rejectsSwap(context: frame.BuildContext) -> None:
    encoded = context.seal(1, b"payload")
    with pytest.raises(frame.FrameError, match="identity mismatch"):
        frame.open_frame(
            encoded,
            key=context.key,
            build_id=bytes(16),
            payload_id=1,
            nonce_prefix=context.nonce_prefix,
        )


def testOpen_whenWrongKey_rejectsRecord(context: frame.BuildContext) -> None:
    encoded = context.seal(1, b"payload")
    with pytest.raises(frame.FrameError, match="authentication failed"):
        frame.open_frame(
            encoded,
            key=b"\x02" * 16,
            build_id=context.build_id,
            payload_id=1,
            nonce_prefix=context.nonce_prefix,
        )


@pytest.mark.parametrize("payload_id", [-1, 65536])
def testSeal_whenIdOutOfRange_rejectsRecord(
    context: frame.BuildContext, payload_id: int
) -> None:
    with pytest.raises(frame.FrameError, match="invalid payload ID"):
        context.seal(payload_id, b"payload")


def testSeal_whenMapOverLimit_rejectsPayload(context: frame.BuildContext) -> None:
    with pytest.raises(frame.FrameError, match="too large"):
        context.seal(0, bytes(frame.MAX_MAP_SIZE + 1))


@pytest.mark.parametrize("payload_id", [0, 1])
def testSeal_whenAtLimit_roundTrips(
    context: frame.BuildContext, payload_id: int
) -> None:
    size = frame.MAX_MAP_SIZE if payload_id == 0 else frame.MAX_DEX_SIZE
    encoded = context.seal(payload_id, bytes(size))
    assert frame.open_frame(
        encoded,
        key=context.key,
        build_id=context.build_id,
        payload_id=payload_id,
        nonce_prefix=context.nonce_prefix,
    ) == bytes(size)


def testOpen_whenHugeDeclaredSize_rejectsBeforeDecrypt(
    context: frame.BuildContext,
) -> None:
    encoded = bytearray(context.seal(1, b"payload"))
    encoded[32:48] = b"\xff" * 16
    with pytest.raises(frame.FrameError, match="invalid payload length"):
        frame.open_frame(
            bytes(encoded),
            key=context.key,
            build_id=context.build_id,
            payload_id=1,
            nonce_prefix=context.nonce_prefix,
        )


def testNewContext_whenCreated_supportsFreshBuild() -> None:
    context = frame.new_context()
    encoded = context.seal(0, b"map")
    assert len(context.key) == 16
    assert (
        frame.open_frame(
            encoded,
            key=context.key,
            build_id=context.build_id,
            payload_id=0,
            nonce_prefix=context.nonce_prefix,
        )
        == b"map"
    )
```

- [ ] From `whitebox/`, run `uv run pytest tests/rasp_whitebox/frame_test.py -q`. Expected: collection fails because `rasp_whitebox.frame` does not exist. A passing run at this point means an unrelated installed module or stale file is being imported; resolve that before proceeding.

## Task 3: Implement the reference codec

**File:** Create `whitebox/src/rasp_whitebox/frame.py`.

This is an ordinary AES-GCM oracle for future compiler/native implementations. It is not an obfuscation or masking backend. The one-use ID set prevents accidental nonce reuse within one context; it cannot protect against a caller reconstructing a context with the same key, and does not claim to do so.

- [ ] Create the module with this complete content:

```python
"""Canonical experimental payload records and a trusted-host AEAD oracle.

This module uses ordinary AES-GCM. It provides no white-box protection and
must not be embedded in a protected application's runtime.
"""

import dataclasses
import secrets
import struct

from cryptography import exceptions
from cryptography.hazmat.primitives.ciphers import aead

HEADER_SIZE = 64
TAG_SIZE = 16
MAX_MAP_SIZE = 4 * 1024 * 1024
MAX_DEX_SIZE = 16 * 1024 * 1024
MAX_PAYLOAD_ID = 65535
_HEADER = struct.Struct(">8sHH16sIQQ12sI")
_MAGIC = b"RASPWBOX"


class Error(Exception):
    """A reference format operation failed."""


class FrameError(Error):
    """A context or record is invalid or authentication failed."""


def _validate_identity(build_id: bytes, nonce_prefix: bytes) -> None:
    """Reject malformed trusted-host context inputs."""
    if len(build_id) != 16 or len(nonce_prefix) != 8:
        raise FrameError("invalid build identity")


def _payload_limit(payload_id: int) -> int:
    """Validate an ID and return its plaintext limit."""
    if payload_id < 0 or payload_id > MAX_PAYLOAD_ID:
        raise FrameError("invalid payload ID")
    return MAX_MAP_SIZE if payload_id == 0 else MAX_DEX_SIZE


@dataclasses.dataclass(frozen=True, slots=True, kw_only=True)
class Header:
    """Validated public metadata needed by the AEAD oracle."""

    plaintext_length: int
    nonce: bytes


def parse_header(
    frame: bytes,
    *,
    build_id: bytes,
    payload_id: int,
    nonce_prefix: bytes,
) -> Header:
    """Validate canonical framing and identity before cryptographic processing."""
    _validate_identity(build_id, nonce_prefix)
    limit = _payload_limit(payload_id)
    if len(frame) < HEADER_SIZE + TAG_SIZE:
        raise FrameError("truncated frame")
    if (
        frame[:8] != _MAGIC
        or int.from_bytes(frame[8:10], "big") != 2
        or int.from_bytes(frame[10:12], "big") != 1
        or frame[60:64] != bytes(4)
    ):
        raise FrameError("unsupported frame format")
    expected_nonce = nonce_prefix + payload_id.to_bytes(4, "big")
    if (
        frame[12:28] != build_id
        or int.from_bytes(frame[28:32], "big") != payload_id
        or frame[48:60] != expected_nonce
    ):
        raise FrameError("frame identity mismatch")
    plaintext_length = int.from_bytes(frame[32:40], "big")
    ciphertext_length = int.from_bytes(frame[40:48], "big")
    if plaintext_length > limit or ciphertext_length != plaintext_length:
        raise FrameError("invalid payload length")
    if len(frame) != HEADER_SIZE + plaintext_length + TAG_SIZE:
        raise FrameError("frame length mismatch")
    return Header(plaintext_length=plaintext_length, nonce=expected_nonce)


@dataclasses.dataclass(frozen=True, slots=True, kw_only=True)
class BuildContext:
    """Single-threaded build context; construct fresh contexts with new_context.

    Explicit construction is for known-key research fixtures only. Do not
    clone, serialize, or resume a context to encrypt additional records.
    """

    key: bytes = dataclasses.field(repr=False)
    build_id: bytes
    nonce_prefix: bytes
    _used_ids: set[int] = dataclasses.field(
        default_factory=set, init=False, repr=False, compare=False
    )

    def __post_init__(self) -> None:
        """Validate the key and identity before any encryption."""
        if len(self.key) != 16:
            raise FrameError("AES-128 needs a 16-byte key")
        _validate_identity(self.build_id, self.nonce_prefix)

    def seal(self, payload_id: int, plaintext: bytes) -> bytes:
        """Encrypt one record, permanently reserving its ID before encryption."""
        limit = _payload_limit(payload_id)
        if len(plaintext) > limit:
            raise FrameError("payload too large")
        if payload_id in self._used_ids:
            raise FrameError("payload ID already used")
        self._used_ids.add(payload_id)
        nonce = self.nonce_prefix + payload_id.to_bytes(4, "big")
        header = _HEADER.pack(
            _MAGIC,
            2,
            1,
            self.build_id,
            payload_id,
            len(plaintext),
            len(plaintext),
            nonce,
            0,
        )
        return header + aead.AESGCM(self.key).encrypt(nonce, plaintext, header)


def new_context() -> BuildContext:
    """Generate an independent key and public identity for one build."""
    return BuildContext(
        key=aead.AESGCM.generate_key(bit_length=128),
        build_id=secrets.token_bytes(16),
        nonce_prefix=secrets.token_bytes(8),
    )


def open_frame(
    frame: bytes,
    *,
    key: bytes,
    build_id: bytes,
    payload_id: int,
    nonce_prefix: bytes,
) -> bytes:
    """Return authenticated plaintext on the trusted host, or raise FrameError."""
    if len(key) != 16:
        raise FrameError("AES-128 needs a 16-byte key")
    header = parse_header(
        frame, build_id=build_id, payload_id=payload_id, nonce_prefix=nonce_prefix
    )
    try:
        return aead.AESGCM(key).decrypt(
            header.nonce, frame[HEADER_SIZE:], frame[:HEADER_SIZE]
        )
    except exceptions.InvalidTag as error:
        raise FrameError("authentication failed") from error
```

- [ ] From `whitebox/`, run `uv run pytest tests/rasp_whitebox/frame_test.py -q`. Expected: 213 tests pass with the exact tests above.
- [ ] Run `uv run ruff format --check .` and `uv run ruff check .`. Expected: no formatting or lint errors.
- [ ] Run `uv run mypy`. Expected: no strict type errors in the source or tests.
- [ ] Run `uv run pytest`. Expected: all research package tests pass.

## Task 4: Review the milestone and commit

- [ ] Verify the public header is exactly 64 bytes, all lengths are byte lengths, and all integer fields use big-endian encoding. Compare the implementation to the design table rather than relying only on round-trip tests.
- [ ] Verify the only plaintext-returning function is explicitly scoped to the trusted host, no runtime or packer imports were added, and no actual challenge keys, generated libraries, or build manifests are in the diff.
- [ ] From the repository root, run `git diff --check`. Expected: no whitespace errors.
- [ ] Stage only `whitebox/pyproject.toml`, `whitebox/uv.lock`, `whitebox/src/rasp_whitebox/__init__.py`, `whitebox/src/rasp_whitebox/frame.py`, and `whitebox/tests/rasp_whitebox/frame_test.py`.
- [ ] Run `git diff --cached --stat` and `git diff --cached --check`; then commit with `git commit -m 'feature: define experimental white-box payload contract'`. Submit through the repository's PR workflow when publishing this implementation.

## Next implementation boundary

M1 starts with `ir.py`, `aes.py`, `gcm.py`, and `reference.py`, followed by a trace-based positive-control attack. Its required result is a standards-equivalent circuit and an attack that demonstrably recovers an unprotected key. Only then begin reproducing the selected masking construction for M2. The cryptographic design's missing research results must not be replaced by stubs, silently assumed invariants, or claims that a passing AEAD test proves white-box security.

## Verification of these plan examples

The exact Python and TOML blocks in this plan were materialized in `/tmp/rasp-whitebox-design-check` during design preparation. On Python 3.14.10 with the pinned dependency/check versions, pytest reported 213 passing tests; Ruff formatting/lint and strict mypy checks passed. This validates the reference examples, not the future white-box compiler, native implementation, or security properties. The temporary package is outside the repository; the committed deliverables for the design task are documentation only.
