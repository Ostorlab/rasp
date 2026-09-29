"""Strict, bounded Ed25519 wire messages shared with the injected runtime."""

from __future__ import annotations

import hashlib
import ipaddress
import os
import pathlib
import re
import stat
import urllib.parse

from cryptography import exceptions
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

MAX_MESSAGE_BYTES = 8192
MANIFEST_FIELDS = ("v", "build", "exe", "runtime", "endpoint", "interval_ms", "client_public", "server_public")
EVIDENCE_FIELDS = ("v", "build", "nonce", "pid", "exe", "runtime", "threats", "operation", "request")
DECISION_FIELDS = ("v", "build", "nonce", "evidence", "action", "expires")
THREATS = frozenset(("tamper", "debugger", "preload", "detectorFailure"))
OPERATIONS = frozenset(("startup", "monitor", "connect", "checkpoint"))
ACTIONS = frozenset(("allow", "deny", "step_up"))


def is_hex(value: str, size: int = 32) -> bool:
    return re.fullmatch(r"[0-9a-f]{" + str(size * 2) + "}", value) is not None


def public_hex(key: ed25519.Ed25519PrivateKey) -> str:
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()


def private_hex(key: ed25519.Ed25519PrivateKey) -> str:
    return key.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
    ).hex()


def read_private_key(path: pathlib.Path) -> ed25519.Ed25519PrivateKey:
    value = read_regular_file(path, 256).decode("ascii").strip()
    if is_hex(value) is False:
        raise ValueError("private key must be 32 bytes of lowercase hex")
    return ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(value))


def read_public_key(path: pathlib.Path) -> str:
    value = read_regular_file(path, 256).decode("ascii").strip()
    if is_hex(value) is False:
        raise ValueError("public key must be 32 bytes of lowercase hex")
    return value


def sign_message(values: dict[str, str], key: ed25519.Ed25519PrivateKey) -> bytes:
    if "signature" in values:
        raise ValueError("signature is reserved")
    for name, value in values.items():
        if re.fullmatch(r"[a-z_]+", name) is None or any(char in value for char in ("\n", "\r", "\x00")):
            raise ValueError("invalid message field")
    signed = "".join(f"{name}={value}\n" for name, value in values.items()).encode("ascii")
    message = signed + f"signature={key.sign(signed).hex()}\n".encode("ascii")
    if len(message) > MAX_MESSAGE_BYTES:
        raise ValueError("message too large")
    return message


def parse_message(message: bytes, fields: tuple[str, ...]) -> tuple[dict[str, str], bytes, bytes]:
    if len(message) > MAX_MESSAGE_BYTES or message.endswith(b"\n") is False:
        raise ValueError("invalid message length or termination")
    try:
        text = message.decode("ascii")
    except UnicodeDecodeError as error:
        raise ValueError("message must be ASCII") from error
    if "\r" in text or "\x00" in text:
        raise ValueError("invalid message characters")
    lines = text[:-1].split("\n")
    expected = (*fields, "signature")
    if len(lines) != len(expected):
        raise ValueError("unexpected message fields")
    values: dict[str, str] = {}
    for line, field in zip(lines, expected, strict=True):
        name, separator, value = line.partition("=")
        if separator != "=" or name != field:
            raise ValueError("unexpected message field order")
        values[name] = value
    if is_hex(values["signature"], 64) is False:
        raise ValueError("invalid signature encoding")
    signature = bytes.fromhex(values.pop("signature"))
    signed = message[: message.rfind(b"signature=")]
    return values, signed, signature


def verify_message(message: bytes, public_key: str, fields: tuple[str, ...]) -> tuple[dict[str, str], bytes]:
    values, signed, signature = parse_message(message, fields)
    if is_hex(public_key) is False:
        raise ValueError("invalid public key")
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key)).verify(signature, signed)
    except exceptions.InvalidSignature as error:
        raise ValueError("invalid signature") from error
    return values, signed


def validate_endpoint(endpoint: str) -> None:
    if endpoint == "":
        return
    parsed = urllib.parse.urlsplit(endpoint)
    try:
        port = parsed.port
    except ValueError as error:
        raise ValueError("invalid endpoint port") from error
    if (
        parsed.scheme not in ("http", "https")
        or parsed.hostname is None
        or port is None
        or port < 1
        or port > 65535
        or parsed.path != ""
        or parsed.query != ""
        or parsed.fragment != ""
        or parsed.username is not None
        or parsed.password is not None
        or len(endpoint) > 512
    ):
        raise ValueError("endpoint must be http[s]://host:port with no path or credentials")
    if parsed.scheme == "http":
        try:
            address = ipaddress.ip_address(parsed.hostname)
        except ValueError as error:
            raise ValueError("HTTP is restricted to literal loopback addresses") from error
        if address.is_loopback is False:
            raise ValueError("HTTP is restricted to literal loopback addresses")
    if re.fullmatch(r"[A-Za-z0-9.:\[\]-]+", parsed.netloc) is None:
        raise ValueError("invalid endpoint host")


def validate_manifest(message: bytes, publisher_public: str) -> dict[str, str]:
    values, _ = verify_message(message, publisher_public, MANIFEST_FIELDS)
    if values["v"] != "rasp-elf-manifest-1":
        raise ValueError("invalid manifest version")
    for name in ("build", "exe", "runtime", "client_public", "server_public"):
        if is_hex(values[name]) is False:
            raise ValueError(f"invalid {name}")
    if re.fullmatch(r"[0-9]+", values["interval_ms"]) is None or not 100 <= int(values["interval_ms"]) <= 60000:
        raise ValueError("interval_ms must be between 100 and 60000")
    validate_endpoint(values["endpoint"])
    if values["endpoint"] != "" and values["server_public"] == "00" * 32:
        raise ValueError("backend requires a decision public key")
    return values


def read_regular_file(path: pathlib.Path, limit: int) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(descriptor, "rb") as stream:
        metadata = os.fstat(stream.fileno())
        if stat.S_ISREG(metadata.st_mode) is False:
            raise ValueError("input must be a regular file")
        if metadata.st_size > limit:
            raise ValueError("file too large")
        data = stream.read(limit + 1)
        if len(data) > limit or len(data) != metadata.st_size:
            raise ValueError("file size changed while reading")
        return data


def sha256_file(path: pathlib.Path) -> str:
    descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
    digest = hashlib.sha256()
    with os.fdopen(descriptor, "rb") as stream:
        metadata = os.fstat(stream.fileno())
        if stat.S_ISREG(metadata.st_mode) is False:
            raise ValueError("hash input must be a regular file")
        if metadata.st_size > 256 * 1024 * 1024:
            raise ValueError("hash input exceeds 256 MiB")
        remaining = metadata.st_size
        while remaining > 0:
            chunk = stream.read(min(65536, remaining))
            if len(chunk) == 0:
                raise ValueError("file size changed while hashing")
            digest.update(chunk)
            remaining -= len(chunk)
        after = os.fstat(stream.fileno())
        if (metadata.st_size, metadata.st_mtime_ns, metadata.st_ctime_ns) != (
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ):
            raise ValueError("file changed while hashing")
    return digest.hexdigest()
