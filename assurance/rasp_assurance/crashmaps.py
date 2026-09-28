"""Encrypt, archive, upload and resolve build-bound private symbol mappings."""

from __future__ import annotations

import argparse
import base64
import hashlib
import http.client
import json
import os
import pathlib
import re
import ssl
import struct
import urllib.parse

from cryptography import exceptions
from cryptography.hazmat.primitives.ciphers import aead

MAX_MAP_BYTES = 16 * 1024 * 1024
MAX_ARCHIVE_BYTES = MAX_MAP_BYTES + 8192
MAGIC = b"RCM1"


def context(tenant: str, app: str, build: str, artifact: pathlib.Path) -> bytes:
    values = (tenant, app, build)
    if any(len(value.strip()) == 0 or len(value) > 200 for value in values):
        raise ValueError("tenant, application and build identifiers required")
    digest = hashlib.sha256()
    with artifact.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return json.dumps(
        {
            "tenantId": tenant,
            "appId": app,
            "buildId": build,
            "artifactSha256": digest.hexdigest(),
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()


def validate_map(data: bytes) -> dict[str, str]:
    if len(data) == 0 or len(data) > MAX_MAP_BYTES:
        raise ValueError("mapping exceeds bounds")
    value = json.loads(data)
    if not isinstance(value, dict) or len(value) == 0:
        raise ValueError("mapping must be a nonempty object")
    for name, original in value.items():
        if (
            not isinstance(original, str)
            or not 1 <= len(original) <= 2048
            or re.fullmatch(r"[A-Za-z_$][A-Za-z0-9_$]*", name) is None
        ):
            raise ValueError("invalid symbol mapping")
    return value


def seal(data: bytes, key: bytes, binding: bytes) -> bytes:
    validate_map(data)
    if len(key) != 32 or len(binding) > 4096:
        raise ValueError("AES-256 key and bounded binding required")
    nonce = os.urandom(12)
    header = MAGIC + struct.pack(">I", len(binding)) + binding + nonce
    return header + aead.AESGCM(key).encrypt(nonce, data, header)


def open_archive(data: bytes, key: bytes, binding: bytes) -> dict[str, str]:
    if (
        len(data) < 36
        or len(data) > MAX_ARCHIVE_BYTES
        or data[:4] != MAGIC
        or len(key) != 32
    ):
        raise ValueError("invalid archive")
    length = struct.unpack(">I", data[4:8])[0]
    if length > 4096 or len(data) < 8 + length + 28 or data[8 : 8 + length] != binding:
        raise ValueError(
            "archive belongs to another tenant, application, build or binary"
        )
    end = 20 + length
    return validate_map(
        aead.AESGCM(key).decrypt(data[end - 12 : end], data[end:], data[:end])
    )


def archive(store: pathlib.Path, data: bytes, binding: bytes) -> pathlib.Path:
    """An immutable 0600 object inside a trusted operator-owned directory."""
    store.mkdir(mode=0o700, parents=True, exist_ok=True)
    destination = store / (hashlib.sha256(binding).hexdigest() + ".rmap")
    descriptor = os.open(
        destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
    )
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
    except BaseException:
        destination.unlink(missing_ok=True)
        raise
    return destination


def symbolize(trace: str, mapping: dict[str, str]) -> str:
    if len(trace) > MAX_MAP_BYTES:
        raise ValueError("trace exceeds bounds")
    return re.sub(
        r"[A-Za-z_$][A-Za-z0-9_$]*",
        lambda match: mapping.get(match[0], match[0]),
        trace,
    )


def upload(url: str, data: bytes, token: str) -> int:
    parsed = urllib.parse.urlsplit(url)
    if (
        parsed.scheme != "https"
        or parsed.hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment != ""
    ):
        raise ValueError(
            "artifact upload requires an HTTPS URL without credentials or fragments"
        )
    if (
        len(data) < 36
        or len(data) > MAX_ARCHIVE_BYTES
        or data[:4] != MAGIC
        or token == ""
        or "\r" in token
        or "\n" in token
    ):
        raise ValueError("encrypted archive and upload credential required")
    connection = http.client.HTTPSConnection(
        parsed.hostname,
        parsed.port or 443,
        timeout=30,
        context=ssl.create_default_context(),
    )
    try:
        target = urllib.parse.urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
        connection.request(
            "PUT",
            target,
            body=data,
            headers={
                "Authorization": "Bearer " + token,
                "Content-Type": "application/octet-stream",
                "Digest": "sha-256="
                + base64.b64encode(hashlib.sha256(data).digest()).decode(),
            },
        )
        response = connection.getresponse()
        if not 200 <= response.status < 300:
            raise ValueError("artifact upload refused")
        return response.status
    finally:
        connection.close()


def read_bounded(path: pathlib.Path, limit: int) -> bytes:
    with path.open("rb") as source:
        value = source.read(limit + 1)
    if len(value) > limit:
        raise ValueError("input exceeds bounds")
    return value


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("archive", "symbolize"):
        command = commands.add_parser(name)
        for option in ("tenant", "app", "build"):
            command.add_argument("--" + option, required=True)
        command.add_argument("--artifact", type=pathlib.Path, required=True)
        command.add_argument("--key-file", type=pathlib.Path, required=True)
        if name == "archive":
            command.add_argument("--symbols", type=pathlib.Path, required=True)
            command.add_argument("--store", type=pathlib.Path, required=True)
        else:
            command.add_argument("--archive", type=pathlib.Path, required=True)
            command.add_argument("--trace", type=pathlib.Path, required=True)
    send = commands.add_parser("upload")
    send.add_argument("archive", type=pathlib.Path)
    send.add_argument("--url", required=True)
    args = parser.parse_args()
    try:
        if args.command == "upload":
            upload(
                args.url,
                read_bounded(args.archive, MAX_ARCHIVE_BYTES),
                os.environ.get("RASP_ARTIFACT_TOKEN", ""),
            )
            print(json.dumps({"uploaded": True}))
        else:
            binding = context(args.tenant, args.app, args.build, args.artifact)
            key = read_bounded(args.key_file, 32)
            if args.command == "archive":
                path = archive(
                    args.store,
                    seal(read_bounded(args.symbols, MAX_MAP_BYTES), key, binding),
                    binding,
                )
                print(json.dumps({"archive": str(path)}))
            else:
                mapping = open_archive(
                    read_bounded(args.archive, MAX_ARCHIVE_BYTES), key, binding
                )
                print(
                    symbolize(
                        read_bounded(args.trace, MAX_MAP_BYTES).decode(
                            errors="replace"
                        ),
                        mapping,
                    )
                )
    except (
        ValueError,
        OSError,
        KeyError,
        RecursionError,
        exceptions.InvalidTag,
        http.client.HTTPException,
    ):
        print(json.dumps({"error": "artifact_operation_failed"}))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
