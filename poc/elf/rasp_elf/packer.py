"""Rewrite dynamic ELF dependencies and publish signed, relocatable bundles."""

from __future__ import annotations

import ctypes
import errno
import json
import os
import pathlib
import secrets
import stat
import subprocess
import sys
import tempfile

import lief
from cryptography.hazmat.primitives.asymmetric import ed25519

from rasp_elf import protocol

RUNTIME_NAME = "librasp_runtime.so"
DEPENDENCY = "$ORIGIN/" + RUNTIME_NAME


def _publish(stage: pathlib.Path, destination: pathlib.Path) -> None:
    """Linux atomic rename that never replaces a concurrent user's directory."""
    libc = ctypes.CDLL(None, use_errno=True)
    rename = libc.renameat2
    rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    rename.restype = ctypes.c_int
    if rename(-100, os.fsencode(stage), -100, os.fsencode(destination), 1) != 0:
        error = ctypes.get_errno()
        if error == errno.EEXIST:
            raise FileExistsError(destination)
        raise OSError(error, os.strerror(error), str(destination))


def keygen(output: pathlib.Path) -> None:
    output = output.absolute()
    if output.exists() is True:
        raise FileExistsError(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".rasp-keys-", dir=output.parent) as temp:
        stage = pathlib.Path(temp) / "keys"
        stage.mkdir(mode=0o700)
        for name in ("publisher", "backend"):
            key = ed25519.Ed25519PrivateKey.generate()
            private = stage / f"{name}.key"
            private.write_text(protocol.private_hex(key) + "\n", encoding="ascii")
            private.chmod(0o600)
            (stage / f"{name}.pub").write_text(protocol.public_hex(key) + "\n", encoding="ascii")
        _publish(stage, output)


def _input_elf(source: pathlib.Path) -> lief.ELF.Binary:
    metadata = source.stat()
    if stat.S_ISREG(metadata.st_mode) is False:
        raise ValueError("input must be a regular ELF file")
    if metadata.st_mode & (stat.S_ISUID | stat.S_ISGID) != 0:
        raise ValueError("setuid/setgid ELF inputs are unsupported")
    if metadata.st_size > 256 * 1024 * 1024:
        raise ValueError("ELF exceeds prototype 256 MiB limit")
    with source.open("rb") as stream:
        identity = stream.read(64)
    if len(identity) < 64 or identity[:4] != b"\x7fELF":
        raise ValueError("input is not an ELF")
    if identity[4:6] != b"\x02\x01" or int.from_bytes(identity[18:20], "little") != 62:
        raise ValueError("only little-endian x86-64 ELF is supported")
    binary = lief.ELF.parse(str(source))
    if binary is None:
        raise ValueError("malformed ELF")
    if binary.header.file_type not in (lief.ELF.Header.FILE_TYPE.EXEC, lief.ELF.Header.FILE_TYPE.DYN):
        raise ValueError("input must be an executable ELF")
    if binary.has_interpreter is False:
        raise ValueError("input must be a dynamically linked executable; static ELF and libraries unsupported")
    if pathlib.PurePosixPath(binary.interpreter).name != "ld-linux-x86-64.so.2":
        raise ValueError("only the glibc x86-64 loader is supported")
    if any("librasp_runtime" in name for name in binary.libraries):
        raise ValueError("ELF is already protected")
    if binary.entrypoint == 0 or len(list(binary.segments)) == 0:
        raise ValueError("invalid ELF executable entrypoint")
    return binary


def _runtime_source() -> pathlib.Path:
    candidates = (
        pathlib.Path(__file__).resolve().parents[1] / "runtime" / "rasp_runtime.c",
        pathlib.Path(sys.prefix) / "share" / "rasp-elf" / "runtime" / "rasp_runtime.c",
    )
    for candidate in candidates:
        if candidate.is_file() is True:
            return candidate
    raise ValueError("native runtime source is missing; install the full rasp-elf distribution")


def pack(
    source: pathlib.Path,
    output: pathlib.Path,
    publisher: ed25519.Ed25519PrivateKey,
    endpoint: str = "",
    server_public: str = "00" * 32,
    interval_ms: int = 250,
) -> dict[str, object]:
    source = source.absolute()
    output = output.absolute()
    if output.exists() is True:
        raise FileExistsError(output)
    if source.name in (RUNTIME_NAME, "rasp.manifest", "report.json"):
        raise ValueError("input name collides with protection metadata")
    protocol.validate_endpoint(endpoint)
    if type(interval_ms) is not int or not 100 <= interval_ms <= 60000:
        raise ValueError("interval_ms must be between 100 and 60000")
    if protocol.is_hex(server_public) is False or (endpoint != "" and server_public == "00" * 32):
        raise ValueError("backend requires a valid decision public key")
    binary = _input_elf(source)
    input_hash = protocol.sha256_file(source)
    original_libraries = list(binary.libraries)
    output.parent.mkdir(parents=True, exist_ok=True)
    client = ed25519.Ed25519PrivateKey.generate()
    with tempfile.TemporaryDirectory(prefix=".rasp-pack-", dir=output.parent) as temp:
        working = pathlib.Path(temp)
        stage = working / "bundle"
        stage.mkdir()
        # Secrets are only written to the temporary compilation header, not the bundle.
        header = working / "rasp_build.h"
        header.write_text(
            f'#define RASP_PUBLISHER_PUBLIC_HEX "{protocol.public_hex(publisher)}"\n'
            f'#define RASP_CLIENT_PRIVATE_HEX "{protocol.private_hex(client)}"\n',
            encoding="ascii",
        )
        header.chmod(0o600)
        command = [
            "gcc",
            "-shared",
            "-fPIC",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-O2",
            "-fvisibility=hidden",
            "-pthread",
            "-Wl,-z,relro,-z,now",
            "-I",
            str(working),
            str(_runtime_source()),
            "-o",
            str(stage / RUNTIME_NAME),
            "-lcrypto",
            "-lssl",
            "-ldl",
        ]
        build = subprocess.run(command, capture_output=True, text=True, check=False, timeout=60)
        if build.returncode != 0:
            raise ValueError("runtime compilation failed (GCC and OpenSSL headers required): " + build.stderr[-4000:])
        binary.add_library(DEPENDENCY)
        executable = stage / source.name
        binary.write(str(executable))
        executable.chmod(stat.S_IMODE(source.stat().st_mode) & 0o777)
        rebuilt = lief.ELF.parse(str(executable))
        if rebuilt is None or DEPENDENCY not in rebuilt.libraries:
            raise ValueError("ELF rewrite did not preserve runtime dependency")
        values = {
            "v": "rasp-elf-manifest-1",
            "build": secrets.token_hex(32),
            "exe": protocol.sha256_file(executable),
            "runtime": protocol.sha256_file(stage / RUNTIME_NAME),
            "endpoint": endpoint,
            "interval_ms": str(interval_ms),
            "client_public": protocol.public_hex(client),
            "server_public": server_public,
        }
        (stage / "rasp.manifest").write_bytes(protocol.sign_message(values, publisher))
        report: dict[str, object] = {
            "format": "rasp-elf-bundle-1",
            "executable": source.name,
            "build": values["build"],
            "input_sha256": input_hash,
            "output_sha256": values["exe"],
            "runtime_sha256": values["runtime"],
            "architecture": "linux-x86_64-glibc",
            "evidence_trust": "software",
            "instrumentation": ["constructor", "periodic_monitor", "connect", "optional_checkpoint"],
            "original_libraries": original_libraries,
            "injected_dependency": DEPENDENCY,
            "backend_enabled": endpoint != "",
            "publisher_public": protocol.public_hex(publisher),
        }
        (stage / "report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        _publish(stage, output)
    return report


def inspect(bundle: pathlib.Path, publisher_public: str) -> dict[str, object]:
    report_path = bundle / "report.json"
    report = json.loads(protocol.read_regular_file(report_path, 16384))
    if isinstance(report, dict) is False:
        raise ValueError("invalid inspection report")
    name = report.get("executable")
    if isinstance(name, str) is False or name in ("", ".", "..") or pathlib.Path(name).name != name:
        raise ValueError("invalid executable name")
    manifest_path = bundle / "rasp.manifest"
    manifest = protocol.validate_manifest(
        protocol.read_regular_file(manifest_path, protocol.MAX_MESSAGE_BYTES), publisher_public
    )
    executable = bundle / name
    if (
        protocol.sha256_file(executable) != manifest["exe"]
        or protocol.sha256_file(bundle / RUNTIME_NAME) != manifest["runtime"]
    ):
        raise ValueError("bundle hash mismatch")
    binary = lief.ELF.parse(str(executable))
    if binary is None or DEPENDENCY not in binary.libraries:
        raise ValueError("missing injected dependency")
    return {
        "verified": True,
        "build": manifest["build"],
        "executable": name,
        "output_sha256": manifest["exe"],
        "runtime_sha256": manifest["runtime"],
        "backend_enabled": manifest["endpoint"] != "",
        "evidence_trust": "software",
        "instrumentation": ["constructor", "periodic_monitor", "connect", "optional_checkpoint"],
    }
