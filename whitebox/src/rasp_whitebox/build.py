"""Compile a key-specialized Linux executable without retaining its sources."""

import os
import pathlib
import secrets
import shutil
import subprocess
import tempfile

from rasp_whitebox import tables


class Error(Exception):
    """The native build could not be completed."""


def build_binary(
    *, key: bytes, output: pathlib.Path, seed: bytes | None = None
) -> pathlib.Path:
    """Generate encoded AES tables and compile a new executable exclusively.

    The optional diversification seed supports reproducible research only.
    It is not a security factor. The key is never passed to a subprocess.
    """
    if output.exists() is True or output.is_symlink() is True:
        raise Error(f"output already exists: {output}")
    if len(key) != 16:
        raise Error("key must contain exactly 16 raw bytes")
    if seed is not None and len(seed) != 32:
        raise Error("diversification seed must contain exactly 32 bytes")
    compiler = shutil.which("g++")
    if compiler is None:
        raise Error("g++ is required to build the Linux executable")
    table_data = tables.generate(key, secrets.token_bytes(32) if seed is None else seed)
    output = output.absolute()
    output.parent.mkdir(parents=True, exist_ok=True)
    template = pathlib.Path(__file__).parent / "native" / "main.cpp"
    try:
        with tempfile.TemporaryDirectory(
            prefix=".whitebox-", dir=output.parent
        ) as name:
            folder = pathlib.Path(name)
            (folder / "whitebox_aes.h").write_text(tables.emit_header(table_data))
            shutil.copyfile(template, folder / "main.cpp")
            executable = folder / "whitebox"
            result = subprocess.run(
                [
                    compiler,
                    "-std=c++20",
                    "-O2",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    "-Wpedantic",
                    "-fvisibility=hidden",
                    "-static-libstdc++",
                    "-static-libgcc",
                    "-s",
                    "-Wl,-z,relro,-z,now,-z,noexecstack",
                    str(folder / "main.cpp"),
                    "-o",
                    str(executable),
                ],
                capture_output=True,
                text=True,
                timeout=180,
                check=False,
            )
            if result.returncode != 0:
                raise Error(f"compiler failed: {result.stderr[-4000:]}")
            executable.chmod(0o700)
            os.link(executable, output)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise Error(f"native build failed: {error}") from error
    return output
