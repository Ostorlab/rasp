"""Freeze iOS compile inputs and refuse drift at the actual O-MVLL load boundary.

This local build policy is not an artifact sidecar or a trust/efficacy claim.
The compiler still runs in its original working directory with unchanged argv.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import subprocess
import sys
import tarfile
import tempfile
import typing

import omvll_seed


class Error(ValueError):
    """An input no longer agrees with the configured build policy."""


class FrozenPolicy(typing.TypedDict):
    """Configure-owned document authenticated by the generated launch command."""

    seed: str
    mode: str
    plugin: str
    config: str
    pythonpath: str
    yaml: str
    files: dict[str, str]


def file_digest(path: pathlib.Path) -> str:
    """Hash the actual file bytes rather than its path or archive label."""
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_policy(state: pathlib.Path, expected_digest: str) -> FrozenPolicy:
    """Validate the configure-owned document before interpreting its fields."""
    if state.stat().st_size > 16384 or file_digest(state) != expected_digest:
        raise Error("frozen policy identity changed; use a new build directory")
    return typing.cast(FrozenPolicy, json.loads(state.read_bytes()))


def check_environment(policy: FrozenPolicy) -> None:
    """Allow absent build-shell settings; supplied settings must agree exactly."""
    seed = os.environ.get("RASP_OMVLL_SEED")
    if seed is not None and omvll_seed.parse_seed(seed) != int(policy["seed"]):
        raise Error("inherited seed conflicts with frozen policy")
    mode = os.environ.get("RASP_OMVLL_SEED_MODE")
    if mode is not None and mode != policy["mode"]:
        raise Error("inherited seed mode conflicts with frozen policy")
    for name, expected in (
        ("OMVLL_CONFIG", policy["config"]),
        ("OMVLL_PYTHONPATH", policy["pythonpath"]),
    ):
        value = os.environ.get(name)
        if value is not None and str(pathlib.Path(value).resolve()) != expected:
            raise Error("inherited O-MVLL path conflicts with frozen policy")


def freeze(arguments: argparse.Namespace) -> int:
    """Capture inputs once; reconfiguration preserves the build directory's seed."""
    state = pathlib.Path(arguments.state)
    if state.exists() is True or arguments.previous_sha256 != "":
        policy = read_policy(state, arguments.previous_sha256)
        check_environment(policy)
        seed = omvll_seed.parse_policy(
            None if policy["mode"] == "default" else policy["seed"], policy["mode"]
        )
    else:
        seed = omvll_seed.parse_policy(
            os.environ.get("RASP_OMVLL_SEED"), os.environ.get("RASP_OMVLL_SEED_MODE")
        )
    config = pathlib.Path(arguments.config).resolve(strict=True)
    plugin = pathlib.Path(arguments.plugin).resolve(strict=True)
    pythonpath = pathlib.Path(arguments.pythonpath).resolve(strict=True)
    if pythonpath.is_dir() is False:
        raise Error("Python standard library path is not a directory")
    plugin_digest = file_digest(plugin)
    if arguments.archive is not None:
        with tarfile.open(arguments.archive) as archive:
            stream = archive.extractfile("omvll-xcode.dylib")
            if stream is None:
                raise Error("plugin archive member missing")
            with stream:
                archived = hashlib.sha256()
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    archived.update(chunk)
        if archived.hexdigest() != plugin_digest:
            raise Error("extracted plugin differs from the selected archive")
    yaml = pathlib.Path(arguments.yaml).absolute()
    policy = {
        "seed": str(seed.seed),
        "mode": seed.mode,
        "config": str(config),
        "plugin": str(plugin),
        "pythonpath": str(pythonpath),
        "yaml": str(yaml),
        "files": {},
    }
    check_environment(policy)
    yaml.write_text(
        f"OMVLL_PYTHONPATH: {json.dumps(str(pythonpath))}\n"
        f"OMVLL_CONFIG: {json.dumps(str(config))}\n",
        encoding="utf-8",
    )
    policy["files"] = {
        str(path): file_digest(path)
        for path in (
            config,
            plugin,
            yaml,
            pathlib.Path(__file__),
            pathlib.Path(omvll_seed.__file__),
        )
    }
    state.write_text(json.dumps(policy, sort_keys=True) + "\n", encoding="utf-8")
    print(file_digest(state))
    return 0


def run(arguments: argparse.Namespace) -> int:
    """Check nearest YAML, identities and environment before launching the child."""
    state = pathlib.Path(arguments.state)
    policy = read_policy(state, arguments.sha256)
    check_environment(policy)
    for name, expected in policy["files"].items():
        if file_digest(pathlib.Path(name)) != expected:
            raise Error("configured file content changed; reconfigure before compiling")
    cwd = pathlib.Path.cwd()
    effective_yaml = next(
        (
            directory / "omvll.yml"
            for directory in (cwd, *cwd.parents)
            if (directory / "omvll.yml").exists()
        ),
        None,
    )
    if (
        effective_yaml is None
        or effective_yaml.resolve() != pathlib.Path(policy["yaml"]).resolve()
    ):
        raise Error("effective omvll.yml differs from the configured file")
    command: list[str] = arguments.command
    if len(command) > 0 and command[0] == "--":
        command = command[1:]
    plugins = [
        value.split("=", 1)[1]
        for value in command
        if value.startswith("-fpass-plugin=")
    ]
    if (
        len(command) == 0
        or len(plugins) != 1
        or str(pathlib.Path(plugins[0]).resolve()) != policy["plugin"]
    ):
        raise Error("compiler command must load exactly the captured plugin")
    if any(
        value.startswith(("@", "-working-directory", "--config"))
        or value == "-fpass-plugin"
        for value in command
    ):
        raise Error("indirect compiler settings are unsupported by the frozen launcher")
    environment = dict(os.environ)
    for name in ("PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP"):
        environment.pop(name, None)
    environment.update(
        RASP_OMVLL_SEED_MODE=policy["mode"],
        OMVLL_CONFIG=policy["config"],
        OMVLL_PYTHONPATH=policy["pythonpath"],
        PYTHONDONTWRITEBYTECODE="1",
    )
    if policy["mode"] == "default":
        environment.pop("RASP_OMVLL_SEED", None)
    else:
        environment["RASP_OMVLL_SEED"] = policy["seed"]
    # An empty per-invocation cache avoids importing stale bytecode for hashed source.
    with tempfile.TemporaryDirectory(prefix="omvll-python-", dir=state.parent) as cache:
        environment["PYTHONPYCACHEPREFIX"] = cache
        return subprocess.run(command, env=environment, check=False).returncode


def main() -> int:
    """Run configure capture or one guarded compile without exposing input values."""
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="action", required=True)
    capture = commands.add_parser("freeze")
    for name in ("state", "yaml", "config", "plugin", "pythonpath"):
        capture.add_argument(f"--{name}", required=True)
    capture.add_argument("--archive")
    capture.add_argument("--previous-sha256", default="")
    compile_command = commands.add_parser("run")
    compile_command.add_argument("--state", required=True)
    compile_command.add_argument("--sha256", required=True)
    compile_command.add_argument("command", nargs=argparse.REMAINDER)
    arguments = parser.parse_args()
    try:
        return freeze(arguments) if arguments.action == "freeze" else run(arguments)
    except (OSError, ValueError, KeyError, tarfile.TarError):
        print(
            "O-MVLL launcher refused inconsistent or unavailable build inputs",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    sys.exit(main())
