"""Real harmless child processes verify launcher policy, never compiler efficacy."""

from __future__ import annotations

import hashlib
import io
import json
import os
import pathlib
import subprocess
import sys
import tarfile
import tempfile
import unittest

SCRIPT = pathlib.Path(__file__).resolve().parents[1] / "omvll_launcher.py"
CHILD = (
    "import json,os,sys; print(json.dumps({'argv':sys.argv[1:],"
    "'seed':os.environ.get('RASP_OMVLL_SEED'),"
    "'mode':os.environ.get('RASP_OMVLL_SEED_MODE'),"
    "'config':os.environ.get('OMVLL_CONFIG'),"
    "'pythonpath':os.environ.get('OMVLL_PYTHONPATH'),"
    "'python_injection':os.environ.get('PYTHONPATH')})); sys.exit(7)"
)


def assert_refused(result: subprocess.CompletedProcess[str]) -> None:
    """Require refusal before the harmless child can produce any output."""
    assert result.returncode == 1, result.stderr
    assert result.stdout == "", "child must not execute"
    assert "O-MVLL launcher refused" in result.stderr


class LauncherTest(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory(prefix="omvll policy ")
        self.addCleanup(self.directory.cleanup)
        self.root = pathlib.Path(self.directory.name)
        self.config = self.root / 'config "quoted".py'
        self.config.write_text("# Harmless configuration identity fixture.\n")
        self.plugin = self.root / "plugin identity bytes"
        self.plugin.write_bytes(b"harmless non-executable plugin identity fixture")
        self.pythonpath = self.root / "Lib"
        self.pythonpath.mkdir()
        self.state = self.root / "policy.json"
        self.yaml = self.root / "omvll.yml"
        self.environment = dict(os.environ)
        for name in (
            "RASP_OMVLL_SEED",
            "RASP_OMVLL_SEED_MODE",
            "OMVLL_CONFIG",
            "OMVLL_PYTHONPATH",
        ):
            self.environment.pop(name, None)

    def freeze(self, seed: str | None = "42", mode: str = "diagnostic") -> str:
        environment = dict(self.environment)
        if seed is not None:
            environment["RASP_OMVLL_SEED"] = seed
        environment["RASP_OMVLL_SEED_MODE"] = mode
        result = subprocess.run(
            [
                sys.executable,
                "-E",
                "-s",
                "-B",
                str(SCRIPT),
                "freeze",
                "--state",
                str(self.state),
                "--yaml",
                str(self.yaml),
                "--config",
                str(self.config),
                "--plugin",
                str(self.plugin),
                "--pythonpath",
                str(self.pythonpath),
            ],
            cwd=self.root,
            env=environment,
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        digest = hashlib.sha256(self.state.read_bytes()).hexdigest()
        assert result.stdout.strip() == digest
        return digest

    def launch(
        self,
        digest: str,
        cwd: pathlib.Path | None = None,
        arguments: list[str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                "-E",
                "-s",
                "-B",
                str(SCRIPT),
                "run",
                "--state",
                str(self.state),
                "--sha256",
                digest,
                "--",
                sys.executable,
                "-c",
                CHILD,
                f"-fpass-plugin={self.plugin}",
                "literal space",
                "$(not-a-shell)",
                *(arguments if arguments is not None else []),
            ],
            cwd=self.root if cwd is None else cwd,
            env=self.environment,
            capture_output=True,
            text=True,
            check=False,
        )

    def testLauncher_whenFrozen_preservesArgvSeedAndChildStatus(self) -> None:
        digest = self.freeze()
        self.environment["PYTHONPATH"] = "/untrusted-import-path"
        result = self.launch(digest)
        assert result.returncode == 7, result.stderr
        output = json.loads(result.stdout)
        assert output["seed"] == "42"
        assert output["mode"] == "diagnostic"
        assert output["config"] == str(self.config)
        assert output["pythonpath"] == str(self.pythonpath)
        assert output["python_injection"] is None
        assert output["argv"] == [
            f"-fpass-plugin={self.plugin}",
            "literal space",
            "$(not-a-shell)",
        ]

    def testLauncher_whenDefaultFrozen_suppliesEffectiveDefaultPolicy(self) -> None:
        digest = self.freeze(None, "default")
        result = self.launch(digest)
        assert result.returncode == 7, result.stderr
        output = json.loads(result.stdout)
        assert output["seed"] is None
        assert output["mode"] == "default"

    def testLauncher_whenZeroFrozen_doesNotTreatAsMissing(self) -> None:
        digest = self.freeze("0", "release")
        result = self.launch(digest)
        assert result.returncode == 7, result.stderr
        assert json.loads(result.stdout)["seed"] == "0"

    def testLauncher_whenInheritedPolicyConflicts_refusesBeforeChild(self) -> None:
        digest = self.freeze()
        for name, value in (
            ("RASP_OMVLL_SEED", "43"),
            ("RASP_OMVLL_SEED", "-1"),
            ("RASP_OMVLL_SEED", "2147483648"),
            ("RASP_OMVLL_SEED", "42\n"),
            ("RASP_OMVLL_SEED_MODE", "release"),
            ("RASP_OMVLL_SEED_MODE", ""),
            ("OMVLL_CONFIG", "/different-config"),
            ("OMVLL_PYTHONPATH", "/different-Lib"),
        ):
            with self.subTest(name=name, value=value):
                self.environment[name] = value
                assert_refused(self.launch(digest))
                self.environment.pop(name)

    def testLauncher_whenInheritedPolicyAgrees_executesChild(self) -> None:
        digest = self.freeze()
        self.environment.update(
            RASP_OMVLL_SEED="42",
            RASP_OMVLL_SEED_MODE="diagnostic",
            OMVLL_CONFIG=str(self.config),
            OMVLL_PYTHONPATH=str(self.pythonpath),
        )
        result = self.launch(digest)
        assert result.returncode == 7, result.stderr

    def testLauncher_whenFrozenFileMutates_refusesBeforeChild(self) -> None:
        digest = self.freeze()
        for path in (self.config, self.plugin, self.yaml, self.state):
            with self.subTest(path=path.name):
                original = path.read_bytes()
                path.write_bytes(original + b"\nchanged")
                assert_refused(self.launch(digest))
                path.write_bytes(original)

    def testLauncher_whenNestedYamlShadowsPinnedYaml_refusesBeforeChild(self) -> None:
        digest = self.freeze()
        nested = self.root / "nested"
        nested.mkdir()
        (nested / "omvll.yml").write_bytes(self.yaml.read_bytes())
        assert_refused(self.launch(digest, cwd=nested))

    def testLauncher_whenNestedDirectoryHasNoYaml_usesActualParent(self) -> None:
        digest = self.freeze()
        nested = self.root / "nested"
        nested.mkdir()
        result = self.launch(digest, cwd=nested)
        assert result.returncode == 7, result.stderr

    def testLauncher_whenPinnedYamlMissing_refusesEnvironmentFallback(self) -> None:
        digest = self.freeze()
        self.yaml.unlink()
        assert_refused(self.launch(digest))

    def testLauncher_whenPluginOrWorkingDirectoryInjected_refusesBeforeChild(
        self,
    ) -> None:
        digest = self.freeze()
        for arguments in (
            ["-fpass-plugin=/foreign-plugin"],
            ["-working-directory=/elsewhere"],
            ["-working-directory", "/elsewhere"],
            ["--config=foreign.cfg"],
            ["@foreign.rsp"],
        ):
            with self.subTest(arguments=arguments):
                assert_refused(self.launch(digest, arguments=arguments))

    def testLauncher_whenReconfiguredWithoutEnvironment_preservesFrozenSeed(
        self,
    ) -> None:
        digest = self.freeze("0", "release")
        command = [
            sys.executable,
            "-E",
            "-s",
            "-B",
            str(SCRIPT),
            "freeze",
            "--state",
            str(self.state),
            "--previous-sha256",
            digest,
            "--yaml",
            str(self.yaml),
            "--config",
            str(self.config),
            "--plugin",
            str(self.plugin),
            "--pythonpath",
            str(self.pythonpath),
        ]
        result = subprocess.run(
            command,
            cwd=self.root,
            env=self.environment,
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        assert result.stdout.strip() == digest
        assert self.launch(digest).returncode == 7
        self.environment["RASP_OMVLL_SEED"] = "1"
        assert_refused(
            subprocess.run(
                command,
                cwd=self.root,
                env=self.environment,
                capture_output=True,
                text=True,
                check=False,
            )
        )

    def testLauncher_whenFrozenStateDeleted_refusesSeedResetOnReconfigure(self) -> None:
        digest = self.freeze("42", "release")
        self.state.unlink()
        result = subprocess.run(
            [
                sys.executable,
                "-E",
                "-s",
                "-B",
                str(SCRIPT),
                "freeze",
                "--state",
                str(self.state),
                "--previous-sha256",
                digest,
                "--yaml",
                str(self.yaml),
                "--config",
                str(self.config),
                "--plugin",
                str(self.plugin),
                "--pythonpath",
                str(self.pythonpath),
            ],
            cwd=self.root,
            env=self.environment,
            capture_output=True,
            text=True,
            check=False,
        )
        assert_refused(result)

    def testLauncher_whenArchivedPluginDiffers_refusesStaleExtraction(self) -> None:
        archive = self.root / "reference.tar.xz"
        for data, expected in (
            (self.plugin.read_bytes(), 0),
            (b"different member bytes", 1),
        ):
            with self.subTest(expected=expected):
                if self.state.exists() is True:
                    self.state.unlink()
                with tarfile.open(archive, "w:xz") as target:
                    member = tarfile.TarInfo("omvll-xcode.dylib")
                    member.size = len(data)
                    target.addfile(member, io.BytesIO(data))
                result = subprocess.run(
                    [
                        sys.executable,
                        "-E",
                        "-s",
                        "-B",
                        str(SCRIPT),
                        "freeze",
                        "--state",
                        str(self.state),
                        "--yaml",
                        str(self.yaml),
                        "--config",
                        str(self.config),
                        "--plugin",
                        str(self.plugin),
                        "--pythonpath",
                        str(self.pythonpath),
                        "--archive",
                        str(archive),
                    ],
                    cwd=self.root,
                    env=self.environment,
                    capture_output=True,
                    text=True,
                    check=False,
                )
                assert result.returncode == expected, result.stderr
                if expected == 1:
                    assert self.state.exists() is False
