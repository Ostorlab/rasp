"""Real harmless child processes verify launcher policy, never compiler efficacy."""

from __future__ import annotations

import hashlib
import io
import json
import os
import pathlib
import py_compile
import shutil
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

    def run_command(
        self, digest: str, command: list[str]
    ) -> subprocess.CompletedProcess[str]:
        """Run an actual driver diagnostic or harmless root-import child."""
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
                *command,
            ],
            cwd=self.root,
            env=self.environment,
            capture_output=True,
            text=True,
            check=False,
        )

    def testLauncher_whenDriverRewritesArguments_refusesBeforeActualDriver(
        self,
    ) -> None:
        clang = shutil.which("clang")
        if clang is None and pathlib.Path("/usr/lib/llvm-20/bin/clang").is_file():
            clang = "/usr/lib/llvm-20/bin/clang"
        assert clang is not None, "real Clang command-printing control requires Clang"
        directory = tempfile.TemporaryDirectory(prefix="omvll-driver-")
        self.addCleanup(directory.cleanup)
        plugin_bytes = self.plugin.read_bytes()
        self.plugin = pathlib.Path(directory.name) / "identity-plugin"
        self.plugin.write_bytes(plugin_bytes)
        digest = self.freeze()
        command = [
            clang,
            "-###",
            "-x",
            "c",
            "-c",
            os.devnull,
            f"-fpass-plugin={self.plugin}",
        ]
        baseline = self.run_command(digest, command)
        assert baseline.returncode == 0, baseline.stderr
        assert f"-fpass-plugin={self.plugin}" in baseline.stderr
        self.environment["CCC_OVERRIDE_OPTIONS"] = f"x-fpass-plugin={self.plugin}"
        direct = subprocess.run(
            command, env=self.environment, capture_output=True, text=True, check=False
        )
        assert direct.returncode == 0, direct.stderr
        assert "Deleting argument -fpass-plugin=" in direct.stderr
        assert '"-fpass-plugin=' not in direct.stderr
        guarded = self.run_command(digest, command)
        assert_refused(guarded)
        assert "Deleting argument" not in guarded.stderr

    def testLauncher_whenDriverConfigEnvironmentInherited_neutralizesDefaults(
        self,
    ) -> None:
        digest = self.freeze()
        self.environment["CLANG_NO_DEFAULT_CONFIG"] = ""
        result = self.run_command(
            digest,
            [
                sys.executable,
                "-c",
                "import os; print(os.environ['CLANG_NO_DEFAULT_CONFIG'])",
                f"-fpass-plugin={self.plugin}",
            ],
        )
        assert result.returncode == 0, result.stderr
        assert result.stdout == "1\n"
        for name in ("CL", "_CL_"):
            self.environment[name] = "/clang:-fpass-plugin=unbound"
            assert_refused(self.launch(digest))
            self.environment.pop(name)

    def testLauncher_whenRootPackageAppears_refusesWithoutRunningIt(self) -> None:
        self.config.write_text('IDENTITY="captured source"\n')
        digest = self.freeze()
        code = (
            "import sys,pathlib,importlib,json; p=pathlib.Path(sys.argv[1]); "
            "sys.path.insert(0,str(p.parent)); m=importlib.import_module(p.stem); "
            "print(json.dumps({'loaded':m.__file__,'identity':m.IDENTITY}))"
        )
        command = [
            sys.executable,
            "-B",
            "-c",
            code,
            str(self.config),
            f"-fpass-plugin={self.plugin}",
        ]
        ordinary = self.run_command(digest, command)
        assert ordinary.returncode == 0, ordinary.stderr
        assert json.loads(ordinary.stdout) == {
            "loaded": str(self.config),
            "identity": "captured source",
        }
        package = self.config.with_suffix("")
        package.mkdir()
        marker = self.root / "package-executed"
        (package / "__init__.py").write_text(
            f"from pathlib import Path; Path({str(marker)!r}).touch(); IDENTITY='unbound package'\n"
        )
        assert_refused(self.run_command(digest, command))
        assert marker.exists() is False

    def testLauncher_whenNativeRootOrHelperAppears_refusesAllRelevantSuffixes(
        self,
    ) -> None:
        digest = self.freeze()
        for stem in (self.config.stem, "omvll_seed"):
            for suffix in (".so", ".abi3.so", ".cpython-310-darwin.so", ".pyc"):
                with self.subTest(stem=stem, suffix=suffix):
                    candidate = self.root / (stem + suffix)
                    candidate.write_bytes(b"non-executable loader ambiguity fixture")
                    assert_refused(self.launch(digest))
                    candidate.unlink()
        helper_package = self.root / "omvll_seed"
        helper_package.mkdir()
        (helper_package / "__init__.py").write_text(
            "raise RuntimeError('must not execute')\n"
        )
        assert_refused(self.launch(digest))

    def testLauncher_whenRootStemIsUnsupported_refusesDuringCapture(self) -> None:
        for name in (
            "sys.py",
            "pathlib.py",
            "omvll.py",
            "omvll_seed.py",
            "json.py",
            "_sha256.py",
            "audioop.py",
            "time.py",
            "dotted.config.py",
            "config.pyc",
        ):
            with self.subTest(name=name):
                self.state.unlink(missing_ok=True)
                config = self.root / name
                config.write_text(
                    "raise RuntimeError('validation must not execute config')\n"
                )
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
                        str(config),
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
                assert self.state.exists() is False

    def testLauncher_whenSharedHelperPackageShadowsBootstrap_refusesBeforeImport(
        self,
    ) -> None:
        bootstrap = self.root / "bootstrap"
        bootstrap.mkdir()
        for name in ("omvll_launcher.py", "omvll_seed.py"):
            shutil.copyfile(SCRIPT.with_name(name), bootstrap / name)
        package = bootstrap / "omvll_seed"
        package.mkdir()
        marker = self.root / "helper-executed"
        (package / "__init__.py").write_text(
            f"from pathlib import Path; Path({str(marker)!r}).touch()\n"
        )
        result = subprocess.run(
            [sys.executable, "-E", "-s", "-B", str(bootstrap / SCRIPT.name), "--help"],
            cwd=self.root,
            env=self.environment,
            capture_output=True,
            text=True,
            check=False,
        )
        assert_refused(result)
        assert marker.exists() is False

    def testLauncher_whenExplicitDefaultSeedPairProvided_refusesLaunchAndRetry(
        self,
    ) -> None:
        digest = self.freeze(None, "default")
        self.environment.update(RASP_OMVLL_SEED="1", RASP_OMVLL_SEED_MODE="default")
        assert_refused(self.launch(digest))
        retry = subprocess.run(
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
        assert_refused(retry)

    def testLauncher_whenBootstrapHelperBytecodeIsStale_readsOwnedSource(self) -> None:
        bootstrap = self.root / "bytecode-bootstrap"
        bootstrap.mkdir()
        for name in ("omvll_launcher.py", "omvll_seed.py"):
            shutil.copyfile(SCRIPT.with_name(name), bootstrap / name)
        helper = bootstrap / "omvll_seed.py"
        source = helper.read_bytes()
        marker = self.root / "stale-helper-executed"
        poison = f"open({str(marker)!r}, 'w').close()\n".encode()
        helper.write_bytes(poison + b"#" * (len(source) - len(poison)))
        info = helper.stat()
        py_compile.compile(str(helper), doraise=True)
        helper.write_bytes(source)
        os.utime(helper, ns=(info.st_atime_ns, info.st_mtime_ns))
        result = subprocess.run(
            [sys.executable, "-E", "-s", "-B", str(bootstrap / SCRIPT.name), "--help"],
            cwd=self.root,
            env=self.environment,
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        assert marker.exists() is False

    def testLauncher_whenHelperIsPreimported_refusesCachedModule(self) -> None:
        code = (
            "import sys,pathlib,runpy; sys.modules['omvll_seed']=pathlib; "
            "sys.argv=[sys.argv[1],'--help']; runpy.run_path(sys.argv[0],run_name='__main__')"
        )
        result = subprocess.run(
            [sys.executable, "-E", "-s", "-B", "-c", code, str(SCRIPT)],
            cwd=self.root,
            env=self.environment,
            capture_output=True,
            text=True,
            check=False,
        )
        assert_refused(result)
