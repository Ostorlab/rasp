"""PR feedback regressions exercise real, temporary sinks."""
import importlib
import os
import pathlib
import shutil
import sqlite3
import subprocess
import tempfile
import unittest

from rasp_agent import agent


class ReviewTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        agent.install()

    def testProcess_whenShellAllowlisted_stillDeniesShellTrue(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            marker = pathlib.Path(directory) / "marker"
            with agent.request_scope("tenant", "shell", (), agent.Policy(allowed_executables=("/bin/sh",))):
                with self.assertRaises(agent.Blocked) as denied:
                    subprocess.run(f"touch {marker}", shell=True, check=True)
            self.assertEqual(denied.exception.event.reason, "shell_execution")
            self.assertFalse(marker.exists())

    def testSql_whenShortSourcesOrLiteralMatch_allowsParameterizedQuery(self) -> None:
        with sqlite3.connect(":memory:") as database:
            with agent.request_scope("tenant", "sql", ("1", "id", "alice", "user"), agent.Policy()):
                self.assertEqual(database.execute("select ? as user_name, 'alice' limit 10", ("1",)).fetchone(), ("1", "alice"))

    def testImport_whenLazyStdlibRead_allowsButDirectReadDenied(self) -> None:
        module = importlib.import_module("colorsys")
        with agent.request_scope("tenant", "import", (), agent.Policy()):
            module = importlib.reload(module)
            with self.assertRaises(agent.Blocked):
                pathlib.Path(module.__file__).read_text()

    def testFile_whenSymlinkThenParent_deniesKernelResolvedEscape(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            allowed = root / "allowed"
            allowed.mkdir()
            (root / "outside" / "sub").mkdir(parents=True)
            (root / "outside" / "secret").write_text("secret")
            (allowed / "link").symlink_to(root / "outside" / "sub")
            path = str(allowed / "link") + "/../secret"
            self.assertEqual(os.path.realpath(path), str(root / "outside" / "secret"))
            with agent.request_scope("tenant", "traversal", (), agent.Policy(allowed_roots=(str(allowed),))):
                with self.assertRaises(agent.Blocked):
                    pathlib.Path(path).read_text()

    def testFile_whenMetadataOperationsEscape_deniesBeforeMutation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            allowed = root / "allowed"
            allowed.mkdir()
            outside = root / "outside"
            outside.mkdir()
            secret = outside / "secret"
            secret.write_text("secret")
            safe = allowed / "safe"
            safe.write_text("safe")
            operations = [
                lambda: os.remove(secret), lambda: os.rename(secret, allowed / "moved"),
                lambda: os.rename(safe, outside / "moved"), lambda: os.listdir(outside),
                lambda: os.scandir(outside), lambda: shutil.rmtree(outside),
                lambda: shutil.copyfile(secret, allowed / "copy"),
                lambda: shutil.copyfile(safe, outside / "copy"),
                lambda: os.symlink(secret, allowed / "link"),
                lambda: os.symlink("../outside/secret", allowed / "link"),
                lambda: os.symlink(safe, outside / "link"),
            ]
            with agent.request_scope("tenant", "files", (), agent.Policy(allowed_roots=(str(allowed),))) as scope:
                for operation in operations:
                    with self.subTest(operation=operations.index(operation)), self.assertRaises(agent.Blocked):
                        operation()
            self.assertEqual(len(scope.events), len(operations))
            self.assertEqual(secret.read_text(), "secret")
            self.assertEqual(safe.read_text(), "safe")

    def testFile_whenRelativeDirFd_deniesAmbiguousPaths(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "secret").write_text("secret")
            descriptor = os.open(directory, os.O_RDONLY)
            try:
                with agent.request_scope("tenant", "dirfd", (), agent.Policy(allowed_roots=(directory,))):
                    for operation in [lambda: os.unlink("secret", dir_fd=descriptor), lambda: os.rename("secret", "moved", src_dir_fd=descriptor, dst_dir_fd=descriptor), lambda: os.symlink("secret", "link", dir_fd=descriptor)]:
                        with self.assertRaises(agent.Blocked):
                            operation()
            finally:
                os.close(descriptor)
            self.assertTrue((root / "secret").exists())

    def testFile_whenOperationsStayWithinRoots_allowsMutations(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            with agent.request_scope("tenant", "safe-files", (), agent.Policy(allowed_roots=(directory,))):
                (root / "source").write_text("safe")
                shutil.copyfile(root / "source", root / "copy")
                os.rename(root / "copy", root / "renamed")
                os.symlink("source", root / "link")
                self.assertEqual((root / "link").read_text(), "safe")
                self.assertIn("renamed", os.listdir(root))
                os.unlink(root / "renamed")
                os.unlink(root / "link")
            self.assertEqual((root / "source").read_text(), "safe")

    def testEvents_whenManyDenials_retainsOnlyBoundedRedactedEvents(self) -> None:
        with agent.request_scope("tenant", "events", ("attack",), agent.Policy()) as scope:
            for _ in range(105):
                with self.assertRaises(agent.Blocked):
                    agent.check_sql("select attack")
        self.assertEqual(len(scope.events), 100)
        self.assertEqual(set(vars(scope.events[0])), {"tenant_id", "request_id", "sink", "reason"})
