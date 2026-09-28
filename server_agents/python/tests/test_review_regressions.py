"""PR feedback regressions exercise real, temporary sinks."""
import importlib
import os
import pathlib
import pkgutil
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest

from rasp_agent import agent


class ReviewTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        agent.install()

    def testPolicy_whenDeniedSinkMisspelled_raisesValueError(self) -> None:
        with self.assertRaisesRegex(ValueError, "supported sink"):
            agent.Policy(denied_sinks=frozenset({"deserialisation"}))

    def testSqlite_whenSubclassReturnsStockCursor_rejectsFactoryBeforeSql(self) -> None:
        class BypassConnection(agent.Connection):
            def cursor(self, factory: type[sqlite3.Cursor] = sqlite3.Cursor) -> sqlite3.Cursor:
                return sqlite3.Connection.cursor(self, factory)

        with (
            agent.request_scope("tenant", "sqlite-factory", (), agent.Policy(denied_sinks=frozenset({"sql"}))),
            self.assertRaisesRegex(ValueError, "custom connection factories"),
        ):
            database = sqlite3.connect(":memory:", factory=BypassConnection)
            try:
                database.cursor().execute("create table forbidden (name text)")
            finally:
                database.close()

    def testSqlite_whenDefaultFactoryAndSqlDenied_blocksBeforeMutation(self) -> None:
        with sqlite3.connect(":memory:") as database:
            with (
                agent.request_scope("tenant", "sqlite-default", (), agent.Policy(denied_sinks=frozenset({"sql"}))),
                self.assertRaises(agent.Blocked),
            ):
                database.cursor().execute("create table forbidden (name text)")
            self.assertEqual(database.execute("select name from sqlite_master where name='forbidden'").fetchall(), [])

    def testSqlite_whenCursorSubclassOverridesExecute_rejectsFactoryBeforeSql(self) -> None:
        class BypassCursor(agent.Cursor):
            def execute(self, sql: str, parameters: tuple[object, ...] = ()) -> sqlite3.Cursor:
                return sqlite3.Cursor.execute(self, sql, parameters)

        with (
            sqlite3.connect(":memory:") as database,
            agent.request_scope("tenant", "sqlite-cursor", (), agent.Policy(denied_sinks=frozenset({"sql"}))),
            self.assertRaisesRegex(ValueError, "custom cursor factories"),
        ):
            database.cursor(factory=BypassCursor).execute("create table forbidden (name text)")

    def testSqlite_whenExactConnectionFactoryGiven_preservesDefaultInterception(self) -> None:
        for factory in (sqlite3.Connection, agent.Connection):
            with self.subTest(factory=factory), sqlite3.connect(":memory:", factory=factory) as database:
                self.assertEqual(database.execute("select ?", (7,)).fetchone(), (7,))
                with (
                    agent.request_scope("tenant", "exact-factory", (), agent.Policy(denied_sinks=frozenset({"sql"}))),
                    self.assertRaises(agent.Blocked),
                ):
                    database.execute("create table forbidden (name text)")

    def testSqlite_whenPositionalFactoryGiven_enforcesExactFactoryContract(self) -> None:
        class CustomConnection(agent.Connection):
            """Custom subclasses cannot be trusted to preserve interception."""

        for factory in (sqlite3.Connection, agent.Connection):
            with self.subTest(factory=factory), sqlite3.connect(":memory:", 5.0, 0, "DEFERRED", True, factory) as database:
                self.assertEqual(database.execute("select ?", (7,)).fetchone(), (7,))
                with (
                    agent.request_scope("tenant", "positional-factory", (), agent.Policy(denied_sinks=frozenset({"sql"}))),
                    self.assertRaises(agent.Blocked),
                ):
                    database.cursor().execute("create table forbidden (name text)")
        with self.assertRaisesRegex(ValueError, "custom connection factories"):
            sqlite3.connect(":memory:", 5.0, 0, "DEFERRED", True, CustomConnection)

    def testProcess_whenShellAllowlisted_stillDeniesShellTrue(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            marker = pathlib.Path(directory) / "marker"
            with (
                agent.request_scope("tenant", "shell", (), agent.Policy(allowed_executables=("/bin/sh",))),
                self.assertRaises(agent.Blocked) as denied,
            ):
                subprocess.run(f"touch {marker}", shell=True, check=True)
            self.assertEqual(denied.exception.event.reason, "shell_execution")
            self.assertFalse(marker.exists())

    def testSql_whenShortSourcesOrLiteralMatch_allowsParameterizedQuery(self) -> None:
        with (
            sqlite3.connect(":memory:") as database,
            agent.request_scope("tenant", "sql", ("1", "id", "alice", "user"), agent.Policy()),
        ):
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
            with (
                agent.request_scope("tenant", "traversal", (), agent.Policy(allowed_roots=(str(allowed),))),
                self.assertRaises(agent.Blocked),
            ):
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

    def testImport_whenColdModuleOutsideRoots_allowsOnlyImportReads(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "rasp_cold_probe.py").write_text("VALUE = 123\n")
            sys.path.insert(0, directory)
            try:
                with agent.request_scope("tenant", "cold-import", (), agent.Policy()) as scope:
                    module = importlib.import_module("rasp_cold_probe")
                    self.assertEqual(module.VALUE, 123)
                    self.assertEqual(len(scope.events), 0)
                    with self.assertRaises(agent.Blocked):
                        os.listdir(directory)
                self.assertFalse((root / "__pycache__").exists())
            finally:
                sys.path.remove(directory)
                sys.modules.pop("rasp_cold_probe", None)

    def testImport_whenLoaderReadsResourceOrTraversal_stillEnforcesRoots(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            package = root / "rasp_resource_probe"
            package.mkdir()
            (package / "__init__.py").write_text("VALUE = 123\n")
            (root / "secret").write_text("private-content")
            sys.path.insert(0, directory)
            try:
                module = importlib.import_module("rasp_resource_probe")
                with agent.request_scope("tenant", "resource", (), agent.Policy()) as scope:
                    with self.assertRaises(agent.Blocked):
                        pkgutil.get_data("rasp_resource_probe", "../secret")
                    with self.assertRaises(agent.Blocked):
                        module.__loader__.get_data(module.__file__)
                    with self.assertRaises(agent.Blocked):
                        module.__loader__.get_code("rasp_resource_probe")
                self.assertGreaterEqual(len(scope.events), 3)
                self.assertTrue(all(event.sink == "file" for event in scope.events))
            finally:
                sys.path.remove(directory)
                sys.modules.pop("rasp_resource_probe", None)
