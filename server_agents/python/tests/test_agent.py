"""Real process/file/SQLite sink tests, with request and tenant isolation."""

from __future__ import annotations

import asyncio
import pathlib
import pickle
import socket
import sqlite3
import subprocess
import sys
import tempfile
import unittest

from rasp_agent import agent


class AgentTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        agent.install()
        agent.install()

    def testProcess_whenRequestStartsUnapprovedExecutable_blocksBeforeExecution(
        self,
    ) -> None:
        with (
            agent.request_scope("tenant-a", "request-1", (), agent.Policy()) as scope,
            self.assertRaises(agent.Blocked) as caught,
        ):
            subprocess.run([sys.executable, "-c", "raise SystemExit(0)"], check=True)
        self.assertEqual(caught.exception.event.sink, "process")
        self.assertEqual(scope.events[0].tenant_id, "tenant-a")

    def testProcess_whenExecutableApproved_runs(self) -> None:
        policy = agent.Policy(
            allowed_executables=(str(pathlib.Path(sys.executable).resolve()),)
        )
        with agent.request_scope("tenant-a", "request-1", (), policy):
            completed = subprocess.run(
                [sys.executable, "-c", "print(7)"], capture_output=True, check=True
            )
        self.assertEqual(completed.stdout, b"7\n")

    def testProcess_whenRelativeExecutable_matchesNoAbsoluteAllowlist(self) -> None:
        with (
            agent.request_scope("tenant", "request", (), agent.Policy()),
            self.assertRaises(agent.Blocked) as caught,
        ):
            subprocess.run(["python3", "-c", "print(1)"], check=True)
        self.assertEqual(caught.exception.event.reason, "relative_executable")

    def testFile_whenOutsideAllowedRoots_deniesAndDoesNotCreate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            allowed = pathlib.Path(directory) / "allowed"
            allowed.mkdir()
            forbidden = pathlib.Path(directory) / "forbidden"
            with agent.request_scope(
                "tenant-a", "request-1", (), agent.Policy(allowed_roots=(str(allowed),))
            ):
                with self.assertRaises(agent.Blocked):
                    forbidden.write_text("sensitive")
                (allowed / "ok").write_text("ok")
            self.assertFalse(forbidden.exists())
            self.assertEqual((allowed / "ok").read_text(), "ok")

    def testFile_whenSymlinkEscapesRoot_denies(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / "allowed").mkdir()
            (root / "secret").write_text("secret")
            (root / "allowed" / "link").symlink_to(root / "secret")
            with (
                agent.request_scope(
                    "tenant",
                    "request",
                    (),
                    agent.Policy(allowed_roots=(str(root / "allowed"),)),
                ),
                self.assertRaises(agent.Blocked),
            ):
                (root / "allowed" / "link").read_text()

    def testSql_whenRequestInputInterpolated_blocksButParametersWork(self) -> None:
        database = sqlite3.connect(":memory:")
        self.addCleanup(database.close)
        database.execute("create table users (name text)")
        value = "' OR 1=1 --"
        with agent.request_scope("tenant", "request", (value,), agent.Policy()):
            for execute in [
                database.execute,
                database.cursor().execute,
                database.executescript,
            ]:
                with self.assertRaises(agent.Blocked):
                    execute("select * from users where name='" + value + "'")
            database.execute("insert into users values (?)", (value,))
            self.assertEqual(
                database.execute(
                    "select name from users where name=?", (value,)
                ).fetchone(),
                (value,),
            )

    def testDeserialization_whenPickleResolvesGlobal_denies(self) -> None:
        data = pickle.dumps(pathlib.Path("/tmp/private"))
        with (
            agent.request_scope("tenant", "request", (), agent.Policy()),
            self.assertRaises(agent.Blocked),
        ):
            pickle.loads(data)

    def testNetwork_whenPrivateAddressRequested_deniesBeforeConnect(self) -> None:
        with (
            socket.socket() as connection,
            agent.request_scope("tenant", "request", (), agent.Policy()),
            self.assertRaises(agent.Blocked),
        ):
            connection.connect(("127.0.0.1", 9))

    def testScope_whenConcurrentRequests_eventsRemainIsolated(self) -> None:
        async def request(tenant: str) -> str:
            with agent.request_scope(
                tenant, "request", ("attack",), agent.Policy()
            ) as scope:
                await asyncio.sleep(0)
                with self.assertRaises(agent.Blocked):
                    agent.check_sql("select attack")
                return scope.events[0].tenant_id

        async def run() -> list[str]:
            return list(await asyncio.gather(request("a"), request("b")))

        self.assertEqual(asyncio.run(run()), ["a", "b"])

    def testScope_whenEnded_doesNotAffectBackgroundWork(self) -> None:
        with agent.request_scope("tenant", "request", (), agent.Policy()):
            pass
        self.assertEqual(
            subprocess.check_output([sys.executable, "-c", "print(3)"]), b"3\n"
        )
