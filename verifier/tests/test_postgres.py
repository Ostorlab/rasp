"""Real PostgreSQL tests require an isolated migrated database and runtime role."""
from __future__ import annotations

import os
import unittest
import uuid

import psycopg
import psycopg_pool

from rasp_verifier import postgres
from rasp_verifier import storage
from tests import test_storage
from tests import test_trust
from tests import helpers
from rasp_verifier import durable_registry
from rasp_verifier import registry
from rasp_verifier import trust
from rasp_verifier import jose
from rasp_verifier import platform

@unittest.skipUnless(os.environ.get("RASP_TEST_POSTGRES_DSN"), "requires isolated PostgreSQL DSN")
class PostgresStorageTest(test_storage.MemoryStorageTest):
    def setUp(self) -> None:
        self.scope = storage.Scope(uuid.uuid4().hex, "com.example")
        self.store = postgres.PostgresStore(os.environ["RASP_TEST_POSTGRES_DSN"], self.scope)
        self.other = self.store.scoped(storage.Scope("other-" + self.scope.tenant_id, self.scope.app_id))
        self.addCleanup(self.store.close)
        self.addCleanup(self.other.close)

    def testRecords_whenStoreRecreated_preservesData(self) -> None:
        self.store.put("build", "durable", {"value": 123})
        restarted = self.store.scoped(self.scope)
        self.addCleanup(restarted.close)
        self.assertEqual(restarted.get("build", "durable"), {"value": 123})

    def testPool_whenTransactionsComplete_reusesConnectionAndClearsScope(self) -> None:
        with self.store.transaction() as connection:
            first_pid = connection.info.backend_pid
            self.assertEqual(connection.execute("SELECT current_setting('rasp.tenant_id')").fetchone()[0], self.scope.tenant_id)
        with self.store.transaction() as connection:
            self.assertEqual(connection.info.backend_pid, first_pid)
        with self.store.pool.connection() as connection:
            self.assertEqual(connection.execute("SELECT current_setting('rasp.tenant_id', true)").fetchone()[0], "")

    def testPool_whenTransactionFails_rollsBackAndReturnsUsableConnection(self) -> None:
        with self.assertRaises(RuntimeError):
            with self.store.transaction() as connection:
                connection.execute("INSERT INTO rasp_records VALUES (%s,%s,'pool','rollback','{}')",
                                   (self.scope.tenant_id, self.scope.app_id))
                raise RuntimeError("abort")
        self.assertIsNone(self.store.get("pool", "rollback"))
        self.store.put("pool", "usable", {"ok": True})
        self.assertEqual(self.store.get("pool", "usable"), {"ok": True})

    def testPool_whenContextExits_closesOwnedPool(self) -> None:
        with self.store.scoped(self.scope) as scoped:
            scoped.put("pool", "context", {})
        with self.assertRaises(psycopg_pool.PoolClosed):
            scoped.get("pool", "context")
        self.assertEqual(self.store.get("pool", "context"), {})

    def testPool_whenClosed_rejectsOperationsWithoutClosingOtherScope(self) -> None:
        self.store.close()
        with self.assertRaises(psycopg_pool.PoolClosed):
            self.store.get("pool", "closed")
        self.other.put("pool", "open", {})
        self.assertEqual(self.other.get("pool", "open"), {})

    def testRls_whenQueryOmitsScope_filtersRowsAndRejectsCrossTenantWrites(self) -> None:
        self.store.put("secret", "same", {"owner": "one"})
        self.other.put("secret", "same", {"owner": "two"})
        with self.store.transaction() as connection:
            self.assertEqual(connection.execute("SELECT value FROM rasp_records").fetchall(), [({"owner": "one"},)])
        with self.assertRaises(psycopg.errors.InsufficientPrivilege):
            with self.store.transaction() as connection:
                connection.execute("INSERT INTO rasp_records VALUES (%s,%s,'secret','forged','{}')", (self.other.scope.tenant_id, self.scope.app_id))


@unittest.skipUnless(os.environ.get("RASP_TEST_POSTGRES_DSN"), "requires isolated PostgreSQL DSN")
class PostgresTrustFlow(test_trust.TrustFlow):
    def setUp(self) -> None:
        self.scope = storage.Scope(uuid.uuid4().hex, helpers.PACKAGE)
        self.state = postgres.PostgresStore(os.environ["RASP_TEST_POSTGRES_DSN"], self.scope)
        self.addCleanup(self.state.close)
        builds = durable_registry.BuildRegistry(self.state)
        builds.register(registry.Build(helpers.BUILD_ID, helpers.BUILD_KEY, helpers.PACKAGE, [helpers.APP_CERT_SHA256]))
        self.trust = trust.TrustService(signing_key=jose.SigningKey.generate(), package_name=helpers.PACKAGE,
            signing_cert_sha256=[helpers.APP_CERT_SHA256], builds=builds, state=self.state,
            platform_attestation=platform.StubPlatformAttestation())

    def testTrust_whenProcessStateRecreated_usesPersistedInstall(self) -> None:
        chain, _ = self._bind()
        previous = self.trust
        restarted = self.state.scoped(self.scope)
        self.addCleanup(restarted.close)
        self.trust = trust.TrustService(signing_key=previous.signing_key, package_name=helpers.PACKAGE,
            signing_cert_sha256=[helpers.APP_CERT_SHA256], builds=durable_registry.BuildRegistry(restarted),
            state=restarted, platform_attestation=platform.StubPlatformAttestation())
        self.assertEqual(self._token(chain)["risk"], "none")
