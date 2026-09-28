"""Repository behavior, isolation and concurrent one-use operations."""
from __future__ import annotations

import concurrent.futures
import time
import unittest
import uuid

from rasp_verifier import storage


class MemoryStorageTest(unittest.TestCase):
    def setUp(self) -> None:
        self.scope = storage.Scope(uuid.uuid4().hex, "com.example")
        self.store = storage.MemoryStore(self.scope)
        self.other = self.store.scoped(storage.Scope("other", self.scope.app_id))

    def testRecords_whenScopeChanges_hidesSameIdentifier(self) -> None:
        self.store.put("build", "same", {"secret": "one"}, insert_only=True)
        self.assertIsNone(self.other.get("build", "same"))
        self.other.put("build", "same", {"secret": "two"}, insert_only=True)
        self.assertEqual(self.store.get("build", "same"), {"secret": "one"})
        with self.assertRaises(storage.ConflictError):
            self.store.put("build", "same", {}, insert_only=True)

    def testChallenge_whenConsumedConcurrently_acceptsOnlyOnce(self) -> None:
        self.store.put_challenge("nonce", "bind", "install", time.time() + 60)
        self.assertFalse(self.other.consume_challenge("nonce", "bind", "install", time.time()))
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            results = list(executor.map(lambda _: self.store.consume_challenge("nonce", "bind", "install", time.time()), range(20)))
        self.assertEqual(sum(results), 1)

    def testChallenge_whenExpiredOrWrongPurpose_rejects(self) -> None:
        self.store.put_challenge("expired", "bind", "install", time.time() - 1)
        self.store.put_challenge("fresh", "bind", "install", time.time() + 60)
        self.assertFalse(self.store.consume_challenge("expired", "bind", "install", time.time()))
        self.assertFalse(self.store.consume_challenge("fresh", "token", "install", time.time()))
        self.assertTrue(self.store.consume_challenge("fresh", "bind", "install", time.time()))

    def testCounter_whenRacedOrDecreased_rejectsReplay(self) -> None:
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            results = list(executor.map(lambda _: self.store.advance_counter("key", 1), range(20)))
        self.assertEqual(sum(results), 1)
        self.assertTrue(self.store.advance_counter("key", 2))
        self.assertFalse(self.store.advance_counter("key", 1))
        self.assertTrue(self.other.advance_counter("key", 1))


