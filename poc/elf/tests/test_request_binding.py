"""Customer middleware must compare evidence to the request it actually received."""

from __future__ import annotations

import hashlib
import inspect
import unittest

from rasp_elf import protocol
from tests import test_backend


class RequestBindingTest(unittest.TestCase):
    def setUp(self) -> None:
        test_backend.AuthorizerTest.setUp(self)
        self.assertIn(
            "expected_request",
            inspect.signature(self.authorizer.authorize).parameters,
            "customer request binding is not implemented",
        )

    def evidence(self, nonce: str, **changes: str) -> bytes:
        return test_backend.AuthorizerTest.evidence(self, nonce, **changes)

    def testAuthorizer_whenCustomerPayloadMatches_authorizesExactRequest(self) -> None:
        nonce = self.authorizer.challenge("ab" * 32)
        payload = b'{"amountCents":5000,"payee":"Alex"}'
        message = self.evidence(nonce, operation="checkpoint", request=hashlib.sha256(payload).hexdigest())
        decision = self.authorizer.authorize(message, expected_request=payload, expected_operation="checkpoint")
        fields, _ = protocol.verify_message(decision, protocol.public_hex(self.server_key), protocol.DECISION_FIELDS)
        self.assertEqual("allow", fields["action"])

    def testAuthorizer_whenCustomerPayloadChanged_deniesRequest(self) -> None:
        nonce = self.authorizer.challenge("ab" * 32)
        message = self.evidence(nonce, operation="checkpoint", request=hashlib.sha256(b"amount=5000").hexdigest())
        decision = self.authorizer.authorize(
            message, expected_request=b"amount=500000", expected_operation="checkpoint"
        )
        fields, _ = protocol.verify_message(decision, protocol.public_hex(self.server_key), protocol.DECISION_FIELDS)
        self.assertEqual("deny", fields["action"])

    def testAuthorizer_whenStartupEvidenceUsedForPayment_deniesRequest(self) -> None:
        nonce = self.authorizer.challenge("ab" * 32)
        decision = self.authorizer.authorize(
            self.evidence(nonce), expected_request=b"", expected_operation="checkpoint"
        )
        fields, _ = protocol.verify_message(decision, protocol.public_hex(self.server_key), protocol.DECISION_FIELDS)
        self.assertEqual("deny", fields["action"])
