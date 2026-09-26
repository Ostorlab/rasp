"""Server-side verification for flutter_rasp.

- `attestation`: verifies an Android Key Attestation chain (device binding).
- `transaction`: verifies transactions signed by the bound key and decides allow / step-up / deny.
- `server`: a small reference bank backend wiring both together.
"""

from .attestation import AttestationError, AttestationResult, verify_key_attestation
from .transaction import Decision, SignedTransaction, TransactionError, decide, verify_transaction

__all__ = [
    "AttestationError",
    "AttestationResult",
    "Decision",
    "SignedTransaction",
    "TransactionError",
    "decide",
    "verify_key_attestation",
    "verify_transaction",
]
