"""Server-side verification for flutter_rasp, built around a trust service.

- `attestation`: verifies an Android Key Attestation chain (device binding).
- `jose`: ES256 JWTs and JWKS for the integrity tokens.
- `report`: verifies the sealed RASP report the native core MACs with a per-build key.
- `platform`: pluggable Play Integrity / App Attest verification.
- `policy`: server-side risk scoring and token lifetime.
- `registry`: the genuine-build and bound-install registries.
- `trust`: the trust service core (challenge -> bind -> token).
- `resource`: helpers for a backend that consumes tokens (DPoP proof verification, allow/step-up/deny).
- `server`: a reference process that serves the trust service and a demo bank backend together.
"""

from .attestation import AttestationError, AttestationResult, verify_key_attestation
from .platform import (
    DisabledPlatformAttestation,
    PlatformAttestation,
    PlatformAttestationError,
    PlatformVerdict,
    StubPlatformAttestation,
)
from .policy import RiskAssessment, TokenPolicy, assess_risk, token_ttl
from .registry import Build, BuildRegistry, Install, InstallRegistry, RegistryError
from .report import ReportError, SealedReport, verify_sealed_report
from .resource import Decision, ResourceError, canonical_request, decide, verify_request
from .trust import TrustError, TrustService

__all__ = [
    "AttestationError",
    "AttestationResult",
    "verify_key_attestation",
    "DisabledPlatformAttestation",
    "PlatformAttestation",
    "PlatformAttestationError",
    "PlatformVerdict",
    "StubPlatformAttestation",
    "RiskAssessment",
    "TokenPolicy",
    "assess_risk",
    "token_ttl",
    "Build",
    "BuildRegistry",
    "Install",
    "InstallRegistry",
    "RegistryError",
    "ReportError",
    "SealedReport",
    "verify_sealed_report",
    "Decision",
    "ResourceError",
    "canonical_request",
    "decide",
    "verify_request",
    "TrustError",
    "TrustService",
]
