# Backend trust foundation

The verifier supports Android Key Attestation plus Google Play Integrity and a separate iOS App Attest lifecycle. The Android challenge/bind/token wire format remains supported. Tokens now include a mandatory `aud: "rasp-resource"`; issuers, audiences, mandatory numeric issuance/expiry and expiry-after-issuance are validated. Older externally minted fixtures without an audience need updating.

## Implementation plan and validation

- [x] Reject wrong application/build signer identity, install replacement, malformed JWT claims and report shapes.
- [x] Add scoped memory/PostgreSQL repositories and atomic challenge/counter operations.
- [x] Verify Google-decoded request/application/device verdicts using an OAuth-backed production adapter.
- [x] Verify bounded Apple CBOR, certificate chain, nonce, RP ID, environment, credential key and assertion counters; expose explicit iOS routes.
- [x] Exercise negative cases, concurrent replay, full Android flows and state recreation against PostgreSQL.

Local validation: 169 unittest cases pass with PostgreSQL 16 and a non-owner runtime role. Combined branch coverage is 82%, above the unchanged 80% gate. This includes synthetic cryptographic Apple fixtures and controlled Google decode responses. Live Google credentials, Apple device attestations, receipts/fraud-metric assessment and on-device behavior have **not** been validated. App Attest does not establish biometric enforcement; its tokens carry `uauth=false`, `sec="app_attest"`.

## Service and storage boundaries

```text
┌──────────────────────┐     ┌──────────────────────────┐
│ Android / iOS client │ ──► │ TrustService             │
└──────────────────────┘     │ challenge / bind / token │
                             └────────────┬─────────────┘
                                          │
                ┌─────────────────────────┼─────────────────────┐
                ▼                         ▼                     ▼
       ┌────────────────┐    ┌─────────────────────┐  ┌─────────────────┐
       │ Google / Apple │    │ Scoped Store        │  │ JWT signing key │
       │ verification   │    │ memory / PostgreSQL │  │ deployment PEM  │
       └────────────────┘    └─────────────────────┘  └─────────────────┘
```

`storage.Scope(tenant_id, app_id)` is immutable. `app_id` is the package or bundle identifier in the reference server. Repository scope comes from trusted deployment configuration; no client header selects a tenant.

`storage.Store` provides `get`, `put`, `delete`, `put_challenge`, `consume_challenge`, and `advance_counter`. `MemoryStore.scoped(scope)` shares one locked backing store; `PostgresStore.scoped(scope)` creates a scope-bound connection adapter. `registry.BuildRepository` and `InstallRepository` preserve the existing registry API; `durable_registry` implements them on a Store. `TrustService(..., state=store)` requires all repository scopes to agree.

Challenges are consumed once using `DELETE ... RETURNING`; counters advance with a conditional PostgreSQL upsert. Row-level policies protect all three tables using transaction-local tenant/application settings. Every normal statement also has explicit scope predicates. Use a non-owner role without `BYPASSRLS`; migrations require a separate schema-owner connection. Build revocation is a monotonic separate record, so registering a build again cannot erase revocation. Install binding is insert-only. Recovery/re-enrollment needs an explicitly authorized administrative flow; overwriting a key is not a recovery API.

`resource.verify_request(..., replay_store=store)` validates the signed scope and atomically advances the session-key counter after signature verification. Production consumers must supply this store; omitting it retains the caller-managed legacy `last_counter` contract. Request counter rows deliberately do not expire, so a reused session key cannot reset replay state. Add bounded retention only together with a proven token-lifetime/key-reuse policy. Challenge expiry prevents reuse; expired rows can be deleted by an operational cleanup job. The in-memory implementation remains for demonstrations/tests.

The reference bank retains in-memory customer sessions/PIN state and is not a durable banking application. The HTTP process is a reference adapter; deploy behind TLS and authentication/rate-limiting appropriate to the application. PostgreSQL stores build key material; restrict its role, storage, backups and database access accordingly. Encryption/key-management integration is a separate control-plane task.

## Configuration

Install dependencies with `python -m pip install -e ./verifier`. The package includes its SQL migration. Run migration through the schema-owner DSN before starting the service:

```python
from rasp_verifier import postgres
postgres.migrate(owner_dsn)
```

Grant the runtime role `SELECT, INSERT, UPDATE, DELETE` on `rasp_records`, `rasp_challenges`, and `rasp_counters`. Set `RASP_POSTGRES_DSN` to that role's DSN. Without the environment variable, the demo uses memory. `--postgres-dsn-env` selects a different variable; it never prints its value.

Existing server flags remain. Additional flags:

| Flag | Purpose |
| --- | --- |
| `--tenant-id TENANT` | Scope the configured application; default `default`. |
| `--signing-key-pem PATH` | Load a persistent P-256 token-signing key. Omission generates an ephemeral demo key. |
| `--google-play-integrity` | Use Google OAuth decode with Application Default Credentials. |
| `--apple-app-id PREFIX.bundle.id` | Configure the full Apple App ID; its bundle must match `--package`. |
| `--apple-root-pem PATH` | Explicit trusted Apple App Attest root certificate(s). |
| `--apple-development` | Accept development AAGUID only. Default is production only. |

Google setup needs an enabled Play Integrity API in the linked Cloud project and authorized ADC credentials. The adapter requests `https://www.googleapis.com/auth/playintegrity`, calls the fixed Google HTTPS decode endpoint, disables redirects, bounds response size, and applies connection/refresh timeouts. It checks request/package/hash/time, app recognition, exact signer digest set and licensing; an optional `versions` set restricts versions when constructing `GooglePlayIntegrityAttestation` directly. Unknown/missing device verdicts yield `NONE`, never a clean verdict. Configured API failures fail closed. The legacy request hash is SHA-256 of the UTF-8 base64 nonce text; standard-base64 and unpadded-base64url digest encodings are accepted. This legacy hash is not a general defense against clean-device attestation relay.

Apple verification uses explicitly provisioned App Attest roots, never certificates supplied as trust anchors by the client. Development and production states must use separate deployment scopes. The App ID prefix is not assumed to equal the Team ID. App Attest receipts returned by verification are opaque; this implementation does not validate or redeem them as fraud evidence.

## iOS client contract

1. `POST /v1/challenge {"installId": ..., "purpose": "ios-bind"}` returns the existing random base64 nonce and 120-second TTL.
2. App Attest `attestKey` uses `clientDataHash = SHA256(UTF8(nonce))`. Send `POST /v1/ios/bind` with `installId`, `nonce`, `keyId` (Apple base64 identifier), and `attestationObject` (standard base64 CBOR). The server checks Apple certificate/authenticator identity and binds the install and key reservation atomically; a failed bind leaves neither a new install nor a key reservation.
3. For tokens, request a challenge with `purpose: "ios-token"`. Seal the report with that nonce and generate the ephemeral session public key.
4. Form the exact UTF-8 message below, with no trailing newline; `sessionJkt` is the RFC 7638 P-256 thumbprint:

```text
rasp-token-1
{nonce}
{sealedReport.mac}
{sessionJkt}
```

5. App Attest `generateAssertion` uses `clientDataHash = SHA256(message)`. Send `POST /v1/ios/token` with `installId`, `nonce`, `keyId`, `assertion` (standard base64 CBOR), `sealedReport`, and `sessionPublicKey` (base64 SPKI DER).

Successful tokens use the existing resource proof format. Assertions bind both report MAC and session key, verify the RP hash/signature, and require an atomically increasing counter. Android and iOS install records cannot enter the other platform's proof route. iOS must still supply a genuine registered-build sealed report; App Attest alone does not bypass that requirement.

## Tests

Run ordinary tests with:

```sh
PYTHONPATH=verifier python -m unittest discover -s verifier/tests -t verifier -q
```

Database tests explicitly skip without `RASP_TEST_POSTGRES_DSN`. To create a disposable PostgreSQL container, migrate it, create a restricted role, execute all tests, and clean up automatically:

```sh
RASP_TEST_PYTHON=/path/to/venv/bin/python bash verifier/scripts/test_postgres.sh
```

The runner requires local Docker and the verifier's dependencies. No production database or cloud account is used. Tests cover competing challenge/DPoP/App Attest counter consumers, same IDs across tenants, RLS queries missing scope predicates, rejected cross-tenant writes, state recreation, invalid JWT shapes/dates, cross-application builds, Apple chain/nonce/environment/key/RP mutations, bounded CBOR and Google malformed/stale/substituted/unlicensed verdicts.

## Primary references

- [Google standard requests and server decoding](https://developer.android.com/google/play/integrity/standard)
- [Google integrity verdict validation](https://developer.android.com/google/play/integrity/verdicts)
- [Apple App Attest server validation](https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server)
- [Apple attestation object validation guide](https://developer.apple.com/documentation/devicecheck/attestation-object-validation-guide)
- [PostgreSQL row security](https://www.postgresql.org/docs/current/ddl-rowsecurity.html)
