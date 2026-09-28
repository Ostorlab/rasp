# Scoped protection control plane

The control plane persists signed protection policies, secret versions, signing keys, security events, delivery metadata, and administrative audit records per tenant and application. The private console calls `/v1/console/apps/{appId}`. PostgreSQL row-level security and explicit scope predicates isolate every record; deployment-owned bearer principals select the tenant, and application grants select which apps and actions they may access.

## Running the backend

Install with `python -m pip install -e ./verifier`. Use PostgreSQL 16 and apply the existing schema with a schema-owner connection:

```python
from rasp_verifier import postgres
postgres.migrate(owner_dsn)
```

Grant a separate runtime role `SELECT, INSERT, UPDATE, DELETE` on `rasp_records`, `rasp_challenges`, and `rasp_counters`. The runtime role must not own tables or have `BYPASSRLS`. Both console and trust service use the same runtime database, tenant, application, and encryption key when sharing signing keys and trust records.

Generate a random credential and its hash on a trusted operator machine:

```python
import hashlib
import secrets
credential = secrets.token_urlsafe(32)
print(credential)  # Deliver privately to the operator; never commit it.
print(hashlib.sha256(credential.encode()).hexdigest())
```

Create a deployment-owned `principals.json` file using the hash, not the bearer value:

```json
{
  "principals": [
    {
      "id": "operator-alice",
      "tenantId": "organisation-a",
      "tokenSha256": "REPLACE_WITH_THE_64_CHARACTER_LOWERCASE_SHA256_HASH",
      "applications": {"dev.ostorlab.rasp.demo_bank": "admin"}
    }
  ]
}
```

Roles are enforced by the server: `reader` can read; `operator` can draft, publish, roll out, restore, and replace secrets; `admin` can also rotate keys and ingest trusted telemetry. Missing application grants are forbidden. A URL, query parameter, or header cannot override the principal's tenant. Credentials are opaque bearer tokens, so their secrecy is the authentication boundary. Remove or rotate a principal in the configuration and restart the process to revoke it; this reference adapter does not integrate an identity provider or dynamic credential administration.

Generate a Fernet key with `cryptography.fernet.Fernet.generate_key()`. Provision it through your secret manager as `RASP_CONTROL_ENCRYPTION_KEY`; preserve it across restarts. Set `RASP_POSTGRES_DSN` to the runtime-role DSN, then run:

```sh
python -m rasp_verifier.console_server --config /private/principals.json \
  --host 127.0.0.1 --port 8080
```

`--dsn-env` and `--encryption-key-env` select alternate environment variable names. The process fails to start without valid principals, PostgreSQL, and a valid encryption key. Secret values and private signing keys are encrypted before persistence; metadata and public keys are readable by authorized readers. Losing the encryption key loses access to stored secret values and signing keys. Database roles, backups, and encryption-key custody remain deployment responsibilities.

Serve `console/` as static files and reverse-proxy `/v1/console/` on the same origin to this backend. The console's supplied Nginx configuration uses `trust:8080`, where `trust` is the backend service's Docker hostname. Terminate TLS and apply connection/rate limits at the proxy. The reference backend binds loopback by default and emits no access logs containing credentials, request bodies, or secret values.

An optional image definition is provided at `deploy/control-plane.Dockerfile`. Build it from the repository root, mount the principal file read-only, and provision the two environment variables:

```sh
docker build -f deploy/control-plane.Dockerfile -t rasp-control-plane .
docker run --rm --name trust --network YOUR_PRIVATE_NETWORK \
  --env-file /private/control-plane.env \
  --mount type=bind,src=/private/principals.json,dst=/run/principals.json,readonly \
  rasp-control-plane
```

## Console API contract

All endpoints require exactly one `Authorization: Bearer <credential>` header. Mutations require JSON, one valid `Content-Length`, and at most 65,536 body bytes. Unknown fields, duplicate JSON keys, non-finite numbers, malformed paths, and unsupported policy settings are rejected. Responses use `Cache-Control: no-store`; failures expose stable error codes, never database errors or secret content.

The prefix below is `/v1/console/apps/{appId}`. List endpoints return `{items: [...], nextCursor: null | string}`. `limit` defaults to 50 and is bounded to 1–100. Cursors are authenticated and bound to the tenant, application, and exact resource; changing scope or using a policy cursor for audit returns 400. Lists use descending keyset pagination, so new records do not shift an existing cursor. Duplicate query keys and unrecognized queries are rejected.

| Method and path | Request / response | Minimum role |
| --- | --- | --- |
| `GET /summary` | Tenant/app identity, persisted install/build/event counts, risk counts, pending delivery count, active/candidate revisions, rollout percentage | reader |
| `GET /installs` | Install ID, platform, security level, bound timestamp; never public-key material or build keys | reader |
| `GET /installs/{installId}/timeline` | Recorded security events for an existing scoped install | reader |
| `GET /bypass-watch` | High/critical events and recorded attestation failure, token denial, or bypass outcomes | reader |
| `GET /policies` | Revision, status, validity, config, and signed envelope | reader |
| `POST /policies/drafts` | `{config, ttlSeconds}` → `{draftId, config, ttlSeconds, createdAt}` | operator |
| `POST /policies/publish` | `{draftId, percent}` → signed revision and deployment status | operator |
| `POST /policies/rollout` | `{revision, percent}` → updated candidate/stable revision | operator |
| `POST /policies/rollback` | `{revision}` → previous content signed as a higher stable revision | operator |
| `GET /secrets` | Name, version, scopes, maximum risk, grant lifetime, update timestamp; never value or ciphertext | reader |
| `POST /secrets` | `{name, value, scopes, maxRisk, ttlSeconds}` → metadata for a new version | operator |
| `GET /keys` | Active key IDs, public `policyKeys` SPKI map, token JWKS, configured overlap | reader |
| `POST /keys/rotate` | `{purpose: "token" | "policy"}` → updated public key metadata | admin |
| `GET /deliveries` | Actual persisted delivery metadata; no synthetic outcomes | reader |
| `GET /audit` | Actor, action, target, received timestamp | reader |
| `POST /telemetry/events` | `{installId, risk, kind, signals, source, policyRevision}` → durable event ID and server timestamp | admin |
| `POST /telemetry/deliveries` | `{eventId, status, attempts, nextAttemptAt, lastError}` → durable delivery metadata | admin |

Every accepted administrative mutation commits its target record and audit entry in the same PostgreSQL transaction. Scoped control-state row locks serialize competing publication and rotation requests. A draft can publish once; concurrent repeat publication returns 409 and produces one published revision and audit entry. Audits use action names such as `policies/publish.requested` and `secrets.requested`; this suffix records the committed control-plane request, not proof that a device applied the change.

## Signed policies and rollout

Policies match the mobile `SignedPolicy` contract:

```json
{"kid": "P-256-key-id", "payload": "base64url-exact-JSON-bytes", "signature": "base64url-raw-64-byte-ES256"}
```

The signed JSON contains `tenantId`, `appId`, `revision`, `issuedAt`, `expiresAt`, and `config`. Signatures cover the exact payload bytes using ECDSA P-256/SHA-256. Revisions are positive, increasing PostgreSQL BIGINT values. Restoring older content issues a higher revision with new validity, so the SDK's anti-rollback check remains effective. Validity is 60–604800 seconds; expiration is enforced by the SDK and by the policy-selection helper.

Supported configuration keys are `policy`, `checkIntervalSeconds`, `accessibilityAllowlist`, `pins`, `wipeOnThreats`, and `reactionDelayMillis`. Interval is bounded to 5–3600 seconds for consistent Android/iOS behavior; reaction delay is 0–60000 milliseconds. Reactions are `report`, `warnUser`, `blockSensitive`, `secureScreen`, `closeApp`, and `silentDegrade`. Secret wiping is a separate `wipeOnThreats` setting. Pins require lowercase DNS hosts and base64 32-byte SPKI digests. Bootstrap identities, development mode, trusted policy keys, and device credentials cannot be changed through remote config.

A 100% publication becomes stable. A smaller percentage becomes the single candidate. `ControlPlane.selected_policy(install_id)` selects a deterministic scope/install cohort; a trusted application gateway must authenticate the install before calling it. This console API does not authenticate mobile devices or fetch policies on their behalf. The deployment must integrate this helper into its authenticated policy distribution path. No matching or unexpired policy returns `None`; publishing alone is not proof of on-device application.

Candidate rollout can increase, but cannot decrease. Promote the candidate to 100%, or restore known content as a higher revision, before publishing another candidate. These guards prevent assigning an older stable revision to an install that already accepted a candidate. Restoring content deploys the new revision to all cohorts. Publish renewed policies before validity expires; the console does not automatically renew them.

## Signing-key rotation and trust issuance

The control plane creates an active and a prepared policy key. `GET /keys` exposes both public bootstrap keys before activation. Provision the prepared key in the SDK's immutable `policyKeys` bootstrap configuration before rotating. Policy rotation activates that previously exposed key and creates the next prepared key. Each future rotation requires distributing its prepared public key beforehand, usually through an application release. The backend cannot prove every install received bootstrap changes; rotating without provisioning causes those installs to reject new policy signatures.

Retired public keys remain available for 604860 seconds, covering the maximum policy lifetime plus clock allowance. Private key material and ciphertext are never returned by any API. Secrets have monotonically increasing versions; a replacement stores only the latest encrypted value. Grant lifetime is bounded to 1–3600 seconds. Storing scopes and risk limits does not create a secret-release endpoint; a separately authenticated runtime entitlement service must enforce them before release.

The existing trust-server CLI can consume the same durable token keys:

```sh
python -m rasp_verifier.server --package dev.ostorlab.rasp.demo_bank \
  --tenant-id organisation-a --cert-sha256 YOUR_RELEASE_DIGEST \
  --build-id YOUR_BUILD_ID --build-key-hex YOUR_BUILD_MAC_KEY \
  --control-plane-keys
```

Use the same `RASP_POSTGRES_DSN` and `RASP_CONTROL_ENCRYPTION_KEY`; `--control-encryption-key-env` selects a different variable. Shared keys require PostgreSQL and cannot be combined with `--signing-key-pem`. The trust service loads the active key for each issuance and exposes overlapping public keys in its JWKS, so a token-key rotation affects the next token without invalidating existing tokens during overlap. Embedders can pass paired `signing_key_provider=plane.token_signing_key` and `jwks_provider=plane.token_jwks` to `TrustService`.

## Events and delivery boundaries

Overview and lists read persisted records. They return zero counts and empty lists until a trusted pipeline records events; no installation, breach, or SIEM result is invented. Trust installs and builds appear when the trust service shares this scoped database. Security-event ingestion is restricted to an admin principal because the control plane does not independently verify telemetry claims. The producer must authenticate/verify its source before ingestion. Administrative requests are audited separately and never counted as device security events.

The supplied deployment does not automatically emit trust decisions or dispatch SIEM traffic. Integrate your verified decision pipeline using `POST /telemetry/events` or `ControlPlane.record_event(...)`. A delivery worker records real attempts and outcomes using `POST /telemetry/deliveries` or `record_delivery(...)`; pending metadata is not proof of dispatch. Avoid putting secrets or personal data in delivery error strings. No delivery retry worker, automatic trust telemetry hook, or secret-release service is shipped here.

## Validation

The verifier suite exercises real HTTP with PostgreSQL 16 and a restricted runtime role: authorization, tenant/application separation, signed scoped policies, revision races, encryption/redaction, token rotation with old-token overlap, cursor tampering, and rollback when audit insertion fails. Fatal Python lint and the unchanged 80% verifier branch-coverage gate run in core CI.

The console CI job also provisions an isolated PostgreSQL service and invokes the real CLI backend for the live Playwright test. Locally, with a migrated dedicated database and restricted test-role DSN:

```sh
RASP_TEST_POSTGRES_DSN=postgresql://YOUR_LOCAL_FIXTURE_ROLE@127.0.0.1/rasp_test \
  RASP_TEST_PYTHON=/path/to/venv/bin/python \
  bash verifier/scripts/test_console_live.sh
```

The runner uses a disposable principal/encryption configuration, binds loopback, runs the existing `console/tests/live.spec.js`, then removes its configuration and stops its backend. Supply `PLAYWRIGHT_BROWSERS_PATH` if browsers are installed in a private cache. Ordinary browser tests remain independently runnable through `cd console && npm test`. No cloud account, production database, or published SDK/package is required.
