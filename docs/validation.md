# Validation and release gates

Release validation combines an HTTP enforcement checker, artifact-size budgets,
and a device-latency p95 budget. Core CI runs unit tests, coverage, fatal lint,
and a 1 MiB host-library size gate. Endpoint probes and device measurements run
separately with operator-provided fixtures.

Packages are proprietary; use local path dependencies or an authorized private
registry. No workflow publishes them.

## What does the core CI gate?

`.github/workflows/ci.yml` runs:

- Verifier and hardener suites.
- Fatal Python lint.
- Native host tests.
- A 1 MiB host native-library size gate.

Coverage.py measures statements and branches. CI gates their combined coverage
at 80% for the verifier and 90% for the hardener; branch-only percentages are not
independently gated. These are regression floors, not claims of complete security
coverage. Coverage XML is the
only uploaded artifact; generated keys, manifests, white-box tables, and private
symbol maps must never be public artifacts.

The host-library gate does not measure an APK, iOS framework, or device-specific
optimized binary. Apply the size command to each artifact with its release budget.

## How does the enforcement checker work?

The checker sends five probes: missing-token, malformed-token, expired-token,
valid, and exact-replay. It fails unless every negative returns 401/403 and the
valid request returns 2xx. It never follows redirects and disables environment
proxies. Exit codes are 0 for pass, 1 for failure, and 2 for invalid configuration.

### Preparing proof fixtures

Run against authorized staging and an expendable account: the positive control
executes the protected operation once. Create two real proof fixtures for the
same method, path, body, and account credentials:

- **Valid fixture:** a currently valid integrity token.
- **Expired fixture:** an authentically issued token expired by at least 60
  seconds. Keep the request proof fresh to isolate token expiry.

The checker cannot establish fixture signature provenance. Obtain both tokens
from the actual trust service.

Save a private JSON file with `url`, uppercase `method`, `bodyBase64`, `headers`,
and `expiredHeaders`. Both header objects contain `X-Integrity-Token`,
`X-Integrity-Key`, `X-Integrity-Sig`, `X-Integrity-Ts`, and `X-Integrity-Counter`,
plus identical business-account authorization. Never commit this fixture.

```sh
python -m rasp_verifier.enforcement /private/path/request-fixture.json
```

The checker sends missing-token, malformed-token, expired-token, valid, and
exact-replay probes:

- Negative probes must return 401/403; the valid request must return 2xx.
- Network failures, redirects, 404, 429, and 5xx fail the gate.
- HTTPS verifies certificates and hostnames. Redirects are never followed.
- Environment proxies are disabled so fixture credentials go only to the target.
- `--allow-loopback-http` permits literal loopback addresses for local tests only.
- Exit codes: 0 passes, 1 fails, 2 invalid configuration.
- Output lists probe names/statuses and omits supplied credentials and bodies.

Tests exercise deliberately broken endpoints and the reference bank with
synthetic hardware attestation, valid ES256 tokens, authentic expired tokens,
and replayed proofs.

## How do I run the performance and size gates?

```sh
python -m rasp_verifier.budgets size path/to/librasp_core.so --max-bytes 1048576
python -m rasp_verifier.budgets latency measurements.json --max-p95-ms 100
```

- **Input:** `{"device":"reference-device-name","samplesMs":[...]}` with at least
  30 finite nonnegative measurements.
- **Gate:** nearest-rank p95.
- **Record:** device model, OS/build, APK/build ID, measured operation, warmup,
  and measurement conditions alongside samples.
- The 100 ms threshold is an invocation example, not a measured claim or SLA.
- Physical-device benchmarks and bypass evidence are required before claiming
  device-farm validation.
