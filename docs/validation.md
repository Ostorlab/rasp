# Validation and release gates

The source and SDK packages are proprietary. No workflow publishes packages.
Use local/path dependencies or an authorized private package registry.

## Core CI

`.github/workflows/ci.yml` runs the verifier and hardener suites, fatal Python
lint, native host tests, and a 1 MiB host native-library size gate. Coverage gates
are 80% for the existing verifier and 90% for the hardener, including branches;
they are regression floors, not claims of complete security coverage. Coverage
XML is the only uploaded artifact. Generated build keys, manifests, white-box
tables, and private symbol maps must never be public artifacts.

The host library size gate is an early regression signal. It does not measure
an APK, iOS framework, or device-specific optimized binary. Run the same size
command on each release artifact with its approved release budget.

## Enforcement checker

Run only against an authorized staging environment and expendable account: the
positive control executes the protected operation once. Create two real proof
fixtures for the exact same method, path, body, and account credentials. One
uses a currently valid integrity token; the other uses an authentically issued
token expired by at least 60 seconds. Keep the expired request proof itself
fresh so the test isolates token expiry. The checker cannot establish fixture
signature provenance; obtain both from the actual trust service.

Save a private JSON file containing `url`, uppercase `method`, `bodyBase64`,
`headers`, and `expiredHeaders`. The two header objects contain the complete
`X-Integrity-Token`, `-Key`, `-Sig`, `-Ts`, and `-Counter` headers and identical
business-account authorization. Never commit this credential-bearing fixture.

```sh
python -m rasp_verifier.enforcement /private/path/request-fixture.json
```

The checker sends missing-token, malformed-token, expired-token, valid, and
exact-replay requests. Every negative probe must return 401/403, and the valid
request must return 2xx. Network failures, redirects, 404, 429, and 5xx fail the
gate. HTTPS uses default certificate and hostname verification; redirects are
never followed. `--allow-loopback-http` permits literal loopback addresses for
local tests only. Exit codes: 0 passes, 1 fails, 2 invalid configuration. Output
contains probe names/statuses and never prints supplied credentials or bodies.

The automated suite tests the checker against intentionally broken HTTP
endpoints and the real reference bank with synthetic hardware attestation,
valid ES256 tokens, an authentically signed expired token, and request replay.

## Performance and size evidence

```sh
python -m rasp_verifier.budgets size path/to/librasp_core.so --max-bytes 1048576
python -m rasp_verifier.budgets latency measurements.json --max-p95-ms 100
```

Latency input is `{"device":"reference-device-name","samplesMs":[...]}` with at
least 30 finite nonnegative measurements. The gate uses nearest-rank p95. Record
the device model, OS/build, APK/build ID, measured operation, warmup method, and
measurement conditions alongside the samples. The sample threshold of 100 ms
above is an invocation example, not a measured performance claim or approved
product SLA. Physical-device benchmarks and bypass regression evidence remain
required before claiming device-farm validation.
