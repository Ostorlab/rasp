# ELF RASP prototype

Approved product direction: binary packing plus runtime instrumentation and backend integration, validated on ELF before Android.

## Supported input and output
Linux x86-64, little-endian, dynamically linked glibc ELF executables, PIE and non-PIE. Reject static ELFs, libraries, setuid/setgid inputs, foreign machines and already protected inputs. LIEF adds a DT_NEEDED entry for librasp_runtime.so using the explicit origin-relative dependency `$ORIGIN/librasp_runtime.so` (preserving existing search paths); there is no shell launcher or dependence on LD_PRELOAD. Output is a relocatable directory containing the rewritten executable, runtime library, signed manifest, and inspection report. Existing arguments, exit codes and output must remain intact. Stripped binaries must work. Multi-process and alternate loaders are outside the initial supported scope.

## Trust and runtime behavior
Compile an Ed25519 publisher public key and a software client signing key into each runtime. Publisher-signed manifest pins executable/runtime SHA-256, backend decision public key, endpoint and scan interval. No private publisher/backend keys ship in the output. Constructors check before main, then a monitoring thread checks periodically. The runtime interposes TCP connect to obtain fresh backend authorization before business connections, with a recursion guard for its own transport. An optional exported checkpoint API binds arbitrary integration payload bytes to authorization. A prepared-request API exports freshly signed checkpoint evidence without consuming its nonce, so the customer can submit it with the actual business request. Customer middleware calls authorize with expected_request and expected_operation, comparing the actual bytes before any business effect. Scans check executable/runtime files, debugger attachment across all thread task statuses (4,096-entry scan cap, 64 KiB/status) and unexpected preload/instrumentation. Failures block with exit code 173; unsupported operation on an explicit checkpoint returns failure. HTTP is allowed only for literal loopback addresses; HTTPS verifies system trust and hostname. Each HTTP exchange has an absolute monotonic two-second transport deadline across connect/TLS/write/read, and response limits are enforced. Hostname lookup follows the system resolver timeout. Files must be regular and no larger than 256 MiB to hash. Local checks are enabled even when no backend is configured.

This is software protection, not hardware attestation: a local attacker can extract the client key, replace the library, remove injection or forge clean evidence. The server validates signatures, registered hashes, fresh single-use challenges and policy, but cannot independently prove the process state. Android later supplies independent attestation. File integrity does not prove all in-memory code is unchanged. Network interposition covers dynamically resolved connect calls, not direct syscalls or arbitrary transaction semantics.

## Wire contract (UTF-8, LF, ordered fields, final LF)
Signed manifest rasp.manifest beside the executable:
```
v=rasp-elf-manifest-1
build=<64 lowercase hex>
exe=<sha256 hex>
runtime=<sha256 hex>
endpoint=<empty or http[s]://host:port, no path/query/userinfo>
interval_ms=<100..60000>
client_public=<32 byte Ed25519 hex>
server_public=<32 byte Ed25519 hex; zeroes offline>
signature=<64 byte hex over preceding bytes>
```
Runtime locates its own library with dladdr and executable through /proc/self/exe. Manifest is located alongside the executable. Missing/malformed/unsigned manifest fails closed.

POST /v1/challenge body `build=<build>\n` -> `nonce=<64 hex>\n`. Challenges live for 30 seconds, are bound to build, consumed atomically, and capped at 4096 live entries.

POST /v1/authorize signed evidence:
```
v=rasp-elf-evidence-1
build=<build>
nonce=<nonce>
pid=<positive decimal>
exe=<sha256 hex>
runtime=<sha256 hex>
threats=<none or comma-separated threat names>
operation=<startup|monitor|connect|checkpoint>
request=<sha256 of operation payload bytes; empty payload for startup/monitor>
signature=<64 byte hex over preceding bytes>
```
Backend enforces registered build, signature, expected file hashes, known threat names, one-use challenge, and policy. Any threat denies; an optional customer callback can return allow, deny or step_up. Step-up blocks until the customer completes verification and changes policy; client never treats it as allow.

Signed response (HTTP 200 even on deny):
```
v=rasp-elf-decision-1
build=<build>
nonce=<nonce>
evidence=<sha256 of evidence bytes preceding signature>
action=<allow|deny|step_up>
expires=<unix seconds, now+30>
signature=<64 byte hex over preceding bytes>
```
Runtime verifies backend signature, exact build/nonce/evidence and expiration (within 60 seconds). Offline, requests are governed only by local policy. Backend is a localhost reference server and reusable authorizer library, with registration from publisher-signed manifests, bounded input, JSONL audit logs, and a middleware-style verify/decide callback.

## Verification acceptance
Compile independent programs without RASP calls, pack and run both PIE/non-PIE/stripped. Verify DT_NEEDED injection, relocation, stdout/arguments/exit behavior, and clean baseline. Test altered executable/runtime/manifest, missing runtime/manifest, preload and debugger, late tampering, connect authorization, explicit checkpoints, backend deny/step-up/outage/bad signature, replay/expiration/wrong-build/wrong-hash/forged evidence, malformed inputs, and rejection of unsupported ELF. Run existing verifier regression tests. Publish reproducible CLI commands and exact supported limits. Android work begins only after this milestone is reviewed.
