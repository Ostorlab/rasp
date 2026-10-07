# ELF RASP prototype

Pack an existing Linux executable, inject runtime protection, and authorize its execution through a backend. The input application needs no RASP calls for startup, continuous scanning, or TCP connection enforcement. This is the ELF validation milestone before porting the pipeline to Android.

The packer rewrites the actual ELF's `DT_NEEDED` table with `$ORIGIN/librasp_runtime.so`. It uses neither a shell wrapper nor `LD_PRELOAD`. The output directory contains the rewritten executable, native runtime, publisher-signed manifest, and inspection report. Keep the companion files together; the directory can be relocated.

```text
Existing ELF + publisher key
            | pack / rewrite DT_NEEDED
            v
Executable + runtime + signed manifest
            | startup / periodic scan / TCP connect
            v
Signed evidence <---- single-use backend challenge
            | verify hashes, threats and customer policy
            v
Signed allow / deny / step_up
```

## Supported scope

- Linux x86-64, little-endian, dynamically linked glibc executables, PIE and non-PIE, including stripped binaries.
- GCC, OpenSSL 3 headers/libraries, Python 3.10+, LIEF, and cryptography are required to pack an executable. The generated runtime uses system OpenSSL shared libraries on the target host.
- Static binaries, shared-library inputs, other architectures/loaders, and setuid/setgid inputs are rejected. Programs that fork are outside this prototype's supported scope: child checkpoints and intercepted connections fail closed. Applications using direct syscalls or private networking implementations can bypass the `connect` interception point.
- Original application dependencies are preserved, but are not copied into the bundle. Deployment still needs those dependencies in their expected locations. Custom constructors, alternate symbol resolution, arbitrary language runtimes and launchers need their own compatibility validation.

## Install and run offline

From the repository root:

```bash
cd elf
uv venv .venv
uv pip install --python .venv/bin/python -e .
.venv/bin/rasp-elf keygen --output dist/keys

gcc -Wall -Wextra -Werror examples/demo.c -o dist/demo
.venv/bin/rasp-elf pack dist/demo --output dist/offline \
  --publisher-key dist/keys/publisher.key
.venv/bin/rasp-elf inspect dist/offline \
  --publisher-public dist/keys/publisher.pub
./dist/offline/demo hello
```

`pack` and `keygen` refuse to overwrite an existing output directory. Use a fresh directory for a new build. Keep publisher and backend private keys outside the output bundle. The per-build software client key is embedded in the runtime; it is not a hardware-backed secret.

Tampering with any signed file is detected before the application starts:

```bash
printf 'changed' >> dist/offline/demo
./dist/offline/demo hello
# RASP threat on stderr, exit 173, application does not run.
```

## Backend-authorized runtime

Produce a separate online bundle:

```bash
.venv/bin/rasp-elf pack dist/demo --output dist/online \
  --publisher-key dist/keys/publisher.key \
  --backend http://127.0.0.1:8788 \
  --backend-public dist/keys/backend.pub \
  --interval-ms 250

.venv/bin/rasp-elf serve \
  --publisher-public dist/keys/publisher.pub \
  --decision-key dist/keys/backend.key \
  --manifest dist/online/rasp.manifest \
  --audit dist/audit.jsonl
```

In another terminal, from `elf/`:

```bash
./dist/online/demo hello
./dist/online/demo wait
```

Startup requires a signed `allow` response. A monitoring thread checks the files, threat signals and backend policy every configured interval. Backend outage, an invalid response, `deny`, or `step_up` prevents execution. The reference backend consumes each challenge atomically, so evidence cannot be replayed. `--manifest` can be repeated to register multiple protected builds.

To prove automatic network enforcement, run a local service in another terminal:

```bash
python3 -m http.server 8790 --bind 127.0.0.1
```

Then:

```bash
./dist/online/demo connect 8790
```

The injected `connect` interceptor gets fresh authorization before opening the application's TCP connection. To deny connections while allowing startup, restart the RASP backend with the same arguments and add `--policy examples/policy.json`. The application exits 173 before its connection reaches the local service. Audit records include the build, operation, payload hash, threats and decision.

HTTP endpoints are restricted to literal loopback IPs. Use `https://host:port` remotely. The runtime verifies the TLS certificate and hostname using OpenSSL's trust store, plus a separately pinned Ed25519 backend decision key from the signed manifest. The reference server supports `--tls-cert`, `--tls-key`, and `--host`. Each HTTP exchange has an absolute two-second deadline across connection, TLS handshake and reads/writes, and bounded response sizes; hostname resolution still follows the system resolver's timeouts. The reference HTTP server uses threaded, in-memory state; production rate limits, persistent registration and audit retention belong in the customer's infrastructure.

## Customer backend integration

`rasp_elf.backend.Authorizer` is reusable without the reference HTTP server:

```python
from rasp_elf import backend
from rasp_elf import protocol

# Load the publisher public key and backend private key from trusted storage.
# customer_policy receives verified build, hashes, threats, operation and request hash.
# Return "allow", "deny", or "step_up". Exceptions fail closed.
authorizer = backend.Authorizer(decision_key, publisher_public, policy=customer_policy)
authorizer.register(publisher_signed_manifest_bytes)
nonce = authorizer.challenge(build_id)

# In middleware, after authenticating the customer, compare evidence to the exact
# request bytes and operation the server received. This consumes the nonce once.
signed_decision = authorizer.authorize(
    evidence_bytes,
    expected_request=request_body_bytes,
    expected_operation="checkpoint",
)
```

The reference runtime sends evidence directly to the RASP backend. Its automatic TCP checkpoint binds the destination socket address, not an HTTP request body or payment amount. Customer transaction binding needs a configured integration point and a backend that checks its actual request bytes. The packer cannot infer arbitrary business transactions from a binary.

For explicit integration, the runtime exports the optional API declared in `runtime/rasp_runtime.h`:

```c
int rasp_checkpoint(const void *payload, size_t length);
int rasp_prepare_request(const void *payload, size_t length, char *evidence, size_t capacity);
```

It performs a fresh scan, hashes those exact bytes, and requests backend authorization; it returns 0 on allow or -1 on denial/error. An application can discover this symbol through `dlsym(RTLD_DEFAULT, "rasp_checkpoint")`, as the integration tests do. For a business request, `rasp_prepare_request` performs a fresh local scan and obtains a nonce, then returns the signed evidence length in the caller buffer without consuming it at the RASP authorizer. Send those evidence bytes alongside the business request; the customer middleware consumes the nonce and compares the actual request bytes with `expected_request`. Preparation requires an online backend and returns -1 on error. This is an opt-in extension; the included demo needs no such call. A signed `step_up` decision blocks, and the customer must complete its own verification before changing authorization policy. Neither a local dialog nor `step_up` alone grants permission.

## Protection and trust boundary

- A publisher signature authenticates the manifest's executable/runtime hashes, backend address/key, build identity and scan interval.
- Scans check files on disk, `TracerPid` across every thread, preload/audit environment variables, and recognizable instrumentation names in `/proc/self/maps`. Thread scans are bounded to 4,096 entries and 64 KiB per status, and file hashing to 256 MiB. Detector failures are denied. Missing or malformed policy is denied; removing the runtime causes the ELF loader to fail.
- Runtime evidence is Ed25519-signed and bound to a fresh, build-specific, single-use challenge. Responses bind the build, challenge, evidence hash and short expiry, and must verify against the pinned backend key.
- This is software protection, not hardware attestation. An attacker controlling the process can extract the client key, forge clean evidence, replace the runtime, or remove the injected dependency. File hashes do not prove all live memory is unchanged. The tests demonstrate the implemented checks; they do not establish that this runtime is unbypassable.
- The current packer adds a native dependency and network interception. It does not yet encrypt/virtualize the original application code, perform arbitrary instruction rewriting, or provide a universal per-function instrumentation engine. These are separate hardening stages; Android additionally needs independent attestation.
- Local application behavior can only be blocked at the installed checkpoints. Enforce sensitive API operations on the customer's backend to protect business effects when client checks are bypassed. Customer authentication remains the customer's responsibility.

## Verification

```bash
.venv/bin/python -m unittest discover -s tests -t . -v
```

Tests compile independent executables and run protected processes. Coverage includes PIE/non-PIE/stripped inputs, original output/arguments/exit codes, relocation, signed manifests, modified/missing files, FIFO replacement, startup and late debugger detection, preload, continuous monitoring, TCP interception, exact checkpoint payloads, allow/deny/step-up/outage, replay/concurrent replay/expiry, malformed HTTP, timeouts, trusted and invalid TLS certificates, and fork rejection. Backend integration compares actual request bytes; mismatch denies.

Development checks:

```bash
uv pip install --python .venv/bin/python -e '.[dev]'
.venv/bin/ruff check rasp_elf tests
.venv/bin/ruff format --check rasp_elf tests
.venv/bin/mypy --strict --follow-untyped-imports rasp_elf
```

The repository's Android verifier regression tests remain separate:

```bash
(cd ../verifier && python3 -m unittest discover -s tests -t .)
```

See `VERIFICATION.md` for the recorded run and the ELF-to-Android handoff criteria.
