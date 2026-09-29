# ELF milestone verification

Recorded on 2026-09-29, on branch `feat/elf-rasp-prototype`. The implemented Linux ELF milestone is verified; the Android binary packing pipeline is the next platform stage.

## Results

| Check | Result |
| --- | --- |
| ELF automated suite | **104 tests passed**, final full run 68.189 seconds |
| Native runtime subset | 33 tests passed; each fixture compiles with `-Wall -Wextra -Werror` |
| Existing Android banking verifier on current main | **192 tests run successfully**, 29 PostgreSQL tests skipped locally (no test DSN) |
| Existing build-time hardener | **71 tests passed** |
| Existing native Android detector core on host | Compiled with strict warnings; native tests passed |
| Ruff | Lint and formatting checks passed |
| Mypy | Strict check passed for all 5 Python source files |
| Python statement coverage | **92%**, 474/515 statements; includes CLI subprocesses |
| Wheel packaging | Wheel built and installed in a separate `/tmp` environment |
| Installed-wheel smoke from outside repository | Signed inspection, offline and online execution, exit-code preservation and denied network side effect passed |
| Independent spec review | Approved after transport deadline and static-input regression fixes |
| Independent code review | Approved after worker-thread debugger fix and regression verification |

The 104 test methods include subcases for malformed envelopes, signatures, manifest values, endpoints, HTTP responses and TLS certificates. Python statement coverage does not measure native C coverage or prove resistance to every bypass.

## Tested behavior

- Rewriting real ELF dependencies, without a shell launcher or `LD_PRELOAD`.
- PIE, non-PIE and stripped executables; arguments, stdout and exit code preservation; relocation of the companion-file directory.
- Compatibility corpus: `true`, `false`, `printf`, `echo`, `cat`, `head`, and `ls`, compared with their original behavior.
- Rejection of static ELF, shared-library input, foreign architecture, non-ELF, privileged input, repacking and output overwrite.
- Signature and file-integrity failures, missing manifest/runtime, modified executable/runtime/manifest, live tampering, FIFO substitution, and huge sparse-file substitution.
- Startup and late debugger attachment, including attachment to an application worker thread; clean short-lived thread churn with explicit checkpoints.
- Constructor authorization, periodic monitoring, dynamically resolved TCP `connect` interception, and optional payload-bound checkpoints.
- Prepared signed evidence forwarded to the actual Python authorizer: exact request accepted, changed body denied and replay rejected.
- Backend allow/deny/step-up, outage, forged or mismatched decisions, challenge expiration and concurrent replay, unknown builds, forged client evidence and invalid metadata.
- TLS trusted certificate success, untrusted certificate rejection and hostname/IP mismatch rejection.
- Missing/duplicate content length, invalid status, chunked/oversized/truncated/NUL responses, hanging backend and slow HTTP/TLS byte trickles.
- Forked checkpoint and evidence preparation rejection before inherited locks can hang the child.

Review caught and corrected an unbounded slow-trickle authorization wait and debugger detection that originally inspected only the leader thread. Separate adversarial tests caught blocking FIFO reads and huge-file hashing; these paths now reject bounded input. Worker ptrace regression tests reap the traced worker's exit event before waiting for the leader.

## Reproduce

From `elf/`:

```bash
uv venv .venv
uv pip install --python .venv/bin/python -e '.[dev]'
.venv/bin/python -m unittest discover -s tests -t . -v
.venv/bin/ruff check rasp_elf tests
.venv/bin/ruff format --check rasp_elf tests
.venv/bin/mypy --strict --follow-untyped-imports rasp_elf
```

The `ELF protection` GitHub Actions workflow runs the full ELF suite, strict types, lint and formatting on pull requests. Existing core CI provisions PostgreSQL and runs the verifier database tests skipped locally.

The tracing tests require Linux ptrace access to child processes. A restricted CI runner must grant that capability rather than silently skip the debugger tests. Native test fixtures use OpenSSL headers, GCC, `/proc`, and `strace`; static-input validation additionally compiles a static libc fixture.

From the repository root:

```bash
(cd verifier && python3 -m unittest discover -s tests -t .)
(cd hardener && python3 -m unittest discover -s tests -t .)
bash .github/scripts/check-native.sh
```

## Local artifacts

Generated demos are intentionally ignored by Git. Private demo signing keys stay outside the app bundles:

- `elf/dist/verified-demo/demo`: offline protected demo, with its signed manifest and runtime alongside it.
- `elf/dist/verified-online-demo/demo`: backend-enabled demo configured for `http://127.0.0.1:8788`.
- `elf/dist/demo-keys/`: demo publisher and backend keys, generated locally; private files have mode 0600.
- `elf/dist/verified-audit.jsonl`: records from the installed-wheel online and denied-connect smoke checks.

The backend used for smoke tests was stopped afterward. Run the offline artifact directly:

```bash
./elf/dist/verified-demo/demo hello
# Application: hello
```

To run the online artifact, first start the backend from `elf/`:

```bash
.venv/bin/rasp-elf serve \
  --publisher-public dist/demo-keys/publisher.pub \
  --decision-key dist/demo-keys/backend.key \
  --manifest dist/verified-online-demo/rasp.manifest \
  --port 8788
```

Use `--policy examples/policy.json` to deny connections while allowing startup. The denied-connect smoke proved that the application's destination listener received no connection.

## Environment

Linux x86-64, kernel `7.0.0-31-generic`, Ubuntu glibc 2.39, GCC 13.3.0, OpenSSL 3.0.13, Python 3.13.2, LIEF `1.0.0-d05b3499b`, cryptography 50.0.1. The wheel smoke used a separate installed environment and ran from `/tmp`, proving it included the runtime C source needed for packing.

## Limits and Android handoff

This is a binary injection and runtime interception prototype with a companion-file bundle. It does not encrypt or virtualize the original program, perform arbitrary instruction rewriting, support static/foreign ELF, or guarantee coverage of direct syscalls and existing network connections. The software client key can be extracted by an attacker controlling the app, so signed clean evidence is not independent attestation of the host. On-disk hashes do not prove that all live memory remains unchanged.

The native transport has an absolute two-second deadline per HTTP exchange; DNS lookup follows the system resolver's own timeouts. Task scans cap entries at 4,096 and each status at 64 KiB; file hashes cap size at 256 MiB. Fork/multiprocess protection remains unsupported. The reference backend keeps registration and challenges in memory and needs production authentication, rate limits and persistence through customer infrastructure.

Next platform work: APK analysis/rebuilding and developer signing; inject an Android bootstrap and reusable detector runtime; map supported framework/network checkpoints; adapt request evidence to Android hardware-backed keys and independent attestation; then run APK compatibility and attack tests. Existing Flutter tests and physical-device Android paths were not rerun as part of this ELF change.
