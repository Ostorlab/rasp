# Private release assurance

Three private release-assurance tools live in `assurance/`: build-bound encrypted
crash maps, redacted evidence export, and a configurable device-farm regression
gate. They bind evidence to release artifacts and keep missing evidence explicit.

Install locally with `python -m pip install -e ./assurance`. These tools do not
publish packages. Keep maps, credentials, and device logs in operator-controlled
storage outside the repository.

## Build-bound crash maps

The hardener emits `symbols.map` as `{obfuscatedSymbol: originalSymbol}`. Before
distributing a stripped binary, archive that exact map against the final binary:

```sh
rasp-crashmap archive --tenant tenant-a --app com.example.app --build BUILD_ID \
  --artifact release/librasp_core.so --symbols private/symbols.map \
  --key-file /run/secrets/crashmap-key --store /private/crashmaps
rasp-crashmap upload /private/crashmaps/ARCHIVE_ID.rmap \
  --url https://artifacts.example.com/private/ARCHIVE_ID.rmap
rasp-crashmap symbolize --tenant tenant-a --app com.example.app --build BUILD_ID \
  --artifact release/librasp_core.so --archive /private/crashmaps/ARCHIVE_ID.rmap \
  --key-file /run/secrets/crashmap-key --trace private/crash.txt
```

`rasp-crashmap archive` writes to `--store` and prints a JSON `archive` path.
Use that exact path for upload and symbolization; `ARCHIVE_ID` stands for its
filename stem, derived from the authenticated binding hash.

The key file contains exactly 32 random bytes provisioned by the deployment
secret store. Upload uses `RASP_ARTIFACT_TOKEN`, HTTPS system trust, a bounded
request timeout, and no redirects. Only the AES-256-GCM encrypted archive is
uploaded. The configured artifact service must authorize the destination's
tenant/app scope. Local archive files are immutable and mode 0600. Tenant,
application, build and final binary SHA-256 are authenticated; a map for another
binary or scope is refused. Store the wrapping-key version identifier beside
each archive so rotating the deployment secret does not orphan older maps.
Retain the matching key securely; the identifier alone cannot decrypt an archive.
Symbolization replaces complete symbol names; address-to-line resolution still
requires the matching private debug symbols and platform symbolizer.

## Evidence export

`rasp-evidence` converts a trust-service report into a redacted evidence export:
it strips free-text, marks authenticity `not_verified_by_exporter`, and maps
detector IDs to reviewed OWASP references.

```sh
rasp-evidence private/verified-report.json --artifact release/app.apk --platform android
```

Input is a decoded report with a `signals` array. The exporter deliberately does
not verify attestation or the report MAC: use the trust service for that before
export, and retain its evidence separately. Output marks authenticity as
`not_verified_by_exporter` and compliance as `not_assessed`. It removes free-text
evidence and maps reported detector/threat identifiers to applicable references.
No signals is **not** a passing compliance result.

The [mapping table at revision `7f0941d`](https://github.com/Ostorlab/rasp/blob/7f0941de0541fc30a72c81e06c18b6776b524497/assurance/rasp_assurance/evidence.py)
records the references reviewed on 2026-09-28 against the official
[MASVS controls](https://mas.owasp.org/MASVS/), [MASWE index](https://mas.owasp.org/MASWE/),
and [MASTG test index](https://mas.owasp.org/MASTG/tests/). Re-run the mapping review
when those indexes add, rename, or deprecate referenced identifiers, or when the
mapping table changes. This pins this tool's reviewed mapping, not an upstream
OWASP release or a claim that future index revisions were verified.
The current Android tests include [emulator detection](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0351/)
and [debugging detection](https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0353/).
Where there is no applicable current test, the mapping uses a knowledge article
or leaves the field null. Deprecated test identifiers are not presented as current.

## Configurable device-farm regression

`rasp-device-farm private/farm.json --junit private/results.xml` runs trusted
operator-supplied preparation/probe/cleanup adapters for local devices or a
remote device farm. Commands are argument arrays, never shell strings. Run the
runner on Linux/macOS in a dedicated lab; adapters must target your provisioned
test devices and application. Cleanup runs even when preparation or probing
fails. The command timeout includes a 100 ms reserve for process-group kill and
reaping; output is bounded, and raw logs/tokens are not copied into result artifacts.
The final wait uses only the remaining deadline. If a kernel task cannot be
reaped after a repeated kill and final nonblocking wait, the case records an
error rather than waiting indefinitely. Uninterruptible kernel tasks can outlive
the caller; Python's subprocess cleanup may reap them later, or the operating
system adopts them when the runner exits. This is not a process sandbox.

Configuration example (adapter paths are supplied by your lab):

```json
{
  "platform": "android",
  "device": "lab-pixel-api35",
  "artifact": "/private/release/app.apk",
  "cases": [{
    "scenario": "frida-fork",
    "prepare": ["python3", "/private/lab/frida_fixture.py", "prepare"],
    "probe": ["python3", "/private/lab/protected_transfer.py"],
    "cleanup": ["python3", "/private/lab/frida_fixture.py", "cleanup"],
    "timeoutSeconds": 120
  }]
}
```

Adapter environments contain only inherited `PATH` and `HOME`, plus the two
runner-owned variables. Provision device access through the operator-owned
adapter; ambient credentials such as `RASP_ARTIFACT_TOKEN` are not forwarded.

Each adapter receives `RASP_FARM_ARTIFACT` and `RASP_FARM_CONTEXT` containing
`runId`, `device`, `artifactSha256`, and `scenario`. The probe returns exactly
those binding fields plus `fixtureVerified`, `baselineAllowed`, and `enforced`
booleans. Verify the attack setup independently (for example the expected Frida
fork is attached, hidden root really exists, or the modified APK is installed),
then perform a protected operation against the trust/resource service. A clean
positive control with the same business credentials must work; network errors,
login failures and crashes are not successful security denials. Baseline expects
`enforced:false`; attack cases expect `true`.

The required matrix includes baseline, Frida fork, hidden root (Android) or
jailbreak (iOS), attestation spoofing, attestation relay, and static patching.
Missing scenarios become `not_run` and fail the release gate. Fresh run/device/
artifact binding prevents accidental reuse of stale adapter output, but adapters
are trusted measurement code, not a cryptographic attestation authority. This
repository supplies the orchestration and gate, not root/jailbreak images or
live vendor attestation credentials. Unit adapters are never recorded as device
bypass results.

## How are physical-device performance budgets measured?

The included `verifier/` package provides release size and latency gates. Install
it with `python -m pip install -e ./verifier` from the repository root, then run
`python -m rasp_verifier.budgets`. See [validation commands and the measurement
format](../docs/validation.md#how-do-i-run-the-performance-and-size-gates).

This branch does not include a mobile scan benchmark collector. Provide a device
adapter that measures the actual scan operation and emits at least 30 finite,
nonnegative `samplesMs` values with a `device` identifier. Tag emulator samples
explicitly and evaluate physical reference devices separately. Neither host
timing nor mocked samples establish physical-device performance. Preserve the
artifact SHA-256, OS, device model, build mode, warmup method, measurement
conditions, and sample file with the release evidence.
