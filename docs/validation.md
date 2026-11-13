# Local validation foundation v1

`validation/run.py` runs two fixed software routes and independently verifies a
private result bundle. It is a reproducibility tool, not a security sandbox,
attestation service or certification. No backend state or catalogue is changed.
The [design](../contracts/validation-foundation.md) records field and resource
limits; its implementation addendum incorporates the root amendments.

The real host fixture calls the production primitive C API in a fresh process.
Its clean control appends one in-memory receipt. The gated operation sees
NOT_READY and appends none. That is **ERROR/runtime_unavailable**, even when the
test conforms. It cannot pass release, detection, denial or effectiveness gates.

The Android fixture uses the actual packed `RuntimeBridge`, a host-compiled policy
expectation and real monitor publication. The clean operation must return OK+ALLOW
and append once; a changed request hash must return OK+DENY/HASH_MISMATCH without
appending. Configuration rejection is not an attack measurement. VPN,
accessibility, IME and support contexts remain context; their v1 device routes are
NOT_RUN. Apple execution and performance/effectiveness acceptance are also NOT_RUN.

## Reproduce the host route

Use Python 3.14 and the repository CMake/compiler prerequisites. Work from a clean,
committed repository root. Use a new private build directory; never reuse a build
made from another checkout. On Linux the plain fixture is static; sanitizer builds
are separate CTest checks and cannot be used under the plain runner's address cap.

```sh
cmake -S runtime -B /tmp/val01-build -DRASP_BUILD_TESTS=ON -DRASP_PLUGINS= \
  -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++
cmake --build /tmp/val01-build --target rasp_validation_host --parallel 2
ctest --test-dir /tmp/val01-build -R '^ValidationHost\.' --output-on-failure
```

The following standard-library recipe constructs a concrete plan. The receipt
must be reviewed alongside compiler/build logs and source association before use;
it is not self-authenticating. It deliberately marks the host cell required so
the release gate fails, despite expected startup conformance.

```python
import pathlib
import subprocess
from validation import run

destination = pathlib.Path('/tmp/val01-inputs')
destination.mkdir(mode=0o700)
head, tree = subprocess.check_output(['git', 'rev-parse', 'HEAD', 'HEAD^{tree}']).decode().splitlines()
files = []
payloads = {
    'host': ('host_executable', pathlib.Path('/tmp/val01-build/tests/rasp_validation_host').read_bytes()),
    'registry': ('registry', pathlib.Path('/tmp/val01-build/rasp_plugins.cpp').read_bytes()),
    'runner': ('suite_source', pathlib.Path('validation/run.py').read_bytes()),
    'suite': ('suite_source', pathlib.Path('validation/suite.json').read_bytes()),
    'fixture': ('fixture_source', pathlib.Path('validation/fixtures/host.c').read_bytes()),
}
receipt = {'version': 1, 'source_head': head, 'source_tree': tree, 'tool_ids': [],
           'flags': ['static', 'RASP_PLUGINS='], 'plugins': [], 'registry_file': 'registry',
           'products': ['host'], 'dependency_manifest': None}
payloads['receipt'] = ('build_receipt', run.canonical(receipt))
for file_id, (role, data) in payloads.items():
    run.write_file(destination, file_id, data)
    files.append({'id': file_id, 'path': file_id, 'role': role, 'bytes': len(data), 'sha256': run.sha(data)})
suite = sorted((row for row in files if row['role'] in {'suite_source', 'fixture_source'}), key=lambda row: row['path'])
cell = {'id': 'host', 'adapter': 'host_c', 'scenario': 'host_startup_unavailable', 'context': 'clean',
        'facility': 'host', 'target': run.host_environment(), 'required': True, 'artifact_ids': ['host'], 'expected': 'error'}
plan = {'version': 1, 'source_head': head, 'source_tree': tree,
        'build_receipt_sha256': run.sha(payloads['receipt'][1]),
        'suite_sha256': run.sha(b'val01.suite.v1\0' + run.canonical(suite)), 'files': files, 'cells': [cell]}
run.write_file(destination, 'plan.json', run.canonical(plan))
```

```sh
python3.14 validation/run.py run --plan /tmp/val01-inputs/plan.json \
  --inputs /tmp/val01-inputs --output /tmp/val01-result
python3.14 validation/run.py verify --plan /tmp/val01-inputs/plan.json --bundle /tmp/val01-result
```

Both commands return **1** for this valid bundle because required startup ERROR
cannot satisfy release. The printed summary says conformance pass and release
fail. Return 2 rejects malformed/binding-invalid evidence; 3 reports I/O failure.
Partial output directories cannot be used as completed bundles. Reverification is
idempotent and does not create samples. Never edit a bundle to turn a missing or
failed cell into a pass. Every planned cell, including errors and absent devices,
stays in the denominator; zero-cell plans and zero/invalid samples are rejected.

## Android preparation and explicit lab invocation

The host route uses only the standard library. Android preflight additionally
requires the **pinned installed** production `rasp-packer`, `lief`, `cryptography`
and their installed dependency closure. No source PYTHONPATH substitution is
accepted. Native resources/stub must come from the corresponding approved build.
Build only the harmless source fixture, with API35+ public SDK and the production
compile-only bridge jar:

```sh
PACKER_PYTHON=/private/pinned-venv/bin/python \
ANDROID_JAR=/private/sdk/platforms/android-35/android.jar \
ANDROID_BUILD_TOOLS=/private/sdk/build-tools/35.0.1 \
bash validation/fixtures/android/build.sh /tmp/val01-android \
  /private/matching/runtime-bridge-compile-only.jar docs/fixtures/local-policy-android-v1.json
/private/pinned-venv/bin/rasp pack /tmp/val01-android/host-unsigned.apk \
  --platform android --build-id val01 --checks debugger \
  --local-policy docs/fixtures/local-policy-android-v1.json --output /tmp/val01-android/protected-unsigned.apk
```

The generated `ExpectedPolicy.java` and its digest belong in the build receipt.
The original sample Activity's stale constant is not modified or reused.
Compile and unsigned packing do not establish signing, installation or execution.
The runner never signs, installs/uninstalls, provisions, enrolls, changes settings,
starts another app to inspect terminated memory, or accesses customer/provider
accounts. Lab owners separately supply the exact preinstalled signed fixture.

An Android plan includes the signed APK, all pristine/injected native bytes and
sidecars, stub, bridge jar, policy/config, exact injected archive entries, generated
source and pinned wheels. Its `injection_manifest` is the closed record described
in the addendum. Preflight calls the production policy parser, resource loader,
capability/support/export/config binders, archive checks and packed-artifact
verifier. The full installed wheel contents and file-backed runtime mappings
must match the pinned dependency manifest, rechecked before/after tool execution.

Without explicit `--lab LAB_ID`, there are **zero ADB invocations**, including help
or server discovery. The result is NOT_RUN/facility_missing; it cannot satisfy a
required release cell. A future authorized lab invocation uses the same `run`
command plus `--lab LAB_ID` and a reviewed, hash-pinned provisioning receipt.
V1 supports isolated, preauthorized USB labs only. Emulator cells are NOT_RUN.

The lab descriptor pins a private preprovisioned ADB home with existing authorized
keys; no key generation/enrollment is permitted. It must state USB and network
isolation. `--one-device` restricts USB, not all transports. The supervisor starts
the pinned ADB 35.0.2-12147458 as `-L localfilesystem:PRIVATE_SOCKET --one-device
SERIAL server nodaemon`. Every client carries `-L PRIVATE_SOCKET -s SERIAL`.
This uses the [upstream command API](https://android.googlesource.com/platform/packages/modules/adb/+/refs/heads/main/client/commandline.cpp)
and verifies local help from the pinned binary before startup.

Client children have RLIMIT_NPROC=0 to prevent daemon auto-start even if the owned
server fails between checks. V1 refuses root execution, unsupported tool shapes
and clients needing additional threads/processes. It never kills the default
server. It kills/reaps its own foreground group, captures bounded server output,
and checks its exact socket removal and unchanged preprovisioned key metadata.
These software controls have local transport tests; actual USB execution still
requires measured lab evidence. The orchestrator cannot supply network/device
isolation; provisioning must enforce it.

Installed APK reads are a separate binary path: at most 64 MiB each and 256 MiB
aggregate, retained with count/hash and exact inventory reference. Text evidence
remains <=256 KiB/file and <=16 MiB total. A hash without its retained binary
fails offline verification. Cleanup force-stops only `fixture.validation`, deletes
only the nonce XML, verifies absence/PID termination and rechecks the installed
APK. It does not claim to inspect process memory after termination.

## Checks and detector review

```sh
VAL01_HOST=/tmp/val01-build/tests/rasp_validation_host \
  python3.14 -m pytest -p no:cacheprovider validation/tests/run_test.py
```

The suite exercises real killed/reaped local children and the production C gate,
plus artifact/source/policy/setup/cleanup forgery, cross-phase/duplicate evidence,
bounds and missing cells. Labelled Android transport fixtures exercise protocol
logic only. They supply no detector effectiveness or physical-device credit.
Paired measurement records require 30..64 expected pairs, <=64 actual pairs across
the suite, two distinct <=8 KiB evidence files/pair and exact missing-index lists.
No collector/budget or performance acceptance exists here. VAL02 owns performance
collection/budgets; VAL03 owns the broader benign/false-positive matrix.

Every detector change review records:

- Exact threat model, platform, source/status meanings and semantic rule version.
- Actual production entry path; clean, unavailable and attack fixture references.
- Benign VPN/accessibility/IME/support/OEM limitations and missing device cells.
- Owner/reviewer, source/artifact/policy/suite hashes and reproduction instructions.
- Separate observed detection, host-confirmed denial, bypass, crash/error and
  unsupported/NOT_RUN counts. Client observations never prove malware or authorize
  server transactions. No numerical public claim without measured populations,
  paired conditions, failures, denominators and uncertainty.

See the [research evidence index](research/index.md). Private bundles are 0700
directories with 0600 data and 0700 executable snapshots. Lab owners retain them
through review/recovery, then explicitly erase them. The runner never uploads
evidence, logs credentials or automatically erases failure evidence.
