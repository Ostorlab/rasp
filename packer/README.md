# Packer

Adds the RASP runtime to a built app: an APK or an AAB for Android, an IPA for iOS. The packer returns the protected app unsigned: you sign it before you ship it.

Android APK/AAB packing rejects class maps above 8 MiB of UTF-8 plaintext and
individual business DEX files above 64 MiB before encryption/publication. These
are operational compatibility limits, not format maxima. See the
[native archive contract](../docs/android-archive-reads.md), including the
external AAB-to-APK metadata limitation.

The packer is a library. `rasp_packer.packer.pack` is its entry point, and the `rasp` command line is a thin client of it, so a job can pack an app without starting a process.

```python
import pathlib

from rasp_packer import packer
from rasp_packer import platforms

result = packer.pack(
    app=pathlib.Path("app.ipa"),
    platform=platforms.Platform.IOS,
    output=pathlib.Path("app-protected.ipa"),
    build_id="e6a8373149e83d008a5212b34bdd23bf637ad9561483c7a3c43b0a157c3f2a18",
    checks=["debugger", "hooks", "jailbreak"],
)
```

```
rasp pack app.ipa --platform ios --build-id e6a8373149e83d008a5212b34bdd23bf637ad9561483c7a3c43b0a157c3f2a18 --checks debugger,hooks,jailbreak --output app-protected.ipa
```

`checks` (`--checks` on the command line) is how the caller chooses the check groups the protected app runs. `pack` requires `checks`, and only the command line defaults it. Without `--checks`, the command line warns and packs the app with only the required check group, `identity`. An id that is not one of the platform's groups is skipped: the command line warns about it, and `pack` reports it in `skipped_checks`. See [Checks](#checks).

`pack` returns the path of the protected app, the app's package name and version, the build id, and the skipped check ids, `skipped_checks`. On iOS, the package name and version are `CFBundleIdentifier` and `CFBundleShortVersionString` from its `Info.plist`; on Android, they are the `package` and `android:versionName` of its manifest.

The packer adds a prebuilt runtime, which comes from the runtime build and is not in the repository. The packer looks for it in its package resources: see the README in `src/rasp_packer/android/resources/` and the one in `src/rasp_packer/ios/resources/`.

Ship each native build's `.capabilities.json` sidecar beside its binary in package resources,
as `cmake --install ... --component runtime` stages it. The packer verifies the pristine byte
digest before config insertion. Invalid present metadata raises `InvalidRuntimeError`;
missing sidecars pack as legacy with unknown capabilities (`PackResult.capability_bindings`
is `None`). `effective_checks` records config selection, not execution evidence. See
[the capability contract](../docs/check-capabilities.md) and [runtime build guide](../runtime/README.md#build).

## Local policy

`--local-policy policy.json` (Python `local_policy=`) embeds a bounded opt-in policy
for both Android and iOS.
Without `--local-policy`, the packer writes the exact legacy config and the app stays report-only. Any explicit
policy requires compatible policy-support descriptors and actual host ABI exports
for every injected native artifact. The packer reports effective policy/config
hashes; it cannot prove host adaptation. See [the local policy contract](../docs/local-policy-contract.md).

## Android

For Android the packer protects the app's code:

- it sorts the app's classes in process with the bundled native `dexsplit` extension. The classes under the app's package are the app's own code. The other classes, such as libraries, stay in the clear, as `classes.dex`, `classes2.dex`, ...;
- it encrypts the app's own classes, in dex files of their own, and stores each of these files as the asset `assets/business/<i>.dex`. It also stores the class map as `assets/rasp/map.bin`, encrypted too: the map names the dex file that defines each of these classes. It stores the key as `assets/rasp/key.bin`;
- it adds a small stub as the last dex file (`classesN.dex`), and sets `<application android:appComponentFactory>` to the stub's class, `co.ostorlab.rasp.RaspStub`, while leaving the app's own `<application android:name>` alone;
- it adds the native runtime as `lib/<abi>/librasp.so`, for each ABI the app has native libraries for, or for every ABI the runtime is built for when the app has none. Android installs the native libraries of one ABI only, so each of the app's ABIs needs the runtime. An app with native libraries for an ABI the runtime isn't built for is refused with `UnsupportedAbiError`. The packer writes the runtime config, which holds the build id and the checks, into the `.rasp_config` section of each `librasp.so`;
- it raises the app's `android:minSdkVersion` to 31 when it is lower, because the runtime supports Android 12 (API 31) and later. The protected app then doesn't install on older devices;
- it removes the app's v1 signature files from `META-INF/`, since the protected APK must be signed again.

For an AAB, the packer writes the same entries under `base/`, with the dex files under `base/dex/`, and edits its manifest the same way.

It reads the app's package and version from the `<manifest>` element. An APK whose manifest has no package, or no literal `android:versionName` (for example an `android:versionName` set to a `@string` resource), is refused with `InvalidApkError`, and so is one without a literal `android:minSdkVersion` on `<uses-sdk>`. An AAB is refused in the same cases, with `InvalidAabError`. An app that already holds the class map, or whose manifest already names the stub as its component factory, is refused with `AlreadyProtectedError`.

At run time Android loads the stub as the app's component factory, and the stub loads the runtime. The runtime starts the thread that runs the checks, and installs the on-demand class loader. The first time the app needs one of its own classes, this loader decrypts the dex file that defines it and loads it from memory.

The stub and the native runtime come from the runtime build. The packer looks for them under `src/rasp_packer/android/resources/` (see the README there), and raises `MissingRuntimeArtifactError` when they are missing.

The binary `AndroidManifest.xml` is edited in place by `android/apk/axml.py`, so the packer needs no Android build tool. The protected APK is returned aligned, with native libraries on 16 KB page boundaries and other stored entries on 4-byte boundaries, so it can be signed directly, with no separate `zipalign` step.

The key is stored in the clear, in `assets/rasp/key.bin`. The encryption raises the effort needed to read the app's code, but on its own does not defeat a determined analyst who reads the key from the app. `TODO.md` at the repository root tracks this limit.

## DEX selection and compatibility

The native reader, model, writer and link analysis support standard little-endian DEX
035, 037, 038, 039 and 040. Inputs must have valid digests, complete maps, typed item
boundaries and valid pools, instructions, debug records and encoded values. Unsupported
versions, opcodes, link sections and malformed inputs fail before publication. Every
rewritten output is read again before encryption. This protects Java/Kotlin DEX code;
it does not encrypt native libraries, Dart snapshots or Hermes bytecode.

For R8 releases, pass the exact build's mapping with `pack(..., mapping=path)` or
`rasp pack ... --mapping mapping.txt`. Without it, selection uses the manifest package.
Mappings are strict UTF-8 (BOM and CRLF accepted); malformed records, conflicting
originals, invalid names, an empty app selection or no target matching the input DEX
fail. Identical duplicates are deduplicated; legitimate many-to-one merges are accepted.
A partial mapping cannot prove that every app class was selected. All classes in each
selected obfuscated package are protected together, including colocated library classes.
A business package that cannot fit in one output DEX fails, because separate defining
loaders would break package-private access. Input definitions under `co.ostorlab.rasp`
are reserved. Preserve the runtime/bootstrap keep rules in the
[Android runtime guide](../runtime/android/stub/README.md) in the app's R8 configuration.

Operational limits are 64 MiB per input/rewritten DEX, 256 input and 256 output files,
256 MiB aggregate input and separately aggregate output, 100,000 unique classes,
1,048,576 aggregate input string IDs and nesting depth 64. Mapping limits are 64 MiB,
1,000,000 class records and 65,536 bytes per line. These are compatibility limits,
not DEX format maxima. A retained request also has **64,000,000 work units** (decimal,
not 64 Mi), **1,610,612,736 cumulative logical allocation bytes** (1.5 GiB), and
**536,870,912 cumulative retained native backing bytes** (512 MiB). Aggregate input
and output remain separately capped at 256 MiB each. Real apps can exceed these finite
limits even below the input size cap and fail explicitly. There is no automatic
larger-budget fallback.

Native allocations consume logical allowance before allocation, including pool reuse,
copies and retries; actual pool growth consumes backing allowance including headers,
alignment, upstream pool metadata and a fixed bookkeeping allowance. Neither counter
is refunded. OS/standard-allocator bookkeeping and total process RSS are outside this
portable byte counter. One request spans analysis, grouping, subdivision and output
reparsing. Direct bindings use the same defaults. `dexsplit._dex.Request(work=...,
storage=...)` may only lower them; nested scopes share counters. Models and analysis
handles retain the original request after scope exit. To combine models, read them
within one request; copying unrelated requests is rejected. Budget exhaustion never
triggers subdivision.

Direct C++ model copies, assignments, copy-on-write bodies and nested containers retain
their source request, including after scope exit. Growth under an unrelated active
request is rejected. Returned type-use descriptors own their storage and remain valid
after their context and method handles are released. Every mapped code item receives
the same structural instruction, register, branch, payload and try/handler checks,
including unused items; complete unused or shared items remain supported.
Unscoped native construction shares one retained default request per thread while its
values remain alive. An explicit native scope starts an independent request when no
scope is active; binding entry points keep their existing independent-request behavior.

Debug locals accept harmless redundant end/restart events, matching ART. Incoming
parameters initialize metadata only at their first register, including wide arguments.
Out-of-frame locals and restarts with no known metadata fail; the latter is an explicit
supported-subset restriction, rather than synthesizing local metadata.

Native model strings preserve UTF-16 units, including supplementary characters.
The unchanged JNI loader uses modified UTF-8 for class names, so supplementary
Unicode business class names currently fail explicitly; BMP business names and
supplementary string literals remain supported.

The [harmless SDK/ART fixture](tests/dexsplit/fixtures/app/README.md) reproduces plain
and R8 multidex APK/AAB inputs and documents the separate signing/device gate.
Host parsing and independent SDK format checks do not establish ART execution.

## Layout

- `src/rasp_packer/packer.py`: `pack`, the entry point.
- `src/rasp_packer/verification.py`: `verify`, the read-only post-pack verifier and its `VerificationResult`.
- `src/rasp_packer/platforms.py`: the platforms, Android and iOS.
- `src/rasp_packer/identity.py`: `AppIdentity`, the package name and version read from the app.
- `src/rasp_packer/checks.py`: the check groups of each platform, in the order the runtime runs them, and the ones every protected app runs. The packer skips an id that isn't one of them and reports it, so that a caller still packs when it passes a check group that was renamed or removed, and adds the ones every protected app runs.
- `src/rasp_packer/cli.py`: the `rasp` command line.
- `src/rasp_packer/ios/`: packing of IPAs.
  - `ipa.py`: unpacks and repacks the IPA, keeping file permissions, and reads the app's identity (`CFBundleIdentifier` and `CFBundleShortVersionString`) from its `Info.plist`.
  - `macho.py`: makes the main executable load the runtime (`LC_LOAD_DYLIB` and `LC_RPATH`) and removes its code signature.
  - `packer.py`: embeds `RaspRuntime.framework`, writes the runtime config into its binary, and removes the app's `_CodeSignature`.
  - `runtime_binary.py`: writes the runtime config into the `__DATA,__rasp_config` section of the framework's `RaspRuntime` binary.
  - `resources.py`: locates the prebuilt `RaspRuntime.framework`, under `resources/` (see the README there). The framework is prebuilt by the runtime build; without it the packer raises `InvalidRuntimeError`.
- `src/rasp_packer/android/`: packing of APKs and AABs.
  - `packer.py`: the Android `pack`. It sorts the app's classes, encrypts the app's own dex files and the class map, adds the stub as the last dex file, adds `librasp.so` for the app's ABIs with the runtime config written into it, sets the manifest's `appComponentFactory` to the stub, raises its `minSdkVersion`, and removes the v1 signature files of an APK.
  - `apk/`: reading and editing the APK.
    - `archive.py`: reading and repacking the APK (a ZIP).
    - `axml.py`: reading and editing the binary `AndroidManifest.xml`.
    - `manifest.py`: the layer over `axml.py` for the component factory, the app's package and version, and its minimum API level.
  - `aab/`: reading and editing the AAB, and its manifest, which is in protobuf format.
  - `cipher.py`: the authenticated cipher for the class map and the app's own dex files.
  - `split.py`: calls the native `dexsplit` extension in process, which sorts the app's classes into the app's own and the others.
  - `loader_map.py`: the class map, which names the dex file that defines each of the app's own classes.
  - `runtime_library.py`: writes the runtime config into the `.rasp_config` section of `librasp.so`.
  - `resources.py`: locating the prebuilt stub and native libraries, and the native splitter resources.
- `tests/`: one test file per source file, at the same path, named `<module>_test.py`.

## Development

Python 3.14 and [uv](https://docs.astral.sh/uv/).

```
cd packer
uv sync --locked
uv run ruff format --check .
uv run ruff check .
uv run mypy
uv run pytest
```

CI runs these commands plus the native core/binding compiler, format, clang-tidy,
CTest and ASan/UBSan/TSan gates (`.github/workflows/packer.yml`). For local native
checks use LLVM 23 and CMake 4.4.4: `cmake --preset dexsplit-host`,
`cmake --build --preset dexsplit-host --parallel 2`, and `ctest --preset dexsplit-host`.
Use `dexsplit-asan` and `dexsplit-tsan` for the sanitizer presets. The native fixture
generator and `tests/dexsplit/fixtures/validate.py --dexdump /path/to/dexdump`
provide independent SDK35 validation for every supported version.

## Build id

Every protected build has a build id, which the packer writes into the app. The caller chooses it and passes it to `pack` (or to `rasp pack --build-id`). The packer accepts any id: it writes it as it is and does not check its format. It only refuses an id it cannot write: an empty one, one with control characters, or one too long for the space the runtime keeps for its config.

## Checks

The runtime runs its checks in groups, such as `debugger` or `hooks`. `src/rasp_packer/checks.py` lists the groups of each platform in `CHECKS`, and each platform's required groups in `REQUIRED_CHECKS_BY_PLATFORM` (currently `identity` on both). `REQUIRED_CHECKS` remains the compatibility view of groups required on every platform. The caller chooses the groups a protected app runs and passes their ids to `pack` (or to `rasp pack --checks`, comma-separated). The packer:

- skips an id that is not one of the platform's groups and reports it in `PackResult.skipped_checks`, so that a caller, such as a CI job, still packs when it passes a group that was renamed or removed. The command line warns about each skipped id on stderr, such as `rasp pack: warning: 'oldcheck' is not a check of android, skipped`, and packs the app;
- adds the required groups, so `checks=["debugger", "hooks", "jailbreak"]` on iOS also runs `identity`;
- writes the ids sorted into the runtime config.

An empty choice, such as `checks=[]`, runs only the required groups. Without `--checks`, the command line warns and packs the app with only the required groups.

## Post-pack verification

Post-pack verification catches lost or replaced protection artifacts, including the manifest, injected runtime and encrypted payload, before the output is created.

Before creating the requested output file, `packer.pack` and `rasp pack` verify the staged archive. The platform packers use the same verification path when called directly. Packing writes to a temporary directory beside the destination, verifies that archive, then atomically creates the destination without overwriting an existing file. Failed packing or verification removes the staging files. The destination filesystem must support hard links. A missing or unusable output parent, or a failed hard link, produces a clean packer error; publication never falls back to replacement or copying.

The CLI reports `unsigned, structurally verified` on success. A verification failure raises `errors.VerificationError` in the library and exits with status 1 and a diagnostic on stderr in the CLI.

Unknown requested checks keep the existing skip-and-report behavior. `pack` resolves the configured checks to the required checks plus every supported requested check, sorted and de-duplicated. Verification requires the embedded configuration to match the declared build id and that exact resolved check sequence.

`rasp_packer.verification.verify(app=..., platform=..., config=..., expected_entries=...)` is the reusable read-only API:

- `config` declares the build id and the canonical check sequence: supported checks only, sorted and de-duplicated, including all required checks.
- `expected_entries` maps ZIP paths to the **trusted bytes prepared for injection**, including every injected/replaced manifest, loader, runtime and payload entry. Keep those bytes from the packing step; deriving them from an untrusted output would defeat replacement detection. The platform packers construct this contract automatically.

The API returns `VerificationResult` with the artifact format (`apk`, `aab`, `ipa`), app identity, declared config and verified runtime paths, or raises `VerificationError`. There is no separate standalone CLI verifier because verifying replacement requires this trusted injection contract.

The checks are deliberately structural:

| Artifact | Verified contract |
| --- | --- |
| All formats | Unique canonical ZIP member paths; no traversal, file/directory aliases, symlinks, encryption or unsupported compression; injected bytes present at their exact paths; embedded config exactly matches the canonical declared config. |
| APK | Binary manifest identity, RASP component factory and minimum API 31; base DEX entries; runtime for every native ABI; runtime ELF machine, bitness, little-endian encoding and shared-library type match its ABI directory; authenticated key/map/business payload coherence; stored payload members; actual local ZIP data alignment (16 KiB for stored `.so`, 4 bytes for other stored files). |
| AAB | Protobuf base manifest, `base/dex`, `base/lib` and `base/assets` paths; the same runtime ELF/config and authenticated payload checks for the base module. Feature modules and unrelated assets are preserved, without imposing base-module ABI coverage or APK alignment on feature delivery. |
| IPA | Exactly one main app bundle; its executable retains execute permission; main executable and embedded runtime are unencrypted arm64 Mach-O files of executable/dylib type respectively; the executable strongly loads `@rpath/RaspRuntime.framework/RaspRuntime` with `@executable_path/Frameworks`; the framework plist names `RaspRuntime`; every runtime slice contains the declared config. Other architectures and encrypted App Store executables are rejected. |

Read limits:

- ZIP: at most 4 GiB on disk, 100,000 members and 4 GiB total uncompressed. Each member is limited to 4 GiB uncompressed; APK/AAB readers retain their stricter 1 GiB total.
- Manifests/plists: at most 4 MiB; runtime binaries: at most 256 MiB.
- Embedded config sections: entirely inside the binary, at most 64 KiB and zero-terminated.
- Encrypted Android class map: at most 16 MiB.

Empty business-code sets are valid and need no encrypted business DEX.

`assets/rasp/` and numbered `assets/business/<i>.dex` entries are reserved for packer output.

Verification limitations:

- Output remains **unsigned**. Structural verification is not proof of installation, successful device execution, attack resistance or runtime provenance.
- The verifier trusts the runtime build and upstream DEX splitter, and compares loader/payload bytes without adding another DEX parser.
- It does not run checks on a device or validate store signatures. AAB `native.pb`/`BundleConfig.pb`, delivery configuration, generated split APKs and their final alignment are not certified here. Google Play/bundletool generate those APKs; validate, sign and test the generated artifacts with the target platform tools before shipping.
- Fixture-sized runtime binaries exercise the archive/config contract in tests; real Android and iOS builds and devices remain separate platform validation.

See [opt-in Android root and environment context](../docs/android-root-context.md) for fixed manager visibility queries, own mount context, public proxy metadata and unsupported developer-settings truth. Existing root/jailbreak refusal observations do not prove an intact stock platform.
