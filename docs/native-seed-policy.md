# Native compiler seed policy

The existing iOS Release build defaults O-MVLL on for `RaspRuntime`'s own source
files. Its linked core/plugins/third-party libraries compile without the plugin;
Android and host builds have no plugin integration here. iOS Debug defaults off.
This change freezes existing iOS compilation inputs. It adds no new transformed
targets, passes, artifact sidecar, packer option or backend protocol.

`RASP_OMVLL_SEED` is an **environment** input: canonical ASCII decimal `0` or
`[1-9][0-9]{0,9}`, at most 10 bytes, numeric range **0..2147483647**. Signs,
negative values, whitespace, leading zeroes, non-ASCII digits, hex, exponents,
underscores and overflow fail. Invalid input is not echoed, truncated or masked.

| Seed | `RASP_OMVLL_SEED_MODE` | Captured policy |
|---|---|---|
| Absent | Absent or `default` | Seed 1, mode `default` |
| Canonical value | Absent | Exact value, mode `explicit` |
| Canonical value | `explicit`, `release` or `diagnostic` | Exact value and supplied mode |
| Present | `default` | Error |
| Absent | `explicit`, `release` or `diagnostic` | Error on initial configuration |
| Any | Empty/unknown mode | Error |

For example, on the supported macOS arm64/Xcode host:

```sh
RASP_OMVLL_SEED=42 RASP_OMVLL_SEED_MODE=diagnostic cmake --preset ios
cmake --build --preset ios --parallel 2
```

Configuration captures `omvll-seed-policy.json` in the build directory. Generated
compiler commands carry its SHA256. Regeneration verifies that document and
preserves the same seed/mode when the original shell environment is absent.
Changing the seed/mode requires a new build directory. A deleted/corrupt captured
policy fails rather than resetting an existing build's seed. `release` requires
an externally selected frozen seed; this code creates no release-attempt store
and draws no random seed during configuration or compilation.

Every C/C++/Objective-C++ invocation of the existing protected target uses the
launcher. It checks the actual plugin, config, shared seed parser, launcher and
generated YAML content hashes. It walks the compiler's real working directory
and parents exactly where upstream first looks for `omvll.yml`; a nearer YAML,
missing YAML or different YAML is refused instead of falling back to another
configuration. Inherited `OMVLL_CONFIG`/`OMVLL_PYTHONPATH` must agree with the
captured paths. Inherited seed/mode settings, if supplied, must agree with the
frozen values; absent settings are supplied from the captured policy. The default
mode passes an absent seed plus `default`, which the shared parser resolves to 1.
An explicitly supplied seed together with `default` is invalid on initial
configuration, reconfiguration and launch, even when the supplied seed is 1.

The pinned plugin imports the config by its filename stem, not by exact file
location. Validation therefore requires a single `.py` root and refuses dotted,
reserved/preimported names and same-stem package/native/bytecode candidates before
the child runs. It uses a standard file finder without executing custom config.
Native suffix checks include foreign-ABI candidates rather than assuming the
host interpreter's suffix list describes embedded Python3.10. The same checks
cover candidates for the shared `omvll_seed` helper; its launcher bootstrap
executes only the owned helper source, bypassing preimports and stale `.pyc`.
Custom config dependencies remain trusted and outside this root-only check.
Reserved names include CPython3.10.7's standard-module names (including platform
and version-specific builtins), the plugin's known `sys`, `pathlib`, `omvll`
preimports, and the launcher's loaded/builtin/frozen/stdlib names and names in
the selected stdlib source directory. This is a fixed root-name reservation,
not custom dependency discovery. Python3.14 controls do not establish actual
embedded Python3.10 behavior; the genuine Apple load remains a CI gate.

The default extracted dylib must match `omvll-xcode.dylib` in the archive already
SHA-verified by CMake. Existing explicit `RASP_OMVLL_PLUGIN`,
`RASP_OMVLL_PYTHONPATH` and `RASP_OMVLL_CONFIG` overrides remain usable when their
resolved identities can be captured and verified. An override is trusted build
code, not an approved protection profile: a custom config can ignore the seed or
choose different passes. Imported custom dependencies and Python stdlib contents
are not comprehensively inventoried by this Stage A policy. Future protected
profiles need separately approved immutable inputs and actual target validation.

The launcher retains child argv, working directory and exit status without a
shell. It rejects a second/different pass plugin and indirect response/config or
working-directory arguments, whose contents/search boundary it cannot verify.
Inherited `CCC_OVERRIDE_OPTIONS`, `CL` and `_CL_` are refused before the driver
can rewrite its checked argv. The compiler child receives
`CLANG_NO_DEFAULT_CONFIG=1`, disabling automatic Clang config files; explicit
config-file arguments remain refused. These are targeted driver channels, not
a complete compiler/process custody or dynamic-library-loader sandbox.
It removes inherited Python import-path/home/startup injection from the compiler
child, clears `PYTHONCASEOK`, and uses a fresh temporary bytecode-cache prefix
with bytecode writing off.
Actual embedded Python behavior remains an Apple validation gate. The launcher
does not sandbox custom config or protect against an attacker controlling the
build process and all its trusted files; hashes establish correspondence within
that build's custody, not authenticity.

Explicit seed settings with iOS protection off fail instead of being ignored.
`-DRASP_OMVLL_SEED=...` and `-DRASP_OMVLL_SEED_MODE=...` are unsupported and fail;
use environment inputs. Ordinary Debug with no such settings remains unchanged.
Android defaults remain unchanged and do not acquire seed/protection support.

The seed is a reproducible diagnostic **input**, not a cryptographic key or
evidence of key secrecy or extraction resistance. The pinned plugin uses it for
some probability and transform choices; function shuffling uses a separate
default-seeded generator. One seed does not prove reproducible native binaries,
packages or timings. No platform execution, performance or attack-resistance
claim follows from parser/launcher tests.

Run the harmless process and real Linux CMake negative controls without loading
the Apple plugin:

```sh
python3 -I -B -m unittest discover -s runtime/cmake/tests -p '*_test.py'
```

Actual protected compilation/execution still requires the approved Apple
compiler/plugin pair. No SDK substitution or Android plugin download is used.
