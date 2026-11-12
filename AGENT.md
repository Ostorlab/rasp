# AGENT.md

Guidance for coding agents working in this repository.

## What this repository is

The production source of Ostorlab Mobile RASP:

- `packer/`: the packer, in Python. It takes a customer's built app (an APK or an IPA), adds the runtime, and returns the protected app unsigned. The customer signs it.
- `runtime/`: the runtime libraries, in C++. They run inside the protected app and run the checks.

Read `README.md`, `packer/README.md` and `runtime/README.md` for the layout of each part.

## Packer

A library first: `rasp_packer.packer.pack` is the entry point, and the `rasp` command line (`cli.py`) is a thin client of it. Keep logic out of the command line.

Run what CI runs (`.github/workflows/packer.yml`), from `packer/`:

```
uv sync --locked
uv run ruff format --check .
uv run ruff check .
uv run mypy
uv run pytest
```

- mypy runs in strict mode over `src` and `tests`.
- Tests: one file per source file, at the same path under `tests/`, named `<module>_test.py`. Test functions are named `test<Action>_when<Condition>_<result>`, for example `testPack_whenOutputExists_raisesOutputExistsError`.
- The packer looks for the prebuilt runtime in its package resources: `rasp_packer/ios/resources/RaspRuntime.framework`, and `rasp_packer/android/resources/stub.dex` with `rasp_packer/android/resources/lib/<abi>/librasp.so`. They come from the runtime build and are not in the repository. Without them, packing an IPA raises `InvalidRuntimeError`, and packing an APK or an AAB raises `MissingRuntimeArtifactError`. Tests use fixtures instead.

## Runtime

Read `runtime/CONTRIBUTING.md` before changing anything in `runtime/`. It holds the rules CI enforces and the ones reviewers check, and the tool versions. The two facts behind them: the runtime runs in the customer's process, so a crash in our code crashes their app; and the attacker controls the device, so anything in the binary, the logs or the files helps them.

The rules that most often matter:

- No exceptions and no RTTI. Functions that can fail return `std::expected`, `std::optional` or a status, marked `[[nodiscard]]`.
- Never end or take over the process: no `exit`, `abort`, signal handlers, `setenv` or `setlocale`. A child created with `fork` calls `_exit` at once and nothing else.
- No global objects with a constructor or destructor; use `constexpr` constants. No recursion, and no more than 4 KB of stack per function.
- Checks report observations (`signal`, `source`, `status`, `value`).
- Release builds log nothing. Log only with `rasp::log`, inside `if constexpr (rasp::kLoggingEnabled)`.
- Platform code goes in its platform folder (`ios/`), chosen by CMake. Every check is platform code. `core/` uses no platform API and has no platform `#if`.
- Document every file and function with `///`, and write no other comments.

Run what CI runs (`.github/workflows/runtime.yml`), from `runtime/`, with LLVM first in `PATH`:

```
git ls-files -z -- '*.h' '*.cpp' '*.h.in' | xargs -0 clang-format --dry-run --Werror
cmake --preset host && cmake --build --preset host --parallel && ctest --preset host
run-clang-tidy -quiet -p build/host "^$PWD/(?!build/).*\.cpp$"
```

- The tests must also pass under the `host-asan` and `host-tsan` presets.
- The host build doesn't compile the iOS code. The `ios` and `ios-dev` presets need a Mac with Xcode; on a Mac, also run `run-clang-tidy -quiet -p build/ios-dev "^$PWD/ios/src/.*\.cpp$"`.
- Fix clang-tidy findings instead of adding `NOLINT`.

## Pull requests

- Every change goes through a pull request.
- Titles start with a type, for example `feature: pack iOS apps` or `chore: add CODEOWNERS`.
- Before pushing, run the CI commands above for the part you changed.
