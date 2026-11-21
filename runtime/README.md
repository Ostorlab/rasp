# Runtime

The C++ runtime that the packer adds to a protected app. It runs the checks inside the app.

## Build

The presets are in `CMakePresets.json`. You need CMake 4.4 or newer.

| Preset | Builds | Needs |
|---|---|---|
| `host`, `host-asan`, `host-tsan` | the code and its tests for a development machine, plain or with sanitizers | Clang from LLVM 23 first in `PATH` |
| `android`, `android-dev` | the Android runtime, release or development | the Android NDK in `ANDROID_NDK_HOME`, the Android SDK in `ANDROID_HOME`, and a JDK |
| `ios`, `ios-dev` | the iOS framework, release or development | a Mac with Xcode |

```
cd runtime
cmake --preset host
cmake --build --preset host
ctest --preset host
```

The Android runtime is built for one ABI at a time: pass `-DANDROID_ABI=arm64-v8a` or `-DANDROID_ABI=x86_64` when you configure it.

The Android stub is Java and is built by a script, not by CMake. Set `ANDROID_JAR` to a platform's `android.jar` and put the SDK's `d8` on `PATH`:

```
ANDROID_JAR="$ANDROID_HOME/platforms/android-36/android.jar" android/stub/build.sh <output folder>
```

## Detection actions

The packer writes report-only groups under `r`, a mask in the same platform order as the checks mask `m`.
The enabled state comes from `m`, or the config's check list when no mask is readable. A group has three states:

- **Off:** monitoring skips it; detections of that group from startup or Android loader checkpoints arm nothing.
- **Report only:** the enabled group runs in monitoring and its detections arm nothing at every call site.
- **Block:** the enabled group's detections arm a delayed process end at startup, in monitoring and at checkpoints.

This changes `main`: startup and checkpoint checks previously blocked whatever `--checks` selected.
A missing or invalid `r` makes enabled groups block. If neither an enabled mask nor a list is readable,
all detections still block, including when `r` is present. Unknown signals and groups without a platform bit block.
Only blocking detections choose the panic delay: `dbg.`, `hook.` and `virt.` use 100–500 ms, others use 1–3 s.

Every entry in `panic.cpp`'s verdict table names its group, for both value findings and source disagreements.
`sig.cert_sha256` belongs to identity; `hw.machine` belongs to emulator. They have informational value verdicts,
as do `cs.*` and `hook.foreign_libs`. The packer tests check every built-in signal constant against this table,
and check both platform mask orders against dispatch. The loader keeps one immutable config in its shared state.

`integ.monitor_alive` stays with `integrity`. On Android, with integrity Off or report-only, a stalled monitoring
thread no longer ends the app through panic. iOS has no integrity bit, so this unexpected signal still blocks there.
Plugins receive complete monitoring observations; the response filter only acts on the separate detections.
Off and report-only do not disable Android's independent DEX key schedule; see the
[root README](../README.md#report-or-block). The config remains unauthenticated, with the same limit for `r` as `m`.

## Logs

Only the development builds, `android-dev` and `ios-dev`, write logs. A release build writes nothing to any log. Development builds log `would panic:` for blocking detections, `report only:` for report-only detections and `check off:` for disabled detections.

## Check before pushing

CI runs clang-format, clang-tidy, every preset and the checks on the release binaries. The exact commands are in [`.github/workflows/runtime.yml`](../.github/workflows/runtime.yml); run them before you push.
