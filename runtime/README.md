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

## Logs

Only the development builds, `android-dev` and `ios-dev`, write logs. A release build writes nothing to any log.

## Check before pushing

CI runs clang-format, clang-tidy, every preset and the checks on the release binaries. The exact commands are in [`.github/workflows/runtime.yml`](../.github/workflows/runtime.yml); run them before you push.
