# Runtime

The C++ runtime libraries that the packer adds to a protected app. They run the checks inside the app and report what they observe to the ADR server.

Before you change anything here, read [CONTRIBUTING.md](CONTRIBUTING.md): it lists the rules the build enforces and the ones reviewers check.

## Layout

The code is grouped the same way at every level. `util/` holds generic helpers that know nothing about RASP. Every other folder is one domain module, named after the job it does: `checks/` produces the observations, `reporting/` sends them to the ADR server, and on Android, `payload/` recovers the app's protected code. The shared part of a module is in `core/`, and its platform part is in the folder with the same name under `ios/` or `android/`. Every check is platform code, so checks are only in the platform folders.

- `core/`: code shared by every platform. It uses no platform API.
  - `include/rasp/observation.h`: `Observation`, the raw fact a check reports (`signal`, `source`, `status`, `value`), and `observed`, `unsupported` and `failed`, which build one. Checks and reporting both use it.
  - `include/rasp/reporting/`: sending the observations to the ADR server.
    - `submit_observations.h`: `ObservationBatch`, a batch of observations as the ADR server receives it, and `submit_observations_request`, the GraphQL `submitObservations` request that sends it. The install id and session id of a batch are `Uuid`s.
    - `reporter.h`: `Reporter`, whose `report` sends, at once and as one batch, only the observations that changed since the last ones reported: an observation is identified by its signal and source, and it has changed when it is new or when its status or value differs. It numbers the batches of a session (`seq`) and sends each one once, in order. A batch is never sent again, even when its request fails. `SessionIds` holds the install id and session id that every batch of the session carries.
    - `transport.h`: `Transport`, the HTTP POST each platform implements with its own network stack.
    - `server.h`: `kServerHost` and `kServerPath`, the ADR server the runtime reports to, `adr.ostorlab.co/apis/graphql`.
  - `include/rasp/util/`: generic helpers.
    - `http.h`: `post_request`, the text of an HTTP/1.1 POST with a JSON body. It refuses a host or a path that isn't made only of visible ASCII characters, and a path that doesn't start with `/`, so neither can change the request line or add a header.
    - `json.h`: JSON string writing. It always writes valid JSON: each byte that isn't valid UTF-8 is replaced with U+FFFD.
    - `logging.h`: `rasp::log` and `kLoggingEnabled`, the development logging that release builds leave out.
    - `uuid.h`: `Uuid`. `random_uuid` makes a random version 4 one, and `to_string` writes its 36-character text form.
  - `src/`: the code of these headers, in the same folders.
- `ios/`: `RaspRuntime.framework`, the runtime for iOS. When the app loads it, it starts the thread that runs the checks and reports them.
  - `src/monitoring.h`: `start_monitoring`, the runtime's thread. It reads the build id from the framework's `Info.plist`, loads the install id, and makes a session id. Then it runs the checks and sends their observations as the session's first batch, and every 60 seconds runs them again and sends only the observations that changed; a run where nothing changed sends nothing. It runs until the process exits, and iOS suspends it while the app is in the background.
  - `src/checks/`: the iOS checks. Each one reports observations, never a verdict.
    - `jailbreak.h`: the jailbreak checks. `jb.fs_paths` (do known jailbreak files exist, read through access and stat), `jb.sandbox_escape` (can the app write outside its sandbox) and `jb.fork_ok` (can the app start a child process). Off a physical device every one is unsupported.
  - `src/reporting/install_id.h`: `load_install_id`, which keeps the install id in a 16-byte file in the app's `Library/Application Support`.
  - `src/reporting/network_transport.h`: `NetworkTransport`, the iOS transport. Each post opens a TLS connection to the server on port 443 with Network.framework, which checks the server's certificate, writes the request, waits for the start of the answer, and closes the connection. One timeout covers the whole post, from opening the connection to the start of the answer.
  - `src/util/logging.cpp`: the iOS backend of `rasp::log`, which writes to the system log with os_log.
- `android/`: `librasp.so`, the runtime for Android, and the stub that loads it. The library runs its checks when it loads, and returns the app's decrypted dex files to the stub.
  - `src/entry.cpp`: a load-time constructor that runs the checks, and `JNI_OnLoad`, which binds (with `RegisterNatives`) the native method the stub calls to decrypt the app's dex files and return them.
  - `src/checks/`: the Android checks. Each one reports observations, never a verdict.
    - `example.h`: `example.loaded`, a placeholder that shows where a check goes and how it reports its observations.
  - `src/payload/`: recovering the app's dex files, which the packer encrypted.
    - `cipher.h`: `decrypt`, which decrypts a frame of the packer's Android cipher: ChaCha20-Poly1305 (RFC 8439), from TF-PSA-Crypto. It refuses a frame whose tag doesn't match.
    - `payload.h`: `Dex`, one dex file of the protected app, and `unpack`, which decrypts the payload and reads the app's dex files from it, in load order. A payload holds at most 1024 dex files.
  - `src/util/logging.cpp`: the Android backend of `rasp::log`, which writes to the system log with `__android_log_write`.
  - `stub/`: `co/ostorlab/rasp/RaspStub.java`, the component factory the packer points the manifest at, and `build.sh`, which builds it into `stub.dex`.
- `tests/`: tests that run on a development machine, with GoogleTest. They use the same folders as the code.

## Build

CMake 4.4 or newer. The presets are in `CMakePresets.json`.

The host presets build with Clang from LLVM 23, the same release as `clang-format` and `clang-tidy`. Put its `bin` folder first in `PATH` (for example `/usr/lib/llvm-23/bin` from apt.llvm.org).

On a development machine, with the tests:

```
cd runtime
cmake --preset host
cmake --build --preset host
ctest --preset host
```

The same with AddressSanitizer, LeakSanitizer and UndefinedBehaviorSanitizer:

```
cd runtime
cmake --preset host-asan
cmake --build --preset host-asan
ctest --preset host-asan
```

The same with ThreadSanitizer, which finds data races. It cannot be combined with AddressSanitizer, so it has its own preset:

```
cd runtime
cmake --preset host-tsan
cmake --build --preset host-tsan
ctest --preset host-tsan
```

For an iOS device (arm64), on a Mac with Xcode:

```
cd runtime
cmake --preset ios
cmake --build --preset ios
```

The framework is written to `build/ios/ios/RaspRuntime.framework`. Its install name is `@rpath/RaspRuntime.framework/RaspRuntime`, which the packer adds to the app's load commands. The framework exports no symbols: the code runs from a constructor when the app loads it.

The framework supports iOS 12.0 and later. It doesn't use the libc++ that comes with iOS, which only supports iOS 15 and later. Instead it links a static libc++ built from LLVM 23.1.3 for the same minimum iOS version, with all its symbols hidden. That library is built once and committed under `third_party/libcxx/`, and `cmake/libcxx.cmake` checks its hash and links it. The build steps, the one-line source change it needs, and the CI job that proves the committed library matches the source are described in `third_party/libcxx/README.md`.

For an Android device (arm64-v8a), with the Android NDK. Set `ANDROID_NDK_HOME` to the NDK's folder first:

```
cd runtime
cmake --preset android
cmake --build --preset android
```

The library is written to `build/android/android/librasp.so`. It exports no entry point of its own: the checks run from a load-time constructor, and the stub's native method is bound with `RegisterNatives`, so the only exported symbol is the JVM's `JNI_OnLoad` hook. Every other symbol, libc++ included, is hidden with `-Wl,--exclude-libs,ALL`. It links the NDK's static libc++ (`c++_static`). It supports Android 12 (API 31) and later, so the stub can load the decrypted code from memory with `InMemoryDexClassLoader`, and the code is never written to disk.

The payload decryption uses ChaCha20-Poly1305 from TF-PSA-Crypto, the cryptography library of the Mbed TLS project. Its source is committed as an archive under `third_party/tf-psa-crypto/`, and `cmake/tf_psa_crypto.cmake` checks the archive's hash, extracts it and builds it as a static library, for Android and for the builds with tests. Its symbols are hidden in `librasp.so` like every other one. Why it is built this way, its configuration, and the CI job that proves the archive is the official release are described in `third_party/tf-psa-crypto/README.md`.

The stub is Java, not C++, so CMake doesn't build it. `android/stub/build.sh` compiles it with `javac` against the platform's `android.jar`, so the Java classes it uses are Android's, and converts it with `d8`. It takes two files from the Android SDK:

- `ANDROID_JAR` must be set to the `android.jar` of a platform at API 31 or newer, for example `$ANDROID_HOME/platforms/android-36/android.jar`. The stub is an `AppComponentFactory` (API 28) and calls the `InMemoryDexClassLoader` constructor with a library search path (API 31).
- `d8` comes from the SDK's build-tools. It must be on `PATH`, or `D8` must be set to its path.

The script writes `stub.dex` to the folder given as its argument, or to `android/stub/` when there is none:

```
cd runtime
ANDROID_JAR="$ANDROID_HOME/platforms/android-36/android.jar" android/stub/build.sh <output folder>
```

The packer installs `stub.dex` as the app's `classes.dex`, and `librasp.so` under `lib/arm64-v8a/`.

## Logs

Only development builds write logs. A release build writes nothing to any log, so a protected app leaves no trace of the runtime in the device's log.

The `RASP_LOGGING` option turns logging on. CMake accepts it only in a Debug build (the build type is compared without case), and only with a single-configuration generator. It refuses every other build type, an empty build type, and multi-configuration generators such as Ninja Multi-Config. On iOS, the development build writes each line to the system log with `os_log`, and the `ios-dev` preset builds it:

```
cd runtime
cmake --preset ios-dev
cmake --build --preset ios-dev
```

The framework is written to `build/ios-dev/ios/RaspRuntime.framework`. Code writes a log line with `rasp::log` (`core/include/rasp/util/logging.h`), and only inside `if constexpr (rasp::kLoggingEnabled)`. In a release build, the compiler still checks the code in that block, but it generates no code for it, so neither the call nor its text is in the framework.

On Android, the development build writes each line to the system log with `__android_log_write`, with the tag `RaspRuntime`, and the `android-dev` preset builds it:

```
cd runtime
cmake --preset android-dev
cmake --build --preset android-dev
```

The library is written to `build/android-dev/android/librasp.so`.

## Format and check

The style is in `.clang-format` and the checks are in `.clang-tidy`.

```
cd runtime
git ls-files -z -- '*.h' '*.cpp' '*.h.in' | xargs -0 clang-format -i
cmake --preset host
run-clang-tidy -quiet -p build/host "^$PWD/(?!build/).*\.cpp$"
```

The host build doesn't compile the iOS code, so on a Mac, check it with the development build too:

```
cmake --preset ios-dev
run-clang-tidy -quiet -p build/ios-dev "^$PWD/ios/src/.*\.cpp$"
```

The Android code, from an Android build, with `ANDROID_NDK_HOME` set:

```
cmake --preset android
run-clang-tidy -quiet -p build/android "^$PWD/android/src/.*\.cpp$"
```

CI (`.github/workflows/runtime.yml`) runs:

- clang-format, and clang-tidy on the shared code and the tests (on Linux), the iOS code (on macOS) and the Android code (with the Android builds);
- the three host builds, the iOS release and development builds, and the Android release, development and stub builds.

On the release binaries, it checks that:

- the framework exports no symbols, and the Android library exports only the JVM's `JNI_OnLoad` hook;
- neither imports any of `exit`, `_Exit`, `quick_exit`, `signal`, `sigaction`, `sigprocmask`, `pthread_sigmask`, `setenv`, `putenv`, `unsetenv`, `setlocale` and `setrlimit`. `.clang-tidy` forbids these functions in the source, and also `abort` and `std::terminate`, which the binary check leaves out;
- neither writes logs: the framework imports no symbol with `_os_log` in its name and contains no `{public}` text, and the Android library imports no symbol with `__android_log` in its name and contains no `RaspRuntime` text.
