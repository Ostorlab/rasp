# Runtime

The C++ runtime libraries that the packer adds to a protected app. They run the checks inside the app and report what they observe to the ADR server.

Before you change anything here, read [CONTRIBUTING.md](CONTRIBUTING.md): it lists the rules the build enforces and the ones reviewers check.

## Layout

The code is grouped the same way at every level. `util/` holds generic helpers that know nothing about RASP. Every other folder is one domain module, named after the job it does: `checks/` produces the observations, `reporting/` sends them to the ADR server, and on Android, `payload/` recovers the app's protected code. The shared part of a module is in `core/`, and its platform part is in the folder with the same name under `ios/` or `android/`. Every check is platform code, so checks are only in the platform folders.

- `core/`: code shared by every platform. It uses no platform API.
  - `include/rasp/observation.h`: `Observation`, the raw fact a check reports (`signal`, `source`, `status`, `value`). Checks and reporting both use it.
  - `include/rasp/reporting/`: sending the observations to the ADR server.
    - `event.h`: `Event`, a batch of observations as the ADR server receives it. The install id and session id of an event are `Uuid`s.
    - `submit_event.h`: the GraphQL `submitEvent` request for an event.
    - `install_id.h`: `load_install_id`, which keeps the install id in a 16-byte file, in a directory each platform chooses. The first launch stores a random id, and later launches read it back. When the file exists but can't be read, the launch uses a random id of its own and leaves the file untouched.
    - `reporter.h`: `Reporter`, which numbers the batches of a session (`seq`) and sends each one at most once, in order. At most 64 batches wait to be sent: when a 65th is added, the oldest one is dropped and never sent. A batch is never sent again, even when its request fails. `SessionIds` holds the install id and session id that every batch of the session carries.
    - `transport.h`: `Transport`, the HTTP POST each platform implements with its own network stack.
    - `server.h`: `kServerHost` and `kServerPath`, the ADR server the runtime reports to, `adr.ostorlab.co/apis/graphql`.
  - `include/rasp/util/`: generic helpers.
    - `http.h`: `post_request`, the text of an HTTP/1.1 POST with a JSON body. It refuses a host or a path that isn't made only of visible ASCII characters, and a path that doesn't start with `/`, so neither can change the request line or add a header.
    - `json.h`: JSON string writing. It always writes valid JSON: each byte that isn't valid UTF-8 is replaced with U+FFFD.
    - `logging.h`: `rasp::log` and `kLoggingEnabled`, the development logging that release builds leave out.
    - `sha256.h`: `sha256` and `hmac_sha256`, SHA-256 and HMAC-SHA256 written with the standard library only.
    - `uuid.h`: `Uuid`. `random_uuid` makes a random version 4 one, and `to_string` writes its 36-character text form.
  - `src/`: the code of these headers, in the same folders.
- `ios/`: `RaspRuntime.framework`, the runtime for iOS. When the app loads it, it runs the checks.
  - `src/checks/`: the iOS checks. Each one reports observations, never a verdict.
    - `example.h`: `example.loaded`, a placeholder that shows where a check goes and how it reports its observations.
  - `src/reporting/network_transport.h`: `NetworkTransport`, the iOS transport. Each post opens a TLS connection to the server on port 443 with Network.framework, which checks the server's certificate, writes the request, waits for the start of the answer, and closes the connection. One timeout covers the whole post, from opening the connection to the start of the answer.
  - `src/util/logging.cpp`: the iOS backend of `rasp::log`, which writes to the system log with os_log.
- `android/`: `librasp.so`, the runtime for Android, and the stub that loads it. When the app starts, the stub calls the library, which runs the checks, starts the thread that reports them, and gives back the app's code.
  - `src/entry.cpp`: `Java_co_ostorlab_rasp_RaspStub_raspStart`, the JNI function the stub calls. It runs the checks and starts the thread that reports them, then decrypts the app's dex files and returns them to the stub.
  - `src/checks/`: the Android checks. Each one reports observations, never a verdict.
    - `example.h`: `example.loaded`, a placeholder that shows where a check goes and how it reports its observations.
  - `src/payload/`: recovering the app's dex files, which the packer encrypted.
    - `cipher.h`: `decrypt`, the native counterpart of the packer's Android cipher. It checks a frame's HMAC-SHA256 tag first, and only then decrypts it with an HMAC-SHA256 keystream.
    - `payload.h`: `Dex` and `unpack`, which decrypts the payload and reads the app's dex files from it, in load order.
  - `src/reporting/thread.h`: `start_reporting`, the reporting thread. It attaches itself to the JVM, loads the install id from the app's no-backup files directory, makes a session id, sends the launch's observations as one batch, detaches itself from the JVM, and ends. Nothing is sent when the app's `config.json` has no build id.
  - `src/reporting/https_transport.h`: `HttpsTransport`, the Android transport. Each post calls Java's `HttpsURLConnection` through JNI: the platform does TLS and checks the server's certificate and host name. It writes the request, waits for the start of the answer, and closes the connection. The timeout is Java's connect timeout and read timeout, which bound each step, not the whole post, and don't cover the DNS lookup. An app without the `INTERNET` permission sends nothing, and the packer doesn't add that permission.
  - `src/util/logging.cpp`: the Android backend of `rasp::log`, which writes to the system log with `__android_log_write`.
  - `stub/`: `co/ostorlab/rasp/RaspStub.java`, the loader the packer points the manifest at, and `build.sh`, which builds it into `stub.dex`. The stub reads the key and the build id from `assets/rasp/config.json` and gives them to the library, with the app's no-backup files directory for the install id.
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

The library is written to `build/android/android/librasp.so`. It exports only the stub's entry point, `Java_co_ostorlab_rasp_RaspStub_raspStart`. Every other symbol, libc++ included, is hidden with `-Wl,--exclude-libs,ALL`. It links the NDK's static libc++ (`c++_static`). It supports Android 8.0 (API 26) and later, so the stub can load the decrypted code from memory with `InMemoryDexClassLoader`, and the code is never written to disk.

The stub is Java, not C++, so CMake doesn't build it. `android/stub/build.sh` compiles it with `javac` and converts it with `d8`. Set `ANDROID_JAR` to the `android.jar` of a platform at API 26 or newer. `d8` comes from `PATH`, or from the `D8` variable. The script writes `stub.dex` to the folder given as its argument, or next to itself when there is none:

```
ANDROID_JAR=<path to android.jar> runtime/android/stub/build.sh <output folder>
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

CI runs the format check, clang-tidy (on Linux for the shared code and the tests, and on macOS for the iOS code), the three host builds, the iOS release and development builds, and the Android release and development builds and the stub (`.github/workflows/runtime.yml`). It checks that the release framework exports no symbols, that the Android library exports only the stub's entry point, and that neither of them imports any of `exit`, `_Exit`, `quick_exit`, `signal`, `sigaction`, `sigprocmask`, `pthread_sigmask`, `setenv`, `putenv`, `unsetenv`, `setlocale` and `setrlimit`. `.clang-tidy` forbids these functions in the source, and also `abort` and `std::terminate`, which the binary check leaves out. CI also checks that the release framework imports no symbol with `_os_log` in its name and contains no `{public}` text, and that the release Android library imports no symbol with `__android_log` in its name and contains no `RaspRuntime` text.
