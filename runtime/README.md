# Runtime

The C++ runtime libraries that the packer adds to a protected app. They run the checks inside the app.

Before you change anything here, read [CONTRIBUTING.md](CONTRIBUTING.md): it lists the rules the build enforces and the ones reviewers check.

## Layout

The code is grouped the same way at every level. `util/` holds generic helpers that know nothing about RASP. Every other folder is one domain module, named after the job it does, such as `checks/`, which produces the observations, and on Android, `payload/`, which recovers the app's protected code. When a module has a part shared by every platform, that part is in `core/`, and its platform part is in the folder with the same name under `ios/` or `android/`. Every check is platform code, so checks are only in the platform folders.

- `core/`: code shared by every platform. It uses no platform API.
  - `include/rasp/observation.h`: `Observation`, the raw fact a check reports (`signal`, `source`, `status`, `value`), and `observed`, `unsupported` and `failed`, which build one.
  - `include/rasp/util/`: generic helpers.
    - `logging.h`: `rasp::log` and `kLoggingEnabled`, the development logging that release builds leave out.
  - `src/`: the code of these headers, in the same folders.
- `ios/`: `RaspRuntime.framework`, the runtime for iOS. When the app loads it, it starts the thread that runs the checks.
  - `src/monitoring.h`: `start_monitoring`, the runtime's thread. It runs the checks, then runs them again every 60 seconds. A development build logs each observation. It runs until the process exits, and iOS suspends it while the app is in the background.
  - `src/checks/`: the iOS checks. Each one reports observations.
    - `jailbreak.h`: the jailbreak checks. `jb.fs_paths` (do known jailbreak files exist, read through access and stat), `jb.sandbox_escape` (can the app write outside its sandbox) and `jb.fork_ok` (can the app start a child process). Off a physical device every one is unsupported.
  - `src/util/logging.cpp`: the iOS backend of `rasp::log`, which writes to the system log with os_log.
- `android/`: `librasp.so`, the runtime for Android, and the stub that loads it. The library runs its checks when it loads, and returns the app's decrypted dex files to the stub.
  - `src/entry.cpp`: a load-time constructor that runs the checks and decrypts the app's dex files, and `JNI_OnLoad`, which builds the class loader over them and stores it in the stub's field.
  - `src/checks/`: the Android checks. Each one reports observations.
    - `debugger.h`: the debugger checks. They run on Android; off Android every observation has the unsupported status.
      - `dbg.tracer_pid`: the process id of the native debugger attached to the app, 0 when there is none, read from the `TracerPid:` line of `/proc/self/status`.
    - `hooks.h`: the hooking checks. They run on Android; off Android every observation has the unsupported status.
      - `hook.maps_hits`: the lines of `/proc/self/maps` that name a known instrumentation framework (Frida, Substrate, Xposed and the like), matched case-insensitively.
      - `hook.rwx_regions`: the lines of `/proc/self/maps` that map memory both writable and executable, where injected code is often written.
    - `integrity.h`: the integrity checks. They run on Android; off Android every observation has the unsupported status.
      - `integ.text_sha256`: the SHA-256 of librasp.so's own executable code (its `.text` section), read once from the installed file (the `file` source) and once from the process's memory (the `memory` source). The two are equal on a clean device and differ when the code was patched in memory, such as by a Frida hook that patches a check to always report a safe value. The server compares them; the app only reports both. The library finds its own file and load address through the dynamic loader, so no path is built into the binary; when the app keeps its libraries uncompressed inside the APK, the file is read from the APK's zip entry.
    - `mitm.h`: the network-interception (man-in-the-middle, MITM) checks. `mitm.tunnels` runs on Android and reports the tunnel list; `mitm.user_cas` is `unsupported` on a device because no app-accessible source exists. Off Android every observation has the unsupported status.
      - `mitm.tunnels`: the network interfaces visible to the process whose name is `tun` or `tap` followed by a digit (such as `tun0` or `tap0`, the layer-3 and layer-2 interfaces of the kernel's TUN/TAP driver) — the interfaces a capture proxy routes traffic through, and the same `tun0` a legitimate VPN app opens; a name like the IPIP `tunl0` does not match. The names are read through `getifaddrs`, which an app process can call even though Android denies it `/proc/net/route`; the check reports each unique tunnel (at most 100) and the server weighs it, and a device with no tunnel reports an empty list.
      - `mitm.user_cas`: the file names of the user-installed CA certificate files in the user trust store (`/data/misc/user/<id>/cacerts-added`), where a certificate the user installs lands instead of the system authorities, so a proxy that decrypts TLS installs its root there. The store is labeled `system_data_file` under SELinux and no public SDK API exposes user CAs to an app, so this signal is reported `unsupported` on a device.
    - `root.h`: the root checks. They run on Android; off Android every observation has the unsupported status.
      - `root.fs_paths`: which known root files exist, such as `su` and the Magisk, KernelSU and APatch files, read through access and stat.
      - `root.mounts`: the lines of `/proc/self/mounts` that a root tool made.
      - `root.rw_mounts`: the lines of `/proc/self/mounts` that mount a system folder writable.
      - `root.selinux_enforcing`: whether SELinux enforces its policy, read from `/sys/fs/selinux/enforce`.
      - `root.build_props`: the build properties that reveal a debuggable or test-signed build, or an unlocked bootloader.
  - `src/payload/`: recovering the app's dex files, which the packer encrypted.
    - `cipher.h`: `decrypt`, which decrypts a frame of the packer's Android cipher: ChaCha20-Poly1305 (RFC 8439), from TF-PSA-Crypto. It refuses a frame whose tag doesn't match.
    - `payload.h`: `Dex`, one dex file of the protected app, and `unpack`, which decrypts the payload and reads the app's dex files from it, in load order. A payload holds at most 1024 dex files.
  - `src/util/logging.cpp`: the Android backend of `rasp::log`, which writes to the system log with `__android_log_write`.
  - `src/util/read_file.h`: `read_file`, which reads a whole file up to a size limit, for the checks that read files under `/proc` and `/sys`.
  - `stub/`: `co/ostorlab/rasp/RaspStub.java`, the component factory the packer points the manifest at, and `build.sh`, which builds it into `stub.dex`.
- `tests/`: tests that run on a development machine, with GoogleTest. They use the same folders as the code.
  - `support/files.h`: `TemporaryDirectory`, a temporary folder removed with its contents, and `write_file`, which writes a file the tests then read.

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

The library is written to `build/android/android/librasp.so`. It exports no entry point of its own: the checks run from a load-time constructor, and the stub calls no native method, so the library exports no `Java_...` symbol. The only symbol it may export is the JVM's `JNI_OnLoad` hook, which the runtime uses to publish the decrypted class loader to the stub. A release build is also stripped (`-Wl,--strip-all`), so it carries no symbol table and no debug sections. Every other symbol, libc++ included, is hidden with `-Wl,--exclude-libs,ALL`. It links the NDK's static libc++ (`c++_static`). It supports Android 12 (API 31) and later, so the stub can load the decrypted code from memory with `InMemoryDexClassLoader`, and the code is never written to disk.

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

The release build leaves out `logging.cpp`, so check the development build too, the way CI does:

```
cmake --preset android-dev
run-clang-tidy -quiet -p build/android-dev "^$PWD/android/src/.*\.cpp$"
```

CI (`.github/workflows/runtime.yml`) runs:

- clang-format, and clang-tidy on the shared code and the tests (on Linux), the iOS code (on macOS) and the Android code (with the Android builds);
- the three host builds, the iOS release and development builds, and the Android release, development and stub builds.

On the release binaries, it checks that:

- the framework exports no symbols, and the Android library exports only the JVM's `JNI_OnLoad` hook;
- neither imports any of `exit`, `_Exit`, `quick_exit`, `signal`, `sigaction`, `sigprocmask`, `pthread_sigmask`, `setenv`, `putenv`, `unsetenv`, `setlocale` and `setrlimit`. `.clang-tidy` forbids these functions in the source, and also `abort` and `std::terminate`, which the binary check leaves out;
- neither writes logs: the framework imports no symbol with `_os_log` in its name and contains no `{public}` text, and the Android library imports no symbol with `__android_log` in its name and contains no `RaspRuntime` text.
