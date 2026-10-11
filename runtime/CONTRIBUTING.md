# Contributing to the runtime

The runtime is a library that the packer puts inside our customers' apps. It runs in their process, on their users' phones. That changes what "a bug" means here:

- If our code crashes, their app crashes. Their users see it, and their crash reports point at their app.
- Whatever we leave on the device, in the binary, in the logs or in the files, an attacker can read and use against the protection.

Most of the rules below follow from these two facts. CI enforces the ones a tool can check. Reviewers check the others, so read them before you write code.

## Set up

| Tool | Version |
|---|---|
| Clang, clang-format, clang-tidy | LLVM 23 |
| CMake | 4.4.4 |
| Xcode, for iOS builds | 27.0 |
| Android NDK, for Android builds | the newest release, as on the CI runner |
| JDK, for the Android stub | 17 or newer |

The host presets compile with the first `clang` in `PATH`, so put LLVM 23 first: `/usr/lib/llvm-23/bin` on Linux, `$(brew --prefix llvm)/bin` on macOS. clang-format and clang-tidy must come from the same release, because their output changes between versions.

## Build, test and check

From `runtime/`:

```
cmake --preset host
cmake --build --preset host --parallel
ctest --preset host
```

| Preset | Builds |
|---|---|
| `host` | the code and the tests |
| `host-asan` | the same, with AddressSanitizer, LeakSanitizer and UndefinedBehaviorSanitizer |
| `host-tsan` | the same, with ThreadSanitizer |
| `ios` | the release framework, the one that ships |
| `ios-dev` | a development framework that writes logs |
| `android` | the release Android library, the one that ships |
| `android-dev` | a development Android library that writes logs |

The tests must pass under `host-asan` and `host-tsan`, not only `host`. A memory error or a data race often doesn't fail a test. It corrupts something and crashes later, somewhere else. In a customer's app, that shows up as a random crash nobody can trace back to us. The sanitizers turn these bugs into test failures.

Before pushing, run what CI runs (`.github/workflows/runtime.yml`): clang-format, clang-tidy, the three host presets, `android` and `android-dev` with the Android NDK, and on a Mac, `ios` and `ios-dev`.

```
git ls-files -z -- '*.h' '*.cpp' '*.h.in' | xargs -0 clang-format --dry-run --Werror
run-clang-tidy -quiet -p build/host "^$PWD/(?!build/).*\.cpp$"
```

The host build doesn't compile the iOS code. On a Mac, check it too: `cmake --preset ios-dev`, then `run-clang-tidy -quiet -p build/ios-dev "^$PWD/ios/src/.*\.cpp$"`.

Fix clang-tidy findings instead of silencing them with `NOLINT`. If a check is wrong for the whole project, propose turning it off in `.clang-tidy`, so everyone sees the decision.

## Never crash the app

### Errors are values, never exceptions

The runtime is built without exceptions and without RTTI. An exception that escapes our code ends the app, and we can't guarantee that every path catches it. So a function that can fail returns `std::expected`, `std::optional` or a status, marked `[[nodiscard]]` so the caller can't ignore it.

Without exceptions, some standard library calls end the process when they fail, because they have no other way to report the failure. Avoid them:

- `.at()` ends the app on a bad index. Check the bounds, then index.
- `std::random_device` ends the app when it can't open a random source. Use `arc4random_buf`, which can't fail.
- Running out of memory ends the app. Every buffer, queue and loop needs an upper limit, and we never read a file or a server response without a size limit.

When a choice exists, use the function that can't fail.

### Load time and the main thread

The runtime starts from a function that runs while the app loads, on the app's main thread, before the app's own code. Anything slow there delays the app's launch, and if launch takes too long, iOS kills the app. So that function only starts work. Network calls, waiting and retries happen on our own thread.

For the same reason, CI enforces three rules on the code that ships:

- **No global objects with a constructor or a destructor.** Their constructors run during that same load, in an order no one controls, so one global can use another before it exists. Their destructors run while the app exits, possibly while our thread still uses them. Use `constexpr` constants instead: a `std::string_view` for text, a `std::array` for a list. The entry point is the only load-time function.
- **No function uses more than 4 KB of stack.** At load time we run on the app's main thread and use its stack. Our own threads have small stacks.
- **No recursion.** How deep a recursion goes depends on its input. A deeply nested server response could use up the stack.

### The process belongs to the app

Some state is shared by the whole process: signal handlers, the signal mask, environment variables, the locale and resource limits. All of it belongs to the app, and we never change it. clang-tidy rejects all of these functions in the source. CI also checks the functions the release binary imports, but that check covers every function below except `abort` and `std::terminate`:

| Functions | Why |
|---|---|
| `exit`, `_Exit`, `quick_exit`, `abort`, `std::terminate` | They end the process, which is the customer's app. A check that fails reports an error status and returns. |
| `signal`, `sigaction`, `sigprocmask`, `pthread_sigmask` | Our handler would replace the app's, or its crash reporter's. On Android, the runtime itself handles `SIGSEGV` to turn null pointers into Java exceptions; taking it over turns those into crashes. |
| `setenv`, `putenv`, `unsetenv`, `setlocale` | They aren't thread-safe. An app thread reading the environment or the locale at the same moment can crash. |
| `setrlimit` | A lower limit makes the app's own calls fail. |

`_exit` is allowed, because a child created with `fork` must end with it.

### `fork`

A check that calls `fork` creates a copy of the app's process. The copy has a single thread, ours. But it inherits the memory of every other thread exactly as it was, including any lock another thread held at that moment. Nobody will ever release those locks in the child. So in the child, anything that might take a lock can hang forever, and that includes allocating memory and logging. The child must call `_exit` right away and do nothing else.

### Threads and exit

The app can exit at any moment, and our thread may be in the middle of its work when it does. The thread must not hold anything that breaks if the process ends there, and the app must never wait for our thread in order to exit.

### System calls

Check the result of every system call. On failure, the check reports a `kError` observation. Never fall back to a guessed or default value: the server would treat it as something we observed. Clean up after a failure too. For example, a probe file must never be left outside the sandbox.

### iOS 12 and our own libc++

The framework supports iOS 12.0 and later, so it fits into any app the App Store accepts today. If our code calls an Apple function that doesn't exist on the phone's iOS version, iOS refuses to load the framework, and the app crashes at launch. The build rejects every Apple function newer than iOS 12. If you need a newer one, call it only inside `if (__builtin_available(iOS 16, *))`, and give older versions a path that also works.

The framework doesn't use the libc++ that comes with iOS, because Apple's copy only supports iOS 15 and later. It carries its own copy, built from LLVM and linked inside the framework. The app keeps using Apple's copy, and the two can lay out the same type differently. So never pass a C++ object, such as a `std::string` or a container, between our code and code outside the framework.

## Never help the attacker

On a protected app, the attacker controls the device. They can read our binary, read the device's logs, fake files and system call results, and intercept or forge network traffic. Write the code with that in mind.

### Observations, not verdicts

A check reports what it saw (`signal`, `source`, `status`, `value`) and never decides whether the device is compromised. The ADR server makes that decision. If the decision were in the app, an attacker could find it in the binary and patch it. On the server, they can't see it, and we can change it without shipping a new runtime.

### No logs in release builds

Anyone with the device and a computer can read its system log, without a jailbreak. If we logged what we check and what we find, an attacker would get exact feedback on every attempt to get around a check. CI checks that the release framework imports no symbol with `_os_log` in its name, and that it contains no `{public}` text, the marker os_log format strings use. It also checks that the release Android library imports no symbol with `__android_log` in its name, and that it contains no `RaspRuntime` text, the tag of our Android log lines.

During development, write log lines only with `rasp::log`, and only inside `if constexpr (rasp::kLoggingEnabled)`. In a release build, the compiler still checks the code in that block, but it generates no code for it, so neither the call nor its text ends up in the binary. Never call `os_log`, `__android_log_write`, `printf` or another log function directly.

### Other rules

- **No exported symbols.** CI checks that the framework exports nothing, and that the Android library exports only the JNI function the stub calls. Exported names show an attacker where our functions are, and could clash with functions of the same name in the app.
- **Treat everything from outside as hostile.** Server responses, files and system call results can all be forged. Parse with limits and check every value before using it.
- **No secrets in the source or the binary.** Anything in the binary can be extracted.
- **Never turn off certificate checks**, not even in a development build. Development code tends to reach release builds.

## Android

The packer points the app's manifest at `co.ostorlab.rasp.RaspStub`, the stub in `android/stub/`. When the app starts, the stub loads `librasp.so` and calls its `raspStart` method. That function runs the checks, then decrypts the app's code and returns it for the stub to load. Decryption happens in native code, never in Java, and the decrypted code stays in memory.

- **`librasp.so` exports only `Java_co_ostorlab_rasp_RaspStub_raspStart`**, the JNI function behind `raspStart`. Everything else, libc++ included, is hidden with `-Wl,--exclude-libs,ALL`. A leaked symbol is a handle an attacker can hook, and CI fails if anything else is exported. JNI fixes the name of that function, so `android/.clang-tidy` lets that one name break the naming rule.
- **The payload cipher must stay byte for byte compatible with the packer's.** It is built on HMAC-SHA256, so the device needs only SHA-256 (`core/include/rasp/util/sha256.h`). The tests decrypt a frame and a payload that the packer made. If you change the cipher on either side, change the other side and these tests with it.
- **The minimum is API 26**, so the decrypted dex files are loaded from memory and never written to disk.

## Code

- **Fixed-width integers for values sent to the server** (`int32_t`, `int64_t`). They must match the GraphQL types exactly. `int` and `long` change size between platforms. Write every intended conversion with `static_cast`: warnings are errors, and the build rejects silent ones.
- **Never keep a `std::string_view` or `std::span` beyond the call that received it.** It points into memory it doesn't own, and that memory can be freed while we still use it.
- **No `<iostream>` or `<regex>`.** Every protected app pays for our binary's size and our load time, and these two add a lot of both.
- **Platform code goes in its platform's folder** (`ios/`, `android/`), chosen by CMake. Every check is platform code: it goes in `ios/src/checks/` or `android/src/checks/`. The same shared code builds for both platforms, so it must not contain platform `#if` blocks.
- **Document every file and function with `///`.** Every C++ file starts with a description of what it holds. A public header documents every public symbol. Every public function says what it does and the cases a caller must know about, describes each parameter with `@param` and, unless it returns `void`, its result with `@return`. Every private function has at least one sentence that says what it does. Write no other comments: names and small functions say how the code does it.
- **Test names** follow `TEST(Suite, action_whenCondition_result)`, for example `TEST_F(Reporter, add_whenTheQueueIsFull_dropsTheOldestBatch)`.
