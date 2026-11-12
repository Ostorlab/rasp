# Optional Application Context integration

**`RuntimeBridge.initialize(Context)` supplies the process's attached Application Context to the native
PackageManager signer reader and the opt-in public service metadata collectors.** This source integration is optional. Binary-only packing still works and does not
automatically provide a supported Application Context.

Without integration, the signer reader retains the existing best-effort, private ActivityThread lookup (at most
five seconds, only on the monitor thread). A failed lookup/read reports `sig.cert_sha256/package_manager` with error
status, not a successful or benign result. APK signer and other existing measurements continue independently.

## Build and package the bridge

Run the commands below from the repository root. Build `stub.dex` and its matching compile-time artifact:

```sh
ANDROID_JAR="$ANDROID_HOME/platforms/android-35/android.jar" \
D8="$ANDROID_HOME/build-tools/35.0.1/d8" ./runtime/android/stub/build.sh /tmp/rasp-stub
```

Put `stub.dex` in the packer's Android resources with the matching native libraries. Give the host developer
`runtime-bridge-compile-only.jar`. In the host's Android Gradle module:

```groovy
dependencies {
    compileOnly files('libs/runtime-bridge-compile-only.jar')
}
```

The JAR contains only RuntimeBridge. **Never use `implementation`, `api`, or bundle its source/class in the host
APK/AAB.** The packer keeps framework DEX classes and appends stub.dex; bundling another bridge would create
competing definitions, possibly in the on-demand loader. Its sole runtime definition must come from stub.dex,
visible through the base loader to decrypted host code. The compile-only JAR is not a standalone runtime SDK.
Do not shade, relocate, or rename this package.

## Preserve names and signatures with shrinkers

Do not run R8 on the shipped stub without these rules:

```proguard
-keep class co.ostorlab.rasp.RuntimeBridge { *; }
-keep class co.ostorlab.rasp.RaspStub { *; }
```

Keep the same rules in host shrinker configuration. For a host shrinker that warns about the deliberately
compile-only bridge, use the narrowly scoped `-dontwarn co.ostorlab.rasp.RuntimeBridge`; never ignore all missing
classes. Test the release/minified packed APK as well as debug. Constants may be inlined, but class and method
names must remain unchanged.
The public entry remains `int initialize(android.content.Context)`; the native `initializeNative` method must retain
the exact JNI descriptor `(Landroid/content/Context;)I`.

## Initialize after Application attachment

Call after Application attachment, normally in the existing Application's `onCreate`:

```java
@Override public void onCreate() {
    super.onCreate();
    try {
        int result = co.ostorlab.rasp.RuntimeBridge.initialize(this);
        // Handle or record the result in host diagnostics as appropriate.
    } catch (LinkageError unavailableInUnpackedBuild) {
        // compileOnly means an unpacked build may have no RuntimeBridge class at all.
    }
}
```

No call is made from `instantiateApplication`, before attachment, or through ActivityThread by this public API.
[Application.onCreate](https://developer.android.com/reference/android/app/Application#onCreate()) is an appropriate
post-attachment callback and should remain quick. A Context/Activity/wrapper input is normalized using public
[Context.getApplicationContext](https://developer.android.com/reference/android/content/Context#getApplicationContext());
only a non-null Application result is retained. A newly constructed, unattached Application normally throws or
returns no usable application Context and must be retried after attachment.

## Initialization results

`RuntimeBridge.initialize` returns one of these result codes:

| Result | Meaning |
|---|---|
| `INITIALIZED` (0) | This process retained its first normalized Application. |
| `ALREADY_INITIALIZED` (1) | The same Application was already retained; safe to repeat. |
| `INVALID_CONTEXT` (2) | Null input, null normalized result, or result is not an Application. |
| `UNAVAILABLE` (3) | Native bridge absent/unregistered/incompatible; retrying after runtime availability is safe. |
| `DIFFERENT_APPLICATION` (4) | A different Application was already retained; it is not replaced. |
| `JNI_ERROR` (5) | Normalization threw or a JNI allocation/lookup failed; no new reference was published. |

`initialize` does no measurement, disk IO, waiting, or monitor synchronization. Host overrides of Context methods
must also return promptly. Failed calls leave an existing Context intact and clear JNI exceptions before returning.
Initialization does not prove a signer measurement succeeded: PackageManager can still fail independently. The
existing monitor measures identity at startup and on subsequent passes (nominally every 60 seconds after each pass),
so a call after startup is consumed on the next pass, even after the initial five-second fallback window. It does
not schedule immediate extra checks or change signer selection. A failed read remains an error observation.

## Ownership and process lifetime

The native accessor atomically publishes one global JNI reference and returns owned local references on each
reader's own thread. It never stores JNIEnv, Activity, window, or the input wrapper. Losing concurrent initializers
delete their candidate global references. The winning Application reference lives for the monitor's process lifetime;
there is deliberately no reset/shutdown race. See [Android JNI ownership/thread guidance](https://developer.android.com/ndk/guides/jni-tips).

Each Android process has its own VM, Application, native state and monitor. Call from Application.onCreate in every
process needing this capability; a main-process call does not initialize a remote service process. The opt-in `accessibility`, `input_method` and `notification_access` groups also consume this Context; unlike the
legacy signer path, they report error until explicit initialization and never look up ActivityThread. See
[service contracts and privacy/version limits](../../../docs/android-service-observations.md). Initialization supplies
Context; the embedded check selection still determines which collectors run.

## Verification

Run [the host runner](../../tests/android/context_bridge/run.sh) from any working directory. It uses the existing
CMake Java/JNI discovery and targets, including the platform-specific JNI headers and shared-library path, with at
most two build/test jobs. Requirements are Bash 3.2 or newer, CMake/CTest 4.4 or newer, Clang with C++23 support, and
a JDK 17 or newer. Put the tools on PATH and set `JAVA_HOME` if CMake cannot discover the intended JDK. Additional
arguments are passed to CMake configuration, for example `-DCMAKE_CXX_COMPILER=/path/to/clang++`.

The runner accepts Linux and macOS hosts; other hosts, including Windows, are explicitly unsupported. Linux execution
is validated locally. Actual macOS runner execution remains a CI gate; Linux validation does not establish a macOS
pass. The Runtime workflow's macOS iOS job runs this same runner under `/bin/bash`, with Java set up explicitly and
the existing CMake installation; its result must be checked after publication. The script uses CMake's host discovery rather than hardcoding Linux JNI includes or using GNU path resolution
and Bash 4 builtins. Missing Java/JNI targets or an empty test selection fail the runner.

The ordinary host preset and manual runner execute all five real-JVM modes (late, early, concurrent, lifetime and
unavailable) plus the native accessor test. The real-JVM tests execute the shipped Java bridge, JNI accessor and
PackageManager consumer, replacing Android services only at the Java boundary.

Sanitizer presets execute **only the native JNI-boundary fixture** for this bridge, testing concurrent publication
and reference ownership in the production accessor. They do not execute the Java/JVM modes: stock JVM GC/JIT and
retained VM allocations are not sanitizer-compatible. No sanitizer reports are suppressed.

Android lifecycle and ART behavior require the [device fixture](../../tests/android/context_bridge/device/README.md).
Host tests and fixture compilation do not establish actual device or minified-host behavior.
