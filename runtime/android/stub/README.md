# Optional Application Context integration

Binary-only packing still works. It does not automatically provide a supported Application Context.
The runtime's current PackageManager signer measurement uses an explicitly supplied Context when available.
Without integration it retains the existing best-effort, private ActivityThread lookup (at most five seconds,
only on the monitor thread). A failed lookup/read reports `sig.cert_sha256/package_manager` with error status,
not a successful or benign result. APK signer and other existing measurements continue independently.

Build `stub.dex` and its matching compile-time artifact:

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
Do not shade, relocate, or rename this package. Do not run R8 on the shipped stub without these rules:

```proguard
-keep class co.ostorlab.rasp.RuntimeBridge { *; }
-keep class co.ostorlab.rasp.RaspStub { *; }
```

Keep the same rules in host shrinker configuration. For a host shrinker that warns about the deliberately
compile-only bridge, use the narrowly scoped `-dontwarn co.ostorlab.rasp.RuntimeBridge`; never ignore all missing
classes. Test the release/minified packed APK as well as debug. Constants may be inlined, but class/method names
and the `(android.content.Context)int` JNI signature must remain unchanged.

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

The native accessor atomically publishes one global JNI reference and returns owned local references on each
reader's own thread. It never stores JNIEnv, Activity, window, or the input wrapper. Losing concurrent initializers
delete their candidate global references. The winning Application reference lives for the monitor's process lifetime;
there is deliberately no reset/shutdown race. See [Android JNI ownership/thread guidance](https://developer.android.com/ndk/guides/jni-tips).

Each Android process has its own VM, Application, native state and monitor. Call from Application.onCreate in every
process needing this capability; a main-process call does not initialize a remote service process. This API supplies
Context only to the existing signer reader; other capabilities are not automatically implemented by initialization.

Host verification: `runtime/tests/android/context_bridge/run.sh` (JDK, Clang C++23). The same five cases run through
ordinary host CTest when Java/JNI are available. Sanitizer presets instead run a native JNI-boundary fixture over
the production accessor to check concurrent publication and reference ownership: stock JVM GC/JIT and retained
VM allocations are not a sanitizer-compatible Java heap. No sanitizer reports are suppressed. They execute the shipped Java/native implementation, replacing Android
services only at the Java boundary. Android lifecycle and ART behavior require the [device fixture](../../tests/android/context_bridge/device/README.md).
