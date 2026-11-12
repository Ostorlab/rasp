# Real entry-point consumers and harmless reference apps

The C and Java parsers share independent `vectors.tsv`; the C suite also covers
framing, literal bounds and20,000 deterministic mutations. `fuzz.c` is a synthetic
libFuzzer driver, bounded to1025 input bytes and16 rules. It never supplies native
policy results. `gate_test.cpp` installs an actual process-lifetime policy, feeds
real CycleMonitor publication and executes `c_host.c`'s native gate -> receipt
boundary in separate gate/report-only processes.

`EntryBoundaryTest` compiles the **actual Android reference Activity/Service/
provider** alongside controlled OS/UI/clock/identity seams, existing RuntimeBridge
and real registered JNI/C gate. Tests cover missing/forged/shared/isolated/cross-user
identity, permission/signing-history loss, API34 refusal/API35 current versus
initial caller, Intent shape, native DENY/unavailable, lifecycle/expiry, real
query cancellation and separate RT20 confirmation. These JVM seams are not Binder
kernel/device/caller proof. Repeat public/IPC delivery may repeat a demo receipt;
this explicitly demonstrates the absence of durable replay protection.

Build real unsigned SDK hosts from the repository root:

```sh
ANDROID_JAR="$ANDROID_HOME/platforms/android-35/android.jar" \
D8="$ANDROID_HOME/build-tools/35.0.1/d8" \
bash runtime/android/stub/build.sh /tmp/rt21-bridge
ANDROID_JAR="$ANDROID_HOME/platforms/android-35/android.jar" \
ANDROID_BUILD_TOOLS="$ANDROID_HOME/build-tools/35.0.1" \
bash runtime/tests/entrypoint_validation/android/device/build.sh /tmp/rt21-host \
  /tmp/rt21-bridge/runtime-bridge-compile-only.jar
ANDROID_JAR="$ANDROID_HOME/platforms/android-35/android.jar" \
ANDROID_BUILD_TOOLS="$ANDROID_HOME/build-tools/35.0.1" \
bash runtime/tests/entrypoint_validation/android/caller/build.sh /tmp/rt21-caller
```

The host APK and proto-manifest AAB contain real SDK/D8 code and zero bridge
class definitions. With an installed packer containing matching reviewed native/
stub/sidecars, exercise the public API or CLI:

```sh
rasp pack /tmp/rt21-host/host-unsigned.apk --platform android --build-id rt21-demo \
  --checks debugger --local-policy docs/fixtures/local-policy-android-v1.json \
  --output /tmp/rt21-host/protected.apk
```

The same command accepts `host-unsigned.aab` and an `.aab` output. Both outputs
remain unsigned and structurally verified, not store/bundletool/installation
acceptance. The AAB uses a real aapt2 protobuf manifest and D8 classes with an
empty default BundleConfig protobuf message for format admission; bundletool is
not available locally and generated split/store validity is not claimed. Do not run this packer on the prelinked Apple reference host.
The host uses the exact fixture policy pin. The caller's pins are all-zero public
placeholders and intentionally do not authorize a real installed certificate.
Real signed caller tests require explicitly reviewed customer/test signing pins
and separately authorized facilities; no keys or device enrollment are generated
by these scripts. They never contact example.invalid or alter domain verification.

On a Mac run `check_apple.sh <actual framework> <task-output>` for Release and
Debug. It executes actual Foundation/Swift/C URL tests on macOS, compiles real
iphoneos C/ObjC/C++/ObjC++ consumers and the unsigned Swift UIKit legacy/scene app,
checks minos12, copied framework bytes and unchanged exact8 exports. A Linux
Swift/fake UIKit header cannot replace this gate. `check_android.sh <stage> <ABI>
<out> <Release|Debug>` cross-links real C/C++ consumers and checks helper symbols
stay hidden. Neither script establishes device behavior or caller identity.

No screenshot is supplied by an unsigned compiler/packer. On Linux without an
Android emulator/device, adb or Apple SDK/simulator, runtime UI screenshots and
physical lifecycle/identity/associated-domain results remain NOT_RUN. Alternate
evidence is actual reference-handler OS-seam receipts plus real SDK/class/link/
packaging checks. Later authorized device testing must record exact signed
artifact identities, OS/device and benign/malicious receipt outcomes separately.


For an additional actual minified source build, set
`R8_JAR="$ANDROID_HOME/build-tools/35.0.1/lib/d8.jar"` on the same host build
command with a fresh output directory. This uses the installed R8 tool and the
source/fixture keep rules, including API35 helper isolation. Record actual device
API31/35 loading separately; no device result follows from a minified DEX build.
