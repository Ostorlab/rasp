# Android integration fixture

This host Application deliberately initializes ten seconds after `onCreate`, after the monitor has started and its
initial best-effort lookup can have finished. The real production identity consumer must emit a successful
PackageManager signer measurement on a subsequent pass. No test native API or second Context store is packaged.
Host JVM tests cover absent fallback, early initialization and failure cases separately; this fixture tests real
Android attachment, encrypted host class loading, JNI registration and the context-dependent signer read.

## Build and pack

Run these commands from the repository root. The device build script requires Bash 4 or newer, a JDK and the Android
SDK build tools.

Build all native ABIs needed by the device with the `android-dev` preset (development logs are required). Build the
stub and stage those exact libraries and stub.dex in the packer's resources as described in
[the runtime build documentation](../../../../README.md).
Build this host against the compile-only artifact:

```sh
export ANDROID_JAR="$ANDROID_HOME/platforms/android-35/android.jar"
export ANDROID_BUILD_TOOLS="$ANDROID_HOME/build-tools/35.0.1"
runtime/android/stub/build.sh /tmp/rt02-stub
runtime/tests/android/context_bridge/device/build.sh /tmp/rt02-device /tmp/rt02-stub/runtime-bridge-compile-only.jar
(
  cd packer
  uv run rasp pack /tmp/rt02-device/host-unsigned.apk --platform android --build-id context-bridge-fixture \
    --checks identity --output /tmp/rt02-device/protected-unsigned.apk
)
```

Set `D8` to `$ANDROID_BUILD_TOOLS/d8` when building the stub if d8 is not on PATH. The fixture DEX contains host
classes only. Do not add the compile-only bridge JAR to d8 inputs. The packer supplies its single definition.

## Sign and run on a device

Generate/use a local Android test signing key, then sign with `apksigner` (never a production key):

```sh
keytool -genkeypair -keystore /tmp/rt02-device/test.jks -alias fixture -keyalg RSA \
  -storepass android -keypass android -dname CN=ContextBridgeFixture -validity 30
"$ANDROID_BUILD_TOOLS/apksigner" sign --ks /tmp/rt02-device/test.jks --ks-pass pass:android \
  --out /tmp/rt02-device/protected.apk /tmp/rt02-device/protected-unsigned.apk
runtime/tests/android/context_bridge/device/check.sh /tmp/rt02-device/protected.apk
```

Use a dedicated Android 12+ device/emulator. `check.sh` installs the fixture, clears device logs, launches it, and
captures at most 80 seconds of development logs. It fails unless initialization succeeds/idempotently repeats and
an `sig.cert_sha256/package_manager ok` measurement follows it; crashes fail as well. The previous fallback may also
succeed on Android, so the host JVM's deliberately unavailable ActivityThread case separately verifies preference
for the supplied Application. Repeat on a minified host variant with the documented keep rules in a release pipeline.

## Validation limits

Physical-device execution is **not run** by the host script or by compilation; report it separately. This fixture
also requires development runtime artifacts, a test signing key and adb access. It asserts integration, not device
integrity or cryptographic attestation.

## Window observation mode (RT10)

The same Application now explicitly starts window observation after successful delayed initialization. Its Activity
attaches its already resumed window one second later, because public lifecycle callbacks cannot enumerate existing
Activities. Later Activity resumes/pauses/rotation use the real public lifecycle adapter. Build with SDK35 using the
same commands; pack with `--checks identity,overlay`, and
run `check.sh protected.apk --windows`. The mode checks
all ten production output identities, active adapter and best-effort coverage on the next selected monitor pass.
The root must first finish the approved combined catalogue; independent RT10 artifacts are not publication-ready.

On a dedicated API31+ device, tap the visible fixture, rotate repeatedly, use Home and return, open two Activity
instances in supported multi-window mode, then dismiss them. Keep the app visible through a selected monitor pass
(nominally sixty seconds after the preceding pass); verify touch deltas and active window snapshots follow the
[documented interval contract](../../../../../docs/android-window-observations.md). For manual Dialog coverage,
add a Dialog in a local host variant and explicitly attach after show/detach before dismiss or pause. Test a host
callback installed before attachment and a replacement afterward: the replacement must remain installed, loss
must be reported, and old wrappers retained inside its chain must remain inert after stop. Repeat start/stop from
main thread and reject calls from a worker. A release/minified host must retain RuntimeBridge and RuntimeBridge$*.

For obscured/partially obscured flags, use an explicitly authorized benign overlay fixture on the dedicated test
device, touch both covered/uncovered portions, and record OS/API/ABI, target SDK, overlay settings and observed flags.
Android12+ may block untrusted touches before the app receives them; a zero counter is not absence evidence. Do not
inject fabricated MotionEvent flags and label them actual OS coverage. Normal/obscured/partial/blocked touches and
system accessibility/legitimate overlays need separate recorded cases. Never classify the benign fixture as malware.
The host-JVM suite covers flag handling deterministically; it does not establish OEM dispatch or device efficacy.

No ADB/hardware run is claimed by fixture compilation. No permissions or flags are added to the host manifest.
