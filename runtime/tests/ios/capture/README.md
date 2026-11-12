# UIKit capture host and device checks

This fixture displays harmless controls and operation status codes. It never records the screen,
reads screenshot files or sends data. The operator initiates any recording or screenshots.
The runtime needs a matching development framework with its check config selecting `screenshot`
and/or `screen_recording`; source opt-in remains off until the operator presses a button.

On a Mac with the repository's required Xcode, build the actual runtime and verify its ABI:

```sh
cd runtime
cmake --preset ios-dev
cmake --build --preset ios-dev --parallel 2
./tests/ios/capture/check_framework.sh "$PWD/build/ios-dev/ios/RaspRuntime.framework" /tmp/capture-abi
cmake -S tests/ios/capture/host -B build/capture-host -G "Unix Makefiles" \
  -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_SYSTEM_NAME=iOS -DCMAKE_OSX_SYSROOT=iphoneos -DCMAKE_OSX_ARCHITECTURES=arm64 \
  -DCMAKE_OSX_DEPLOYMENT_TARGET=12.0 -DRASP_FRAMEWORK="$PWD/build/ios-dev/ios/RaspRuntime.framework"
cmake --build build/capture-host --parallel 2
```

That last command builds an unsigned iOS app bundle with the actual Xcode compiler/SDK, not a
signed device run. The Makefiles generator preserves iOS 12 without Xcode 27's project-level
minimum-target rejection; the runtime already uses this compiler path. The bundle explicitly
copies the matching framework and uses `@executable_path/Frameworks`. For device execution,
create the fixture IPA from `build/capture-host/CaptureHost.app`, then pack it with the matching runtime/sidecar and
`--checks screenshot,screen_recording`. Follow the packer's normal unsigned-output signing
steps before installing on the device. The host links only the six public C functions; packing
must use the same matching framework ABI. Do not substitute a simulator or synthetic notification
run for a physical device result. No credentials, signatures, app artifacts or screenshots belong
in this repository.

The C++/ObjC++ ABI probes and this ObjC++ fixture use no C++ standard-library headers. They use
`-nostdinc++` so the public C header's `<stdint.h>` resolves through the compiler/system C headers;
Xcode 27's libc++ wrapper otherwise rejects the preserved iOS 12 deployment target. This does not
disable warnings or change the language, system/framework headers, linker inputs or deployment floor.
It does not establish support for arbitrary C++ standard-library code on iOS 12 with that SDK.

Use a physical iOS 12 legacy host; iOS 13–16 selected-scene and non-scene hosts; iOS 17+ scene
traits; and an iPad with multiple scenes. If a version/device is unavailable, record not_run.
The supplied scene manifest enables multi-scene use on supporting versions; to test a true
non-scene iOS 13+ app, build a separate fixture copy without UIApplicationSceneManifest.
On modern non-scene hosts only screenshot observation is supported by this integration.

1. Launch with configured groups but without pressing start. Expect never_started, no measured
   negative state. Start screenshot only; it must not select a scene. Start recording only in a
   fresh stopped session; selecting a scene is still required. Changing active options returns
   OPTIONS_CONFLICT. Repeating identical start returns NO_CHANGE without extra observers.
2. Select the current scene/window with recording already active; the first current value is an
   initial sample, not a transition. Stop and restart recording using system controls. Expect
   callbacks/state changes for the selected scene on iOS 17+, screen-scoped fallback on older iOS.
   Mirroring/AirPlay is the same capture flag semantics, not recorder identity.
3. Use hardware screenshot controls while opted in and active. Count delivered screenshot
   notifications after capture, without attributing them to the selected scene. Repeat without
   a selected scene and with two active scenes; a single notification must not be multiplied.
4. Open another scene using the button on supporting devices. Select A then B; teardown of A
   must not clear B. Background/nonselected-scene lifecycle has no effect on B. Background,
   deactivate and resume the selected scene; current state must become unavailable first and
   resume must take a new initial sample. Disconnect selected B; reselect explicitly on reconnect.
5. Clear selection, repeat clear/stop/start, rotate and change windows/screens. Verify no callbacks
   from the old epoch establish a value and no scene/window stays alive because of this adapter.
   Stop while pending counts exist; the next enabled cycle retains deltas, with current state
   deactivated. Normal app pause/resume must not invent a zero or inactive scene-capture flag.
6. In a debugger pause the main thread past 15 seconds while allowing the worker to run: observe
   stale/absent current state. Resume to recover with an actual main sample. Debugger scheduling
   limitations must be recorded; absence of a worker run is not a passed freshness check.
7. Pack separate screenshot-only / recording-only / identity-only configs. Disabled groups must
   not emit rows or consume the enabled source. Retain a cycle in a test consumer and verify
   subsequent drains/stop cannot change its observations and metadata.

Record exact source HEAD, framework/app SHA-256, Xcode/SDK, device model/OS, selected mode/options,
actions, initial/callback/resample/status/loss observations, expected vs actual result and limits.
Use development runtime cycle logging only; never capture sensitive content. API behavior can
vary by mechanism/OS, and callbacks cannot prove uninterrupted delivery or absence of capture.
Physical device checks are not_run until an operator has actually recorded these results.
