# Primitive policy consumers and UIKit host

`../capture/check_framework.sh` checks the exact eight exports, installed headers,
module map, iOS12 floor, and actual C/ObjC/C++/ObjC++ plus Swift host linkage for both
release and debug frameworks using the real Apple SDK. The Swift host references
all 27 typed `kRaspLocal*` constants because Swift cannot import the INT32_C macro form.
Only primitive C values cross the private-libc++ boundary. Swift UInt32 fields preserve
the uint32 version range.

First build and validate the development framework as described in the runtime build
guide. From the repository root, with that actual framework at the path below:

```sh
cmake -S runtime/tests/ios/local_policy/host -B runtime/build/ios-policy-host -G "Unix Makefiles" \
  -DCMAKE_BUILD_TYPE=Debug -DCMAKE_SYSTEM_NAME=iOS -DCMAKE_OSX_SYSROOT=iphoneos \
  -DCMAKE_OSX_ARCHITECTURES=arm64 -DCMAKE_OSX_DEPLOYMENT_TARGET=12.0 \
  -DRASP_FRAMEWORK="$PWD/runtime/build/ios-dev/ios/RaspRuntime.framework"
cmake --build runtime/build/ios-policy-host --parallel 2
```

CI checks that the resulting PolicyHost.app declares the iOS 12.0 minimum platform
version and compares its copied runtime bytes.
The ObjC++ host uses only system C headers and UIKit, so -nostdinc++ preserves the
reviewed iOS12 header search behavior on Xcode27. This build validates linkage; its
app already loads and embeds RaspRuntime and is not an unprotected packer input.

The PolicyHost fixture compiles the exact policy hash matching
docs/fixtures/local-policy-ios-v1.json. Rebuild the fixture when that policy or hash
changes. To pack an unprotected `demo.ipa` using a packer installation with matching
iOS artifacts, run from the repository root:

```sh
rasp pack demo.ipa --platform ios --build-id demo-1 --checks debugger \
  --local-policy docs/fixtures/local-policy-ios-v1.json --output protected.ipa
```

The input must not already load or embed the runtime; the packer rejects already
protected apps. Adapt the source before building the input app and recompile its
expected hash for any changed policy. Packing does not add operation call sites.

Signing/installing/device execution is a separate action, not a local build claim.
Record any real iPhone/iPad startup, stale/suspend/resume and receipt-count outcomes
separately. This fixture appends only for status OK and final ALLOW. REPORT, DENY,
unknown actions and errors return without changing receipts. REPORT remains advisory;
the fixture's choice not to append is not a runtime-enforced denial. Packing or
an equality hash cannot prove adaptation or grant server authority. No capture observer
is registered by this fixture.
