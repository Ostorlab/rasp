# Primitive policy consumers and UIKit host

`../capture/check_framework.sh` checks the exact eight exports, installed headers,
module map, iOS12 floor, and actual C/ObjC/C++/ObjC++ plus Swift host linkage for both
release and debug frameworks using the real Apple SDK. The Swift host references
all 27 typed `kRaspLocal*` constants because Swift cannot import the INT32_C macro form.
Only primitive C values cross
the private-libc++ boundary. Swift UInt32 fields preserve the uint32 version range.

Configure `host/` using Unix Makefiles, the actual iOS toolchain, arm64/iphoneos,
CMAKE_OSX_DEPLOYMENT_TARGET=12.0 and RASP_FRAMEWORK pointing at the validated framework.
Build with parallel2. CI checks the resulting PolicyHost.app minos12 and compares its
copied runtime bytes. The ObjC++ host uses only system C headers and UIKit, so
-nostdinc++ preserves the reviewed iOS12 header search behavior on Xcode27.

The compiled expectation matches docs/fixtures/local-policy-ios-v1.json; pack with
checks debugger and that policy. Recompile the host for any changed policy hash.
Signing/installing/device execution is a separate action, not a local build claim.
On a real iPhone/iPad record startup, stale/suspend/resume and receipt counts. The
host returns before its in-memory mutation on any denial/error. An explicit REPORT
branch is advisory; no source adaptation or server authority can be inferred from
packing or an equality hash. No capture observer is registered by this fixture.
