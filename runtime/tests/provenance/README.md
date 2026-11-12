# RT19 inactive collector tests

Stage A is based on `0fd8b4d01f6d9e398904dea28f85d193daeb1edb`.
The new Android maps/native-loader/public-JNI and iOS copied-dyld collectors are
compiled only by this test directory. Their implementation is intended for later
reuse after root approves Stage B. Normal dispatch, shipping source lists,
catalogues, six iOS capture exports, packer code and installed resources retain
all parent bytes. No new output is supported by a shipping artifact.

The shared review contract is `/tmp/mega-adr/contracts/module-provenance.md`;
local gate evidence and unavailable platform checks are recorded in
`/tmp/mega-adr/reports/rt19.md`. Those shared files are outside the checkout.
Root owns the final combined runtime/plugin/backend parent and revision.

Collectors report unverified location/topology evidence, without paths, file or
class names, addresses or stable module identifiers. App/OS location is lexical;
loader coverage is best effort. Legitimate ART/JIT/memfd, in-memory DEX, custom
plugins and dyld shared-cache behavior must not be treated as malware or trusted
code. iOS uses declared executable segment flags, not a VM-wide executable scan.
No csops call, attestation or policy enforcement is added. RT04 stays unchanged.

| Boundary | Finite limit |
| --- | --- |
| Maps | Two complete reads, 4 MiB plus EOF probe/read, 8192 records, 8192 bytes/line, 2048 read attempts/read, eight consecutive EINTR |
| Android native images | 4096 images, 1024 program headers/image, 2 MiB total header copies, 4 MiB names, 16384 executable intervals |
| Public app locations | Base plus 64 split APK paths, 4096 bytes/path, 256 KiB aggregate |
| Java topology | Two public passes, 16 nodes, 256 UTF-16 units/class name, 64-slot local frame; 900 checkpoints plus bounded cleanup keep total JNI calls below 2048 |
| iOS images | Two passes, 4096 images/pass, 4096 commands/image, 64 KiB commands/image, 8 MiB headers and 4 MiB names/pass |
| Work | 131072 checkpoints/source, 100 ms cooperative time/source; no cancellation of blocked native/JNI calls |
| Output | Module source 32 rows ×192 bytes; topology 16×96; fixed metadata ≤256 bytes; each failed data source has monostate |

Input/source failure never becomes an empty successful inventory. Output sample
saturation does not stop complete-source validation. Native/proc sources remain
independent; changed brackets or failed second maps reads make correlation
unknown. Bracketing cannot exclude an ABA race. Unknown boundary error codes
become an explicit error, never a clean result.

`native_module_name_test.cpp` replaces only `dl_iterate_phdr` metadata. It uses
actual `mmap`/`mprotect` guard pages and the actual `process_vm_readv` adapter to
verify a valid NUL immediately before an unreadable page, an inaccessible pointer,
and a 4096-byte unterminated name. Page-aware copies stop at the terminator while
retaining pointer, byte and work limits. Outside an active case the link wrapper
delegates to the real iterator so sanitizer loader enumeration remains intact.
This interposed executable is excluded under TSan because its startup iterator
runs before TSan initializes. ASan/UBSan/leak checks cover all three cases; TSan
still covers actual native collectors and JNI boundaries in other executables.

The real JVM suite uses ordinary `java.lang.ClassLoader` parent/name operations
with `-Xcheck:jni`. Java fixtures replace only public Application services. It is
not ART/device evidence. Sanitizer runs use the native JNI failure-boundary table
without starting a JVM. Preexisting host exceptions are preserved; probe-owned
exceptions and local frames are cleaned up.

Standalone host build (CMake 4.4, Clang, JDK development headers and GoogleTest
1.17 are required; a read-only FetchContent source cache may be supplied):

```sh
cmake -S runtime/tests/provenance -B /tmp/rt19-host \
  -DCMAKE_CXX_COMPILER=clang++ -DCMAKE_C_COMPILER=clang \
  -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
cmake --build /tmp/rt19-host --parallel 2
ctest --test-dir /tmp/rt19-host --parallel 2 --output-on-failure
```

Use C/C++ `-fsanitize=address,undefined -fno-omit-frame-pointer
-fno-sanitize-recover=all` or `-fsanitize=thread -fno-omit-frame-pointer` for the
corresponding native sanitizer builds. Host LLVM20 was available locally; exact
LLVM23 CI remains a separate gate.

For NDK adapters, configure this directory with the NDK toolchain,
`ANDROID_PLATFORM=android-31`, each supported `ANDROID_ABI`,
`ANDROID_STL=c++_static` and `RASP_PROVENANCE_COMPILE_ONLY=ON`; build in Debug and
Release. This produces inactive objects/static helpers, not a shipping runtime,
DEX, sidecar or packer resource. Actual iPhoneOS/Simulator Foundation/Mach/dyld
adapter compilation, minOS12 imports, UIKit/export gates and physical devices
require the appropriate Apple environment; portable Mach-O fixtures cannot
close those gates. On Apple, the bundle helper uses ARC and disables Objective-C
exceptions in its test target.

When included by the normal `RASP_BUILD_TESTS=ON` native graph, actual Android/iOS
capability executables gain dormant builtin/CycleMonitor checks. Optional frozen
PL03 sink checks require `RASP_PROVENANCE_PL03_SOURCE` pointing at the task-owned
copy of exact commit `e5f3ec3df0cd3e34dfad43bdc15e6533578f22d7`, with its verified
`source-identities.json`. Configuration validates every copied file hash. It
uses unchanged Sender/serializer/CycleDelivery/Outbox/DNS encoder sources, real
private storage, and captured external network boundaries. The digest C island
uses the native TF-PSA SHA256 implementation with its private declaration macro;
this test does not validate PL03 platform TLS adapters. No live sibling source
or dependency environment is modified.

Dormancy executables do not link collector objects. A separate explicit exposure
executable invokes all eight proposed pairs and proves inherited serialization,
spooling and retry without approved catalogue coverage or finite local TTL.
Those intentionally incomplete test cycles are never published. Reporting
opt-in can automatically upload/spool future delivered rows; no per-pair privacy
filter is implemented. Stage B stays held before emission/artifact admission
pending exact tenant/authority, hold, retention, erasure, restore and consumer
approval. Existing deletion scope is not expanded.

`ProvenanceDormancy.exactInheritedBytes` compares inherited files against the
exact parent and admits only new collector/helpers/test paths plus the test
CMake addition. It proves dormant source bytes, not device efficacy. The full
unchanged installed packer matrix is not duplicated for these inactive objects;
root must run genuine combined artifact/packer/consumer gates before Stage B.
