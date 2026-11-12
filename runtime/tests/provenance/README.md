# Module provenance checks

Stage B reuses the approved Stage A collectors from `f78a8187fac16db9d3b27cdd6f79577652185751`
after merging HD02 `67002a9a9ae78409f90f42341c48f8971e1d15eb`. The shipping
hooks dispatcher emits the allocated revision-10 pairs. Original inactive evidence
and its checkpoint remain intact; dormant-stage assertions are no longer active.
See [module-provenance.md](../../../docs/module-provenance.md) for public semantics
and `/tmp/mega-adr/reports/rt19-stage-b.md` for exact task evidence.

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
Release. The standalone compile-only graph produces objects/static helpers, not a shipping runtime,
DEX, sidecar or packer resource. Actual iPhoneOS/Simulator Foundation/Mach/dyld
adapter compilation, minOS12 imports, UIKit/export gates and physical devices
require the appropriate Apple environment; portable Mach-O fixtures cannot
close those gates. On Apple, the bundle helper uses ARC and disables Objective-C
exceptions in its test target.

When included in the normal native graph, the capability executables check actual
selected/unselected builtin dispatch and both monitor callback paths. With actual
reporting and DNS plugin targets selected, `pl05_sink_test.cpp` uses their real
serializers, private storage, cycle admission, outbox restore/retry and DNS encoder.
Only transport I/O is captured; no external service is contacted. Controlled lanes
replace only collector I/O and preserve the actual parser, reducer and catalogue.
They include source denial/deadline and sample saturation. Sentinel paths and
addresses must be absent from new reduced rows. Existing older hooks retain their
own payload semantics.

The stage-16 retry test preserves an old matched record with its still-active
original authority: native storage has no finite TTL. Serialization loss, monitor
retention loss and original caps remain visible. This does not implement backend
retention/hold/erasure/restore controls or claim backend admission. Emitted fixtures
are local test evidence for the separately owned registered-backend adoption gate.

`ProvenanceIntegration.historyAndPolicy` checks exact revision-9 reconstruction,
unchanged 125 semantic rule blocks, 13/7 selector digests, and the original
3 Android/8 iOS exports. The Apple workflow checks actual SDK sources, obfuscation,
framework exports/minOS12, packer consumer and UIKit hosts, including pinned PL05.
Linux/portable fixtures do not close Apple SDK or physical-device gates.
