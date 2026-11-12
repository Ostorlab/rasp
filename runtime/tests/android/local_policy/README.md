# Adapted local policy host

Build the matching compile-only bridge jar and stub with `android/stub/build.sh`.
Then build `device/build.sh <output> <runtime-bridge-compile-only.jar>` with
ANDROID_JAR and ANDROID_BUILD_TOOLS set to actual SDK paths. The jar is compile-only;
the packer supplies the bridge in the stub. Do not bundle another bridge class.

Pack the unsigned host with checks debugger and
`--local-policy ../docs/fixtures/local-policy-android-v1.json` from runtime/.
The host compiles that exact policy hash before packing. A different policy/hash
must be deliberately built into the host, including a changed policy_version.

The native fixture tests exercise the shipping C/JNI facade and actual adapted
in-memory operation for benign, indicator, every unavailable status, stale,
clock error and recovered new-cycle cases. UINT32_MAX runs in a separate JVM to
preserve one-shot policy ownership. These tests replace collector/clock boundaries,
never the gate or the host operation. The source APK does not expose fixture JNI.

`check_library.sh <installed prefix> <ABI> <outputs>` checks exactly three exports
and links actual C/C++ consumers against that installed library and public header.
CI runs it for every release and debug ABI. Cross-linking does not execute a device.

Record physical-device startup, suspend/resume, stale, concurrent host calls and
receipt count results separately; none are claimed by local builds. Local decisions
are hookable client evidence and never server authorization.
