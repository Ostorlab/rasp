# Adapted local policy host

From `runtime/`, set ANDROID_JAR to an actual API35-or-newer SDK platform jar,
D8 to the SDK d8 executable, and ANDROID_BUILD_TOOLS to that build-tools directory.
Build the matching compile-only bridge jar, stub and harmless source host:

```sh
./android/stub/build.sh /tmp/rasp-policy-sdk
./tests/android/local_policy/device/build.sh /tmp/rasp-policy-host \
  /tmp/rasp-policy-sdk/runtime-bridge-compile-only.jar
```

The jar is compile-only; the packer supplies the bridge in the stub. Do not bundle
another bridge class. With a packer installation containing matching stub/native
artifacts, run this CLI command from `runtime/`:

```sh
rasp pack /tmp/rasp-policy-host/host-unsigned.apk --platform android \
  --build-id demo-1 --checks debugger \
  --local-policy ../docs/fixtures/local-policy-android-v1.json \
  --output /tmp/rasp-policy-host/protected.apk
```

The host compiles that exact policy hash before packing. Rebuild it for a changed
policy/hash, including a changed policy_version. The actual operation admits only
a non-null decision whose `allows()` returns true: status OK and final ALLOW.
REPORT, candidate ALLOW, unknown actions and non-OK results never admit through this
accessor. It reads a historical owned copy; gate again immediately before execution
following any queue, resume or retry.

The native fixture tests exercise the shipping C/JNI facade and actual adapted
in-memory operation for benign, indicator, unavailable status, stale, clock,
coverage and recovered new-cycle cases. UINT32_MAX and explicit report-only run in
separate JVMs to preserve one-shot policy ownership. Future/invalid copied status
and action fields are tested only at the owned Java result boundary. The gate and
host operation are not replaced. The source APK exposes no fixture JNI.

`check_library.sh <installed prefix> <ABI> <outputs>` checks exactly three exports
and links actual C/C++ consumers against that installed library and public header.
CI runs it for every release and debug ABI. Cross-linking does not execute a device.

Record physical-device startup, suspend/resume, stale, concurrent host calls and
receipt-count outcomes separately; none are claimed by local builds. Local decisions
are hookable client evidence and never server authorization.
