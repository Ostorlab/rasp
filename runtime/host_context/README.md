# Local host context source adapter

This optional source package tracks one explicitly declared sensitive flow and
calls the existing local-policy gate before an adapted host operation. It adds
no measurement, telemetry, backend data or injected runtime code. A coherent
host declaration cannot repair missing, stale or positive native evidence.

Read [the integration contract](../../docs/host-context-contract.md). API version1
and reason vocabulary1 are local source contracts, separate from the native gate
ABI1. Platform source is compiled into the customer's app and must be rebuilt
together with this header. Never add the C helper to RaspRuntime/librasp targets
or package another RuntimeBridge class.

- Android Java: compile `android/co/ostorlab/rasp/host/HostOperationContext.java`
  with the app. Use the existing bridge jar **compile-only**; the packer supplies
  its sole RuntimeBridge definition. No native method or extra stub class is added.
- Apple: compile `src/host_context.c`, `src/clock_math.c`, `ios/host_clock.c` and
  `ios/HostOperationContext.swift` with the host. Its bridging header includes
  `rasp/host_events.h`; include this directory's `include/` and the actual installed
  framework `Headers/`. Link the existing framework. Swift uses its typed
  `kRaspLocal*` values. The host helper symbols have hidden visibility.
- C/ObjC/C++ hosts: compile the same C reducer/arithmetic and the appropriate platform clock
  source, include the header, and link the existing native policy library. Keep
  valid caller-owned storage and enforce main-thread ownership. The core needs
  no heap or C++ runtime.

The portable C source declares two platform functions: a checked suspend-inclusive
clock and main-thread identity. The provided platform files implement them. A host
port must supply those exact boundaries; it cannot supply public event timestamps
or a replacement native decision. There are no host callbacks in the reducer.

Harmless examples are in `../tests/host_context/{android/device,ios}/`; native
consumers and shared C/Java transition vectors are in `../tests/host_context/`.
The source APK/Swift app starts a flow explicitly in its selected Activity/legacy
single-window application, closes it on pause/inactive, and changes only an
in-memory demo receipt count after actual native ALLOW. Its input can stay empty.
It never reads it. These examples deliberately do not execute a REPORT branch.
Production apps that choose advisory execution must code that branch explicitly.

Unsupported input frameworks and custom controls return UNSUPPORTED. This slice
has no Compose/WebView/Flutter/React Native adapter, auto observers, permissions,
keyboard switching, text/key/touch/clipboard/SMS collection, app delegate takeover
or transaction interception. Customer source and UX review are required.
