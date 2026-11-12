# Android service metadata observations

The opt-in `accessibility`, `input_method` and `notification_access` groups report bounded service metadata visible
to the calling app's Android user. They do not classify services or their publishers. TalkBack, password managers,
custom assistive keyboards and authorized support tools can legitimately produce nonempty results. A capability
or request flag does not establish that a service is connected, receiving events, controlling this app, reading a
password, intercepting an OTP or displaying the current keyboard.

Enable the groups explicitly, for example `--checks accessibility,input_method,notification_access`. Packer defaults
remain identity only; a native config with no groups still runs no checks. No iOS group or output is added.

## Supported initialization and ownership

The host must supply its attached Application through `RuntimeBridge.initialize(this)` from `Application.onCreate`
in each participating process. Follow the [compile-only bridge, shrinker and initialization instructions](../runtime/android/stub/README.md).
These new collectors use only that supported retained Context; they never use the signer's legacy private
ActivityThread fallback. Before initialization, each Context-dependent output reports error. A later monitor pass
can succeed after initialization; the nominal interval remains 60 seconds after the previous pass finishes.

All service reads run on the monitor worker, using its attached JNI environment. Only the process-lifetime
Application global reference is shared; no JNIEnv or local reference crosses threads. Each collector owns a local
frame (capacity 24); each list entry has a separate frame. Frames are popped on every path. Allocation, lookup,
service-call and string-read exceptions are checked and cleared before returning an error. No initialization,
permission request or settings change is performed by a collector.

## Exact native output contracts

Each selected group emits the fixed observation count below, including errors and unsupported results. A list's
length is independent of that count. `ok`, `error` and `unsupported` below name the native statuses, as displayed by
`describe`; the portable fixtures are contract examples, not a new transport schema.

| Group | Signal / source | Value when ok | Observation count |
|---|---|---|---|
| accessibility | `a11y.enabled_services` / `accessibility_manager` | Sorted unique string list; each record is `package/fully.qualified.Class capabilities=U flags=U` | 1 |
| input_method | `ime.enabled_components` / `input_method_manager` | Sorted unique string list of `package/fully.qualified.Class` | 1 |
| input_method | `ime.current_component` / `input_method_manager` | One `package/fully.qualified.Class` string; selected IME for this process's user | 1 |
| notification_access | `notification.enabled_listeners` / `settings_secure` | Sorted unique string list of `package/fully.qualified.Class` | 1 |

`U` is the decimal unsigned representation of the complete 32-bit Java `int` mask. Accessibility capabilities come
from `getCapabilities()`; flags come from the public `flags` field and describe requests/configuration. Unknown
future bits are preserved. Only identical complete records deduplicate: two services in one package, or one
component returned with distinct masks, remain distinct. Relative `.Class` names expand to `package.Class` before
sorting. No parallel component/flag arrays can lose association.

| Public OS API level | Accessibility | Enabled IMEs | Selected IME | Notification listeners |
|---|---|---|---|---|
| Below 31 | unsupported | unsupported | unsupported | unsupported |
| 31, 32, 33 | enabled accessibility component/capability/flag records | public enabled list, fallback context only | unsupported; no lookup of the API34 method | AndroidX-compatible secure setting pattern; denied/missing values remain error |
| 34, 35 and later | same enabled accessibility component/capability/flag records | same public enabled list | public `getCurrentInputMethodInfo()` | same pattern; denied/missing values remain error |

The runtime's supported Android floor is 31. Version gates use public `Build.VERSION.SDK_INT`, before looking up
newer methods. An unreadable/malformed SDK value reports error. Future OS versions are attempted through these
public interfaces; vendor policy or API behavior can still make reads unavailable. The selected IME is the user's
selection, not proof it is visible, bound to this app's focused editor or processing text. On older supported OS
versions the enabled list supplies context and never substitutes a supposed current value.

A non-null empty accessibility/IME list is a valid empty list. A null list, null entry, null component or null
API34 selected IME is unknown/error. For notification listeners, only an explicit empty setting string means an
empty list; a null result is unknown/error. Exceptions (including denied settings access), missing services,
lookup/reference failures, malformed components, changing list size and any limit overflow return error with no
value. A list read fails as a whole even after valid earlier entries. The two IME observations fail independently;
a failed enabled-list read can coexist with a successful selected component. Error status does not encode a
particular exception or permission cause and must never be assessed as absence of services.

## Bounds and visibility

Each list accepts at most 128 entries, counted before deduplication. Raw and normalized components are limited to
1024 ASCII bytes each, using dot-separated Java identifier segments (letters, digits after the initial character,
`_` and `$`). Non-ASCII identifiers, controls, embedded NUL, separators, empty segments and malformed components
are conservatively unknown/error. Valid but unrepresentable names are not truncated into another service.

The notification string is limited to 131072 UTF-16 code units before native copying, then validated as ASCII;
normalization also enforces 131072 total output bytes. Accessibility and IME lists independently enforce 131072
summed complete record bytes, including accessibility flag suffixes. The current component has its own 1024-byte
limit. Local references, loops and native string allocations are bounded; the platform owns the Java objects it
returns. No partial, truncated or over-limit list is reported as clean. Public service snapshots are not atomic;
size changes are rejected, but a same-size concurrent replacement cannot be detected.

Results cover the current process user/profile and what the OS exposes to that caller. They are not a device-wide
or cross-profile inventory. These paths do not query PackageManager's installed packages, request
QUERY_ALL_PACKAGES, add `<queries>`, or infer that a package is absent because it cannot be resolved. OS/vendor
filtering, settings policy and service changes can limit completeness. No READ_SMS, POST_NOTIFICATIONS,
notification-listener binding, accessibility-service declaration or privileged settings permission is added.

No screen content, accessibility event payload, typed text, key events, SMS, notification body, clipboard,
contacts/accounts, application labels/descriptions or other-process memory is collected. Component identifiers can
still reveal use of assistive or support software; enable and retain these optional observations only for the
host's agreed purpose. These facts can be spoofed on an attacker-controlled client and are not attestation.

## Primary API provenance

Verified against the following primary documentation and source on 2026-11-12:

- [AccessibilityManager.getEnabledAccessibilityServiceList(int)](https://developer.android.com/reference/android/view/accessibility/AccessibilityManager#getEnabledAccessibilityServiceList(int))
  is public since API14. The collector passes `AccessibilityServiceInfo.FEEDBACK_ALL_MASK` (`-1`) and reads only
  [getCapabilities()](https://developer.android.com/reference/android/accessibilityservice/AccessibilityServiceInfo#getCapabilities())
  (API18), [flags](https://developer.android.com/reference/android/accessibilityservice/AccessibilityServiceInfo#flags)
  and [getId()](https://developer.android.com/reference/android/accessibilityservice/AccessibilityServiceInfo#getId()).
  [Android 15 AccessibilityServiceInfo source, getId](https://github.com/aosp-mirror/platform_frameworks_base/blob/android-15.0.0_r1/core/java/android/accessibilityservice/AccessibilityServiceInfo.java#L882)
  confirms the flattened-short ComponentName representation and nullable unset component. Capabilities and flags
  describe metadata/configuration, not observation of service actions.
- [InputMethodManager.getEnabledInputMethodList()](https://developer.android.com/reference/android/view/inputmethod/InputMethodManager#getEnabledInputMethodList())
  is public since API3 and returns a non-null list for the calling process user.
  [getCurrentInputMethodInfo()](https://developer.android.com/reference/android/view/inputmethod/InputMethodManager#getCurrentInputMethodInfo())
  is public since API34, returns the selected IME for that user and explicitly permits null.
  [InputMethodInfo.getId()](https://developer.android.com/reference/android/view/inputmethod/InputMethodInfo#getId())
  supplies the component identifier; [Android 15 InputMethodInfo.computeId source](https://github.com/aosp-mirror/platform_frameworks_base/blob/android-15.0.0_r1/core/java/android/view/inputmethod/InputMethodInfo.java#L202)
  confirms `ComponentName.flattenToShortString()`. No secure-setting default-IME heuristic is used.
- [AndroidX NotificationManagerCompat.getEnabledListenerPackages source](https://github.com/androidx/androidx/blob/androidx-main/core/core/src/main/java/androidx/core/app/NotificationManagerCompat.java#L706)
  uses public `Settings.Secure.getString(context.getContentResolver(), "enabled_notification_listeners")`, splits on
  `:` and parses ComponentName. The collector uses this compatible pattern but retains full components rather than
  collapsing packages, rejects malformed entries, and treats null as unknown instead of reusing a cached result.
  [Android 15 Settings.Secure source](https://github.com/aosp-mirror/platform_frameworks_base/blob/android-15.0.0_r1/core/java/android/provider/Settings.java#L9727)
  identifies the colon-separated enabled-listener setting as readable. The SDK constant itself is hidden; no hidden
  field is looked up. This is a compatibility pattern, not a public guarantee that every vendor/future OS exposes
  the setting. There is no invented NotificationManager enumeration API.
- [JNI ownership and threading](https://developer.android.com/ndk/guides/jni-tips) and
  [package visibility](https://developer.android.com/training/package-visibility) describe relevant integration
  constraints. No PackageManager inventory or settings-write workaround is used.

## Reproduction and coverage

The host CMake preset builds `rasp_android_service_jni` and the framework-shaped Java fixtures alongside the shipped
RuntimeBridge. `AndroidServiceExposure.publicMetadata` runs real JVM JNI with `-Xcheck:jni`, the compiled production
dispatcher/collectors, simulated SDK31/33/34/35 and an API34 method that fails if called below its gate. Controls
include no Context; valid empty lists; TalkBack/password-manager/custom assistive IME/support-listener metadata;
selected/enabled distinction; relative/full names; preserved masks including unknown high bits; null/malformed
records; denied/throwing/missing services; JNI local-reference/frame/method failures; component/count/byte overflow;
partial-list exceptions; and 1000 attached worker reads with detach. These API-level results are simulations,
not ART/device executions. Host native parser/dispatch tests also run without a JVM, including sanitizer presets.
The JVM fixture is intentionally excluded from sanitizer presets, consistently with the existing bridge tests.

From `runtime/`, using the documented cached/pinned toolchain and at most two jobs:

```sh
cmake --preset host
cmake --build --preset host --parallel 2
ctest --preset host --parallel 2 --output-on-failure -R '^(AndroidServiceExposure|ServiceComponents|android[.]Builtin)'
```

The [task-only Android fixture](../runtime/tests/android/context_bridge/device/README.md#service-metadata-checks)
allows repeatable measurement after real Application attachment without adding a production probe API. Compilation
and host tests do not establish physical-device, vendor/profile, minified-host or service effectiveness results.
[Portable positive, benign and unknown examples](fixtures/android-service-observations-v1.json) define exact output
names and semantics for coordinated backend/UI adoption. They deliberately contain no malware-family or automatic
malware verdict. These four outputs, introduced in schema 1, revision 4, remain unchanged in schema 1, revision 9, catalogue `2a9b706406907d297b139d0b24c70acb41c0dc452f6cad826dfd08d3487f553d`,
alongside the inherited inline-hook and second-source contracts. Native CMake emits sidecars
for this combined source; a pristine revision 3 sidecar remains foreign to its revision 9 consumer.
See [binding and expected-output semantics](check-capabilities.md). Backend/UI adoption remains
a separate coordinated change.
