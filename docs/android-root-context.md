# Android root and environment context

Four Android groups are explicit opt-ins: `root_packages`, `root_context`, `proxy` and `developer_settings`.
For example, `--checks root_packages,root_context,proxy,developer_settings` selects six observations.
Packer defaults remain identity only. Existing `root`, `debugger` and `mitm` groups retain their output names
and selection. These observations are client-supplied context, not attestation, root proof, an installed/active
remote-tool classification or a man-in-the-middle verdict. Legitimate development devices, stock containers,
VPNs, corporate proxies and user CAs can produce relevant observations.

Package and proxy reads use the [retained public Application](../runtime/android/stub/README.md).
Initialize `RuntimeBridge` from the attached Application in every participating process. A global
`android:process` alias does not change this API: no process-name-derived package, private ActivityThread
fallback or other-process lookup is used. Before initialization, Context-dependent outputs are error;
a later monitor cycle can succeed. The monitor's interval remains unchanged.

## Fixed outputs

The [portable examples](fixtures/android-root-context-v1.json) cover benign, visible, PAC and unknown states.
Every selected group returns its fixed outputs, including error and unsupported states. No failure is
converted to an empty list or false boolean.

| Group | Signal / source | Successful value |
|---|---|---|
| root_packages | `root.manager_packages_v1` / `package_manager` | Three ordered `PACKAGE visible` or `PACKAGE not_visible` records |
| root_context | `root.mountinfo_context_v1` / `proc_self_mountinfo` | Five strings: `mounts=N`, `overlay=N`, `shared=N`, `master=N`, `root_rw=true` or `root_rw=false` |
| root_context | `root.mount_namespace_v1` / `proc_self_ns_mnt` | This process's `mnt:[decimal]` link identity |
| proxy | `net.default_proxy_v1` / `connectivity_manager` | `[mode=none]`, `[mode=manual, host=HOST, port=N]`, or `[mode=pac]` |
| developer_settings | `debug.adb_enabled_v1` / `settings_global` | Unsupported, no value |
| developer_settings | `debug.developer_options_enabled_v1` / `settings_global` | Unsupported, no value |

The supported Android floor is API 31. Package and proxy collectors read the public `Build.VERSION.SDK_INT`
before Context-dependent calls; below 31 is unsupported, malformed/unreadable version is error. Other native
hosts return unsupported. Developer settings are always unsupported: the current public documentation says
both settings return sanitized zero for all third-party applications. No historical OS/target SDK matrix is
claimed to yield truth, and no settings query with a zero default is made. This deliberately conservative
contract also applies to API 31–35 and future versions until an independently documented trustworthy public
interface exists. Existing JDWP, Debug API and `ro.debuggable` observations remain separate facts; none is
renamed to ADB or developer-options truth.

## Narrow package visibility

[Version1 source data](../packer/src/rasp_packer/android/root_manager_packages_v1.json) is shared by packer queries
and native configure-time generation. The selected identifiers, in order, are:

| Package | Official upstream provenance | Scope |
|---|---|---|
| `com.topjohnwu.magisk` | [Magisk](https://github.com/topjohnwu/Magisk), [upstream changelog identifying the canonical package](https://github.com/topjohnwu/Magisk/blob/master/docs/changes.md) | Default manager only |
| `me.weishu.kernelsu` | [KernelSU manager build configuration](https://github.com/tiann/KernelSU/blob/main/manager/app/build.gradle.kts) | Default manager; PR/custom variants excluded |
| `me.bmax.apatch` | [APatch manager build configuration](https://github.com/bmax121/APatch/blob/main/app/build.gradle.kts) | Default manager only |

These are a deliberately small versioned selection, not an up-to-date catalogue of every manager. Custom,
renamed/repackaged, hidden, other-profile or policy-filtered managers can remain invisible. Package identity
can be reused or spoofed; visible does not establish publisher identity, installation completeness, active
root use, malware or current control of this process.

The collector calls only public `PackageManager.getPackageInfo(name, 0)`, three times. A non-null response
means visible; `NameNotFoundException` means **not_visible**, with nonexistence unproven. Any other exception,
null response, lookup/allocation failure or missing Context/manager invalidates the whole list. No partial
list, app labels, versions, signatures, components or installed-package inventory is exported.

Only selection of `root_packages` adds the three exact `<queries><package android:name="…"/></queries>` entries
to binary APK and proto AAB manifests. Existing host packages, intents, providers, attributes and ordering
are retained. Existing selected names are not duplicated; a repeated mutation is byte-identical. No broad
query, QUERY_ALL_PACKAGES, permission request or settings change is introduced. Host permissions remain
host-owned. The [official visibility documentation](https://developer.android.com/training/package-visibility/declaring)
explains exact-name queries and filtering; the [public PackageManager API](https://developer.android.com/reference/android/content/pm/PackageManager#getPackageInfo(java.lang.String,%20int))
defines the lookup and NameNotFoundException. An app can disappear/change between sequential calls; an
unobservable same-value replacement is not detected.

## Own mount context

Only `/proc/self/mountinfo` and `/proc/self/ns/mnt` are read. No other process, zygote or kernel-worker
inventory is performed. No meaningful supported wchan utility was established, so wchan is omitted.

The mount reader uses an owned nonblocking, close-on-exec descriptor, rejects a final symlink, FIFO,
directory, negative/over-limit size, read/close failure, excessive interruption and detected inode/size/time
changes. It accepts at most 1 MiB and 4096 complete records, 8192 bytes per line and 128 fields per record.
Missing/denied/disappearing paths and any malformed/over-limit table report error, without a partial summary.
Procfs snapshots are not atomic: regular-file metadata comparison cannot detect all same-size/same-time
forgeries, nor all concurrent mount changes.

The parser validates mount/parent IDs, major:minor, absolute mountpoints, mount/superblock options, the `-`
separator, filesystem type/source and propagation fields; it decodes kernel `\040`, `\011`, `\012` and `\134`
escaping before structural comparisons. It accepts benign nsfs synthetic roots such as `net:[decimal]` and
forward optional tags, and requires some root mount to avoid manufacturing a default root flag. Read-only
and read-write options are distinguished exactly. Overlay and shared/master counts describe context only;
stock namespaces, overlayfs and containers are not classified as root. No arbitrary paths, mount sources,
option strings or names of host applications are exported.

The namespace readlink is bounded to 64 bytes and must be exactly `mnt:[nonzero unsigned decimal]`.
The number is an ephemeral process-namespace context token. It is not a device identifier, cross-device
identifier, stable installation identity or evidence that the namespace differs from a trusted system.
No comparison with another process is made. The two mount observations fail independently.

The grammar comes from [official pinned Android kernel show_mountinfo](https://android.googlesource.com/kernel/common/+/c110fed0e606ff922d5cad8ab74ba9410ca41694/fs/proc_namespace.c).

## Default HTTP proxy and permissions

Public `ConnectivityManager.getDefaultProxy()` provides the proxy exposed for this process's global/bound/
default-network context. A successful null result is `mode=none`: no default HTTP proxy exposed by that API.
It does not prove the absence of other proxies, per-connection routing, restricted-network filtering or
interception. Missing Context/service, exceptions including security denial, bad JNI results and malformed
manual metadata report error. No interface enumeration or system property is substituted for this API.

A nonempty public `ProxyInfo.getPacFileUrl()` (tested against `Uri.EMPTY`) reports only `mode=pac`.
The documented null PAC result and `Uri.EMPTY` both select manual metadata; a thrown exception remains error. The URI
is never copied to a native string or exported, and no PAC URL/content is fetched. PAC host/port can be local
resolver details, so neither is reported as the endpoint. Manual proxies export only a host of at most 253
ASCII characters and a port from 1–65535. Hosts must be bounded DNS-style labels or IPv6 literals; URI paths,
credentials, zone identifiers, controls, non-ASCII/unrepresentable names and invalid ports are error. Manual
hosts can reveal local environment names, which is why this group is opt-in. No exclusion list is exported.

No permission is added. The [public default-proxy API](https://developer.android.com/reference/android/net/ConnectivityManager#getDefaultProxy())
(API 23) declares no permission requirement. [Pinned official ConnectivityManager source](https://android.googlesource.com/platform/packages/modules/Connectivity/+/c1f99e3a2b82f389592218076857b3a00e50e831/framework/src/android/net/ConnectivityManager.java)
confirms the public entry and internal network-access filtering. The runtime does not call its hidden
internal methods. Platform/vendor behavior may still limit visibility; errors stay unknown. See also
[ProxyInfo](https://developer.android.com/reference/android/net/ProxyInfo) and the current public
[ADB_ENABLED](https://developer.android.com/reference/android/provider/Settings.Global#ADB_ENABLED) and
[DEVELOPMENT_SETTINGS_ENABLED](https://developer.android.com/reference/android/provider/Settings.Global#DEVELOPMENT_SETTINGS_ENABLED)
contracts. Sources reviewed 2026-11-12; no private settings fallback is used.

## Existing root/jailbreak probe limitations

Existing Android `root.fs_paths` continues to report ENOENT/ENOTDIR as not found in the caller's view;
denied and other lookup failures invalidate that source. iOS `jb.fs_paths` now follows the same error rule:
denial, loops and invalid strings are error with no partial clean list. An empty list never proves stock.

Historical `jb.sandbox_escape/open=false` means only that this particular write attempt failed with a
recognized refusal/missing-parent error. EPERM/EACCES/EROFS/ENOENT can describe sandbox policy, sealed or
read-only storage, or a missing parent. It is not proof of an intact sandbox or an absence of jailbreak.
That raw boolean meaning is retained. The probe now exclusively creates a new file with no final symlink
follow, so an existing host file is left intact and reported error; cleanup/close failures are error.
Positive creation remains a local capability observation, not a cryptographic jailbreak conclusion.

## Reproduction

Production parsers and Android builtin selection are compiled into host tests. The real JVM fixture uses
`-Xcheck:jni`, simulated Android public APIs and the compiled production dispatcher on the caller and 1000
fresh attached workers per package/proxy collector. Only the retained Application global is shared; JNI
local frames are per invocation (24 references) and per package (8 references), and all pending JNI errors
are checked/cleared. Package count is fixed at 3; no unbounded Java lists/arrays are traversed.

Fixtures cover visible/visibility-limited managers, failures after earlier successful queries, null/denied
services, API floors, JNI frame/reference/method failures, proxy none/manual/PAC/malformed/large values,
real own-proc namespace dispatch, stock/overlay/nsfs grammar and malformed/large/missing/FIFO/symlink native
inputs. Real aapt2 fixtures exercise both APK and AAB host queries with an intent, provider, existing package
and permission. Physical Android/vendor/profile and physical iOS verification remain **not run**; Linux
own-proc and JVM execution are not device-effectiveness measurements.
