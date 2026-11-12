# Runtime

The C++ runtime libraries that the packer adds to a protected app. They run the checks inside the app.

Before you change anything here, read [CONTRIBUTING.md](CONTRIBUTING.md): it lists the rules the build enforces and the ones reviewers check.

## Layout

The code is grouped the same way at every level. `util/` holds generic helpers that know nothing about RASP. Every other folder is one domain module, named after the job it does, such as `checks/`, which produces the observations, and on Android, `payload/`, which recovers the app's protected code. When a module has a part shared by every platform, that part is in `core/`, and its platform part is in the folder with the same name under `ios/` or `android/`. Every built-in check is platform code, so the built-in checks are only in the platform folders.

- `core/`: code shared by every platform. It uses no platform API.
  - `include/rasp/config.h`: `Config`, the runtime's config that the packer writes into the app (the build id and the ids of the check groups to run), and `is_check_enabled`. Without a list of groups, no group runs.
  - `include/rasp/parse_config.h`: `parse_config`, which reads the config from the JSON the packer writes. Members it doesn't know are ignored.
  - `include/rasp/cycle.h`: the finite monitor-cycle path and immutable owned metadata/observation snapshot. See the [consumer contract](../docs/measurement-cycle-contract.md) for callback ownership, coverage, bounds and rollout.
  - `include/rasp/private_storage.h`: `acquire_private_storage`, the worker-thread-only call that returns an owned private directory and matching stable install identity, queried independently after late Application attachment. See the [storage consumer contract](../docs/private-storage-contract.md).
  - `include/rasp/observation.h`: `Observation`, the raw fact a check reports (`signal`, `source`, `status`, `value`), and `observed`, `unsupported` and `failed`, which build one.
  - `include/rasp/util/`: generic helpers.
    - `logging.h`: `rasp::log` and `kLoggingEnabled`, the development logging that release builds leave out.
    - `read_file.h`: `read_file`, which reads a whole file up to a size limit, for the checks that read files under `/proc` and `/sys`.
  - `src/`: the code of these headers, in the same folders.
- `ios/`: `RaspRuntime.framework`, the runtime for iOS. When the app loads it, it starts the thread that runs the checks.
  - `src/monitoring.h`: `start_monitoring`, the runtime's thread. It runs the check groups the config lists, then runs them again every 60 seconds. A development build logs each observation. It runs until the process exits, and iOS suspends it while the app is in the background.
  - `src/checks/`: the iOS checks. Each one reports observations.
    - `debugger.h`: the debugger checks. Off a physical device every observation has the unsupported status.
      - `dbg.traced`: whether the kernel marks the app's process as traced by a debugger, read through sysctl from the `P_TRACED` flag of the process. The monitoring thread reads it on every pass, so it also sees a debugger that attaches after launch.
      - `dbg.parent`: the process id of the app's parent process, read through getppid. An app that iOS launched normally has `launchd`, process id 1, as its parent; an app launched under a debugger has another parent. The runtime reports the value and doesn't judge it.
    - `jailbreak.h`: the jailbreak checks. `jb.fs_paths` (do known jailbreak files exist, read through access and stat), `jb.sandbox_escape` (can the app write outside its sandbox) and `jb.fork_ok` (can the app start a child process). Off a physical device every one is unsupported.
    - `emulator.h`: the emulator check, which reports whether the app runs on the iOS Simulator rather than a physical device. Unlike the other iOS checks it is useful on the Simulator — the thing it detects — so it reports a real `true` there rather than `unsupported`; on a physical device both sources read normally and report `false`, and only off Apple platforms, where `TargetConditionals.h` and the `hw.machine` MIB don't exist, is every observation `unsupported`.
      - `emu.simulator`: whether the app runs on the Simulator, read through two sources. `target_conditionals` is the compile-time `TARGET_OS_SIMULATOR` flag, baked into the slice when it was built, so a correctly built device binary can't carry a `true`. `sysctl` reads `hw.machine`: on a device it is the model identifier such as `iPhone15,2`, on the Simulator it is the host Mac's architecture (`x86_64` or `arm64`), which no physical device reports. The second source confirms the first at runtime, so a repacked binary can't simply report `false`.
    - `mitm.h`: the network-interception (man-in-the-middle, MITM) checks. `mitm.tunnels` and `mitm.proxies` run on a physical device, and `mitm.user_cas` is unsupported everywhere. Off a physical device every observation has the unsupported status.
      - `mitm.tunnels`: the names of the process's tunnel interfaces that are up and carry an IPv4 address, read through getifaddrs. A name matches when it is `utun`, `ipsec`, `ppp`, `tun` or `tap` followed by digits and nothing else, such as `utun3` (a Network Extension packet tunnel), `ipsec0` (a built-in IKEv2 or IPsec VPN) or `ppp0`; a name like the IPIP `tunl0` does not match. Stock iOS keeps several `utun` interfaces open for its own services, so the name alone would match on every device; an interface is reported only when getifaddrs lists it with the `IFF_UP` flag and an `AF_INET` address, the kind of address a VPN app assigns to its tunnel. A tunnel whose only addresses are IPv6 is not reported. The value is a list of strings, sorted and without duplicates, at most the 100 smallest, and an empty list when there is no such tunnel. It has the same name and value as the Android signal. A legitimate VPN opens the same interfaces as a capture app, so the runtime reports the tunnels and doesn't judge them. The monitoring thread reads it on every pass, so it also sees a tunnel opened after launch.
      - `mitm.proxies`: the proxies that the system's current proxy settings configure, read through CFNetworkCopySystemProxySettings from the settings of the device's primary network. Each proxy is one string: a manual HTTP proxy that is enabled and has a host is `http <host>:<port>`, such as `http 192.168.1.10:8080`, with an IPv6 host between brackets, such as `http [fd00::2]:8080`, and without `:<port>` when it has no port; proxy auto-config that is enabled is `pac <url>`, such as `pac http://wpad.example/proxy.pac`, or `pac` alone when it has no URL. The HTTP proxy comes first, so the list has at most two strings, and it is empty when no proxy is configured. Only the keys iOS makes available are read (`kCFNetworkProxiesHTTPEnable`, `kCFNetworkProxiesHTTPProxy`, `kCFNetworkProxiesHTTPPort`, `kCFNetworkProxiesProxyAutoConfigEnable` and `kCFNetworkProxiesProxyAutoConfigURLString`); the HTTPS, SOCKS and FTP keys are marked unavailable on iOS. A host or URL is kept to its first 1024 bytes of UTF-8. A value of the wrong type, or a port outside 0 to 65535, is reported as an error, like a failed call. An interception proxy such as Burp Suite or mitmproxy set in the Wi-Fi settings shows up here, and so does a company's proxy, so the runtime reports the proxies and doesn't judge them. The monitoring thread reads it on every pass, so it also sees a proxy set after launch. A VPN that carries the device's traffic becomes the primary network, so while it is connected the signal reports the VPN's proxies, usually none, and not the Wi-Fi proxy: the traffic then goes through the tunnel and not through the Wi-Fi proxy, and the tunnel is reported by `mitm.tunnels`.
      - `mitm.user_cas`: always unsupported, through `trust_store`. iOS has no public API that lists the certificate authorities the user installed, such as the root of an interception proxy, and the trust store is outside the app's sandbox. The signal is still reported, so iOS and Android report the same signals. Interception through such an authority can be caught when it is used instead, by checking the key of a TLS connection to a known server; that is future work, listed in `TODO.md`.
    - `virtualizer.h`: the virtualizer check, which reports whether the app runs as a guest inside another app (an app virtualizer) rather than installed as a standalone app. Off a physical device every observation is unsupported.
      - `virt.exec_path`: whether the main executable's path, read through dyld, lies outside the system's app-container layout `/private/var/containers/Bundle/Application/<UUID>/<App>.app/`. A genuine install sits inside it; a virtualizer loads the guest from its own data container (under `/private/var/mobile/Containers/Data/Application/`) instead of a system bundle path, so the executable path lies outside the layout. A sophisticated virtualizer can fake the path, so this is a signal, not proof.
      - `virt.foreign_images`: the loaded images, read through dyld, whose path lies outside the legitimate roots:
        - the app's own bundle directory
        - `/usr/lib`
        - `/System`
        - the cryptex OS images under `/private/preboot/.../Cryptexes/OS/System/`, where modern iOS keeps stock frameworks such as WebKit

        A virtualizer maps its own runtime into the guest from its data container, so those images show up here (at most 64 such images are reported). A clean process reports an empty list.
    - `hooks.h`: the hooking checks. Off a physical device every observation has the unsupported status.
      - `hook.maps_hits`: the paths of the images loaded in the process, read through dyld, that name a known instrumentation or hooking framework (Frida, Cycript, Substrate and the tweak loaders that replace it, SSL Kill Switch and the like), matched on the file name or on a folder that only holds tweaks, without regard to case.
      - `hook.dyld_env`: the value of `DYLD_INSERT_LIBRARIES` when the runtime loaded, read through getenv, the libraries the environment asks dyld to insert into the app.
      - `hook.frida_port`: whether a TCP connection to port 27042 of the loopback address is accepted, read through connect, the port frida-server and Frida Gadget listen on by default.
      - `hook.rwx_regions`: the regions of the app's memory that are both writable and executable, read through vm_region, where injected code is often written.
    - `integrity.h`: the runtime's own executable integrity observations, enabled by the `integrity` group. Off a physical iOS device both observations are unsupported.
      - `integ.text_sha256`: two lowercase SHA-256 strings, from `file` and `memory`, for the running RaspRuntime image's `__TEXT,__text` section. `dladdr` locates this framework, independently of the customer's main executable. The runtime reports the values for a later assessor to compare; it does not report a tampering verdict.

        Only the nonempty, file-backed, regular pure-instruction section in a read/execute `__TEXT` segment is measured. Headers, padding, signatures, writable data and dyld-mutated pointers are excluded. Thin arm64 executable/dylib layouts are supported, including signed images and code transformed at compile time by O-MVLL. The checked memory reader uses `vm_read_overwrite`; inaccessible or concurrently unmapped memory returns an error without a direct pointer dereference. Slide resolution uses the mapped header plus the section's offset from `__TEXT.vmaddr`.

        Load commands are limited to 1 MiB, each of at most five fixup streams (four classic dyld streams and one chained-fixup payload) to 1 MiB, and code to 64 MiB. Offsets, virtual ranges, section flags and relocation metadata are checked against the [Mach-O layout](https://github.com/apple-oss-distributions/xnu/blob/main/EXTERNAL_HEADERS/mach-o/loader.h) and [chained fixup structures](https://github.com/apple-oss-distributions/dyld/blob/main/include/mach-o/fixup-chains.h). Classic pointer rebase/bind streams and chained fixups outside `__TEXT` are accepted; unsupported chained multi-start page layouts return unsupported. Declared text fixups, classic relocation tables, non-pointer or threaded dyld opcodes are unsupported. Missing, truncated, malformed or unreadable sources return error observations with no value; unsupported image layouts (including fat or non-arm64 files) are rejected as errors. Encrypted disk code is unsupported while its readable mapped code can still be hashed.

        The installed file is an attacker-controlled baseline. Matching hashes do not defeat an attacker patching both file and memory, redirecting reads, or changing the reporting code. They are observations, not cryptographic attestation. The production reader runs only on a physical iOS device; host fixtures do not exercise `vm_read_overwrite` or establish on-device behavior.
    - `identity.h`: the app-identity self-check, which reports the identity the app runs with, which a repackaged or re-signed copy changes. Off a physical device every observation has the unsupported status.
      - `id.bundle_id`: the bundle identifier of the app's main bundle, read through two sources. `CFBundle` is the value CoreFoundation reports, and `Info.plist` is the `CFBundleIdentifier` key read from the main bundle's Info.plist file on disk, so a hook on CFBundle shows as two values that disagree.
      - `id.team_id`: the Team ID of the code signature of the app's main executable, read through `code_signature`.
      - `id.cdhash`: the cdhash of the code signature of the app's main executable, read through `code_signature`.
  - `src/util/logging.cpp`: the iOS backend of `rasp::log`, which writes to the system log with os_log.
- `android/`: `librasp.so`, the runtime for Android, and the stub that loads it. When the library loads, it starts the thread that runs the checks. The stub then has it install the on-demand class loader, which decrypts each of the app's own dex files the first time one of its classes is needed.
  - `src/entry.cpp`: a load-time constructor that starts the runtime's thread.
  - `src/monitoring.h`: `start_monitoring`, the runtime's thread. It runs the check groups the config lists, then runs them again every 60 seconds. A development build logs each observation. It runs until the process exits.
  - `src/checks/`: the Android checks. Each one reports observations.
    - `service_exposure.h`: opt-in `accessibility`, `input_method` and `notification_access` groups. With the explicit retained Application Context, they report enabled accessibility component/capability/flag records, enabled IMEs plus the selected IME on API34+, and enabled notification-listener components through the AndroidX-compatible secure-setting pattern. No contents or key events are read. Empty, unavailable and failed reads remain distinct; assistive software is legitimate context. See [exact contracts, bounds, API gates, provenance and fixtures](../docs/android-service-observations.md).
    - `debugger.h`: the debugger checks. They run on Android; off Android every observation has the unsupported status.
      - `dbg.tracer_pid`: the process id of the native debugger attached to the app, 0 when there is none, read from the `TracerPid:` line of `/proc/self/status`.
      - `dbg.java_debugger`: whether a Java debugger is connected to the app, read through two sources that fail in different ways. `jdwp_threads` is the names of the app's threads that belong to JDWP, the connection of a Java debugger, read from `/proc/self/task/*/comm`: `ADB-JDWP Connec` runs while the app can be debugged, `JDWP Transport ` and `JDWP Event Help` start when a debugger attaches and stay after it detaches, and only `JDWP Command Re` runs while a debugger is attached. `debug_api` is what `android.os.Debug.isDebuggerConnected` returns through JNI, or an error status when the call can't be made or throws. Renamed threads leave the method returning `true`, and a hook on the method leaves the threads, so hiding one source shows as two values that disagree.
    - `emulator.h`: the emulator checks, which report whether the app runs on an emulator or a virtualized device rather than real hardware. They run on Android; off Android every observation has the unsupported status.
      - `emu.props`: the build properties whose value is an emulator tell, read through the system property store, as `name=value`. The hardware property is `goldfish` or `ranchu` (the Android emulator's machines), one of the QEMU flags `ro.kernel.qemu` or `ro.boot.qemu` is set, or the product name, model or device carries `sdk`, `emulator` or `generic`. A real device sets these to its own hardware and product names, so none match and the check reports nothing.
    - `hooks.h`: the hooking checks. They run on Android; off Android every observation has the unsupported status.
      - `hook.maps_hits`: the lines of `/proc/self/maps` that name a known instrumentation framework (Frida, Substrate, Xposed and the like), matched case-insensitively.
      - `hook.rwx_regions`: the lines of `/proc/self/maps` that map memory both writable and executable, where injected code is often written.
      - `hook.threads` through `proc_task`: the names of the app's own threads that announce Frida's Gum JavaScript runtime, read from `/proc/self/task/*/comm`. Any name containing `gum-js-loop` (Frida's Gum JavaScript interpreter loop) or `frida` matches, ignoring case; generic `gmain` and thread-pool names alone do not match. The check reports the lexicographically smallest 32 distinct matching names.

        The scan accepts at most 4096 numeric thread-ID entries and 16 bytes per comm file (1–15 non-control name bytes plus newline); nonnumeric entries are skipped before counting or reading, and reaching 32 matches does not stop enumeration. A complete bounded read returns `kOk` and a string list, empty when nothing matches. Listing/read failures, disappeared numeric entries, malformed names or extra tasks return `kError` with no value, even if some names matched. The status does not identify the failure's errno.

        These names are raw heuristic evidence: legitimate names can match, renaming or hiding threads evades the probe, markers past the kernel's 15-byte truncation point are invisible, and concurrent changes prevent an atomic snapshot. This is not exhaustive anti-Frida detection or cryptographic attestation.
      - `hook.inline` through `prologue`: a bounded comparison of selected libc/libdl function-entry bytes with their on-disk ELF definitions. It emits one status and a list of changed names, without an enforcement action or malware verdict. See [inline_hooks.md](inline_hooks.md) for the exact list, limits, status contract and host/device validation boundary.
    - `identity.h`: the app-identity self-check. It reports the running package name, the process's own user id, the path the runtime's library loads from, and signing-certificate digests through native reads and public PackageManager JNI. Off Android every observation has the unsupported status.
      - `id.package`: the first NUL-separated field of `/proc/self/cmdline`, which Android sets to the process name, with any private `:<name>` suffix of a secondary process trimmed. That read is the package name for the main and private processes, but not for a global `android:process` name such as `com.other:remote`, where the process name isn't the package; the additive `id.package.v1/application_context` reads `getPackageName()` from the supported retained Application for actual package identity. A clone or a repackaged app published under a different name reports that other name.
      - `id.uid`: the process's own user id, from `getuid`. Android packs the user and the app into one number as `user_id * 100000 + app_id` (app id 10000-19999, with 99000-99999 reserved for isolated processes), so `uid / 100000` is the user the app runs under:
        - user 0, the main install: apps sit in 10000-19999
        - user 1 or more, a copy running in a work profile, an OEM "Dual Apps" clone, or an added user: apps sit in 110000-119999 (user 1), 1010000-1019999 (user 10), and so on

        The probe reports the raw uid and doesn't decide, since a work profile is legitimate while, say, a cloned banking app may not be. It doesn't catch a third-party virtualizer (such as Parallel Space) that runs under the host's own uid; `id.code_path` does.
      - `id.code_path`: the path `librasp.so` loads from, reported from the raw `dladdr` result (`dli_fname`). A genuine install loads it from the app's own install directory `/data/app/.../<package>-<suffix>`, in one of three forms (the embedded forms are what AGP produces when it packages the library uncompressed, with `android:extractNativeLibs="false"`, the common modern default):
        - extracted: `/data/app/~~.../com.example-<suffix>/lib/<abi>/librasp.so`
        - embedded in a single APK: `/data/app/~~.../com.example-<suffix>/base.apk!/lib/<abi>/librasp.so`
        - embedded in an app bundle: `/data/app/~~.../com.example-<suffix>/split_config.arm64_v8a.apk!/lib/arm64-v8a/librasp.so` (bundletool names the ABI split with an underscore while the in-APK directory uses a hyphen)

        A third-party virtualizer (such as Parallel Space or VirtualApp) runs the guest app inside its own process and redirects its files, so the library loads from the host app's data directory instead, such as `/data/data/com.parallel.intl/.../com.example/lib/<abi>/librasp.so`. That path still contains the guest package as a subdirectory, so the tell is the owning directory, not a substring: `/data/app/.../<package>-<suffix>` on a genuine install, or the host's `/data/data/...` directory on a virtualized one.

        `id.uid` can't surface this because the process runs under the host's normal uid. A sophisticated virtualizer can fake the path, so this is a signal, not proof.
      - Versioned complete current signer sets, ordered single-signer rotation history, and supported Application package identity are documented in [Android signer observations](../docs/android-signer-observations.md). Legacy scalar outputs below retain first-signer semantics. schema 1, revision 5 introduced all nine identity outputs, preserved exactly in revision 7; generated cycle coverage retains errors as present observations.
      - `sig.cert_sha256`: the SHA-256 of the certificate of the key that signed the APK the app runs from, read two ways so the server can check they agree. The `apk_signing_block` source reads it from the APK file's own APK Signing Block, in native code a Java hook can't reach: the first certificate of the signer Android uses on the device, read as Android verifies the blocks, newest first. That is the first v3.1 or v3 signer whose range of API levels contains the device's API level, so after a key rotation it is the new key on the Android versions the v3.1 block covers and the old key on the versions below that range, or v2's first signer when no v3 signer applies.

        It is the digest `apksigner verify --print-certs` prints, the one Play Console shows for the app signing key, and the one Play Integrity returns in its `appIntegrity` verdict as `certificateSha256Digest` — an array of base64-encoded URL-safe digests, where this signal reports one hex digest. A repackaged app must be signed again, and the signing key never travels inside the APK, so in practice the re-signing key differs and the certificate changes even when nothing in it is hooked; a separate trusted backend/customer signing registry could compare the digest after that integration exists. Like the other identity probes, this is a signal, not proof: whoever holds the original signing key can reproduce the digest.

        The runtime does not verify the signature or current file integrity. Installation-time platform verification does not prove these file bytes are unchanged now. An APK signed only with the JAR scheme has no APK Signing Block, so the `apk_signing_block` source reports an error.

        The `package_manager` source reads the same digest a second way, through `PackageManager.getPackageInfo` with `GET_SIGNING_CERTIFICATES` (the app's own Context, reached with `ActivityThread.currentApplication`). The runtime's thread starts before Android creates the Application, so on the first pass this read waits for it, up to five seconds, on the runtime's own thread; an error from this source is then a failed read, not a normal cold start. An APK signed only with the JAR scheme splits the pair by design: `package_manager` reports the v1 signer's digest where `apk_signing_block` reports an error, so one source's error beside a digest is an expected state, not a hook tell.

        A tool that hooks the package manager to return the original certificate makes the two sources disagree, which the server sees. Because the read goes through Java, a Java hook can change it; because `apk_signing_block` reads the APK file in native code, a Java hook can't reach it but a redirected file read could fool it. Each source fails in the way the other doesn't, so a tool that hides the re-signing from one source leaves the other unchanged. Both pick the signer Android uses on the device, so on a rotated-key app they report the same key per Android version.
    - `integrity.h`: the integrity checks. They run on Android; off Android every observation has the unsupported status.
      - `integ.text_sha256`: the SHA-256 of librasp.so's own executable code (its `.text` section), read once from the installed file (the `file` source) and once from the process's memory (the `memory` source). The two are equal on a clean device and differ when the code was patched in memory, such as by a Frida hook that patches a check to always report a safe value. The runtime reports both and doesn't compare them. The library finds its own file and load address through the dynamic loader, so no path is built into the binary; when the app keeps its libraries uncompressed inside the APK, the file is read from the APK's zip entry.
    - `mitm.h`: the network-interception (man-in-the-middle, MITM) checks. `mitm.tunnels` and `mitm.user_cas` run on Android; the first reports the tunnel list and the second the user-installed authorities. Off Android every observation has the unsupported status.
      - `mitm.tunnels`: the network interfaces visible to the process whose name is `tun` or `tap` followed by a digit (such as `tun0` or `tap0`, the layer-3 and layer-2 interfaces of the kernel's TUN/TAP driver) — the interfaces a capture proxy routes traffic through, and the same `tun0` a legitimate VPN app opens; a name like the IPIP `tunl0` does not match. The names are read through `getifaddrs`, which an app process can call even though Android denies it `/proc/net/route`; the check reports each unique tunnel (at most 100), and a device with no tunnel reports an empty list.
      - `mitm.user_cas`: the file names of the user-installed CA certificate files in the user trust store (`/data/misc/user/<id>/cacerts-added`), where user-installed certificates are stored apart from the system authorities, so a proxy that decrypts TLS installs its root there. The directory is labeled `system_data_file` under SELinux, so it can't be listed; the runtime reads the names through JNI instead, from the aliases of the `AndroidCAStore` KeyStore, which needs no Context: a user authority's alias is `user:` followed by its file name. The check reports the names sorted, and an empty list when the user installed none.
    - `root.h`: the root checks. They run on Android; off Android every observation has the unsupported status.
      - `root.fs_paths`: which known root files exist, such as `su` and the Magisk, KernelSU and APatch files, read through access and stat.
      - `root.mounts`: the lines of `/proc/self/mounts` that a root tool made.
      - `root.rw_mounts`: the lines of `/proc/self/mounts` that mount a system folder writable.
      - `root.selinux_enforcing`: whether SELinux enforces its policy, read from `/sys/fs/selinux/enforce`.
      - `root.build_props`: the build properties that reveal a debuggable or test-signed build, or an unlocked bootloader.
  - `src/loader/`: the class loaders.
    - `GeneratingClassLoader.java`: the on-demand class loader. Its only logic is `findClass`, a native method.
    - `loader.cpp`: the native code of the loader. `JNI_OnLoad` binds the stub's native `install`, which makes the loader the parent of the app's base class loader. The loader's native `findClass` decrypts a dex file of the app the first time one of its classes is needed.
    - `loader_dex.h`: `loader_dex`, the dex of `GeneratingClassLoader.java`, which the build embeds in the library.
  - `src/payload/`: recovering the app's dex files, which the packer encrypted.
    - `cipher.h`: `decrypt`, which decrypts a frame of the packer's Android cipher: ChaCha20-Poly1305 (RFC 8439), from TF-PSA-Crypto. It refuses a frame whose tag doesn't match.
    - `dex_store.h`: `open_dex_store`, which reads and decrypts the class map from the app's APK, and `decrypt_dex`, which reads and decrypts the dex file that defines a class.
  - `src/util/logging.cpp`: the Android backend of `rasp::log`, which writes to the system log with `__android_log_write`.
  - `stub/`: `co/ostorlab/rasp/RaspStub.java`, the component factory the packer points the manifest at, and `build.sh`, which builds it into `stub.dex`.
- `tests/`: tests that run on a development machine, with GoogleTest. They use the same folders as the code.
  - `support/files.h`: `TemporaryDirectory`, a temporary folder removed with its contents, and `write_file`, which writes a file the tests then read.

## Build

CMake 4.4 or newer. The presets are in `CMakePresets.json`.

The host presets build with Clang from LLVM 23, the same release as `clang-format` and `clang-tidy`. Put its `bin` folder first in `PATH` (for example `/usr/lib/llvm-23/bin` from apt.llvm.org).

On a development machine, with the tests:

```
cd runtime
cmake --preset host
cmake --build --preset host
ctest --preset host
```

The same with AddressSanitizer, LeakSanitizer and UndefinedBehaviorSanitizer:

```
cd runtime
cmake --preset host-asan
cmake --build --preset host-asan
ctest --preset host-asan
```

The same with ThreadSanitizer, which finds data races. It cannot be combined with AddressSanitizer, so it has its own preset:

```
cd runtime
cmake --preset host-tsan
cmake --build --preset host-tsan
ctest --preset host-tsan
```

For an iOS device (arm64), on a Mac with Xcode:

```
cd runtime
cmake --preset ios
cmake --build --preset ios
```

The framework is written to `build/ios/ios/RaspRuntime.framework`. Its install name is `@rpath/RaspRuntime.framework/RaspRuntime`, which the packer adds to the app's load commands. The framework exports no symbols: the code runs from a constructor when the app loads it.

The framework supports iOS 12.0 and later. It doesn't use the libc++ that comes with iOS, which only supports iOS 15 and later. Instead it links a static libc++ built from LLVM 23.1.3 for the same minimum iOS version, with all its symbols hidden. That library is built once and committed under `third_party/libcxx/`, and `cmake/libcxx.cmake` checks its hash and links it. The build steps, the one-line source change it needs, and the CI job that proves the committed library matches the source are described in `third_party/libcxx/README.md`.

For an Android device (arm64-v8a), with the Android NDK, the Android SDK and a JDK. Set `ANDROID_NDK_HOME` to the NDK's folder and `ANDROID_HOME` to the SDK's folder first:

```
cd runtime
cmake --preset android
cmake --build --preset android
```

The library is written to `build/android/android/librasp.so`. The only symbol it exports is the JVM's `JNI_OnLoad` hook. The checks start from a load-time constructor, and `JNI_OnLoad` binds the stub's native method with `RegisterNatives`, so the library exports no `Java_...` symbol. A release build is also stripped (`-Wl,--strip-all`), so it carries no symbol table and no debug sections. Every other symbol, libc++ included, is hidden with `-Wl,--exclude-libs,ALL`. It links the NDK's static libc++ (`c++_static`). It supports Android 12 (API 31) and later.

The payload decryption uses ChaCha20-Poly1305 from TF-PSA-Crypto, the cryptography library of the Mbed TLS project, and some checks use its SHA-256. Its source is committed as an archive under `third_party/tf-psa-crypto/`, and `cmake/tf_psa_crypto.cmake` checks the archive's hash, extracts it and builds it as a static library, for Android, for iOS and for the builds with tests. Its symbols are hidden like every other one. Why it is built this way, its configuration, and the CI job that proves the archive is the official release are described in `third_party/tf-psa-crypto/README.md`.

The on-demand class loader, `android/src/loader/GeneratingClassLoader.java`, is Java, but the packer doesn't ship it as a dex of the app. When CMake configures the build, `cmake/loader_dex.cmake` compiles it with `javac` and the SDK's `d8`, and writes the dex as a byte array into a generated header, so the dex is embedded in `librasp.so`. It takes the newest platform's `android.jar` and the newest build-tools' `d8` from the SDK, which it finds through `ANDROID_HOME`, `ANDROID_SDK_ROOT` or `-DRASP_ANDROID_SDK=<folder>`, and `javac` from `JAVA_HOME` or `PATH`. The Android builds stop when one is missing. The builds with tests compile it the same way when they find all three, and leave out the test of the dex when they don't.

The stub is Java, not C++, so CMake doesn't build it. `android/stub/build.sh` compiles it with `javac` against the platform's `android.jar`, so the Java classes it uses are Android's, and converts it with `d8`. It takes two files from the Android SDK:

- `ANDROID_JAR` must be set to the `android.jar` of a platform at API 31 or newer, for example `$ANDROID_HOME/platforms/android-36/android.jar`.
- `d8` comes from the SDK's build-tools. It must be on `PATH`, or `D8` must be set to its path.

The script writes `stub.dex` to the folder given as its argument, or to `android/stub/` when there is none:

```
cd runtime
ANDROID_JAR="$ANDROID_HOME/platforms/android-36/android.jar" android/stub/build.sh <output folder>
```

The packer adds `stub.dex` as the app's last dex file, and `librasp.so` under `lib/<abi>/`.

Native builds also emit `<binary>.capabilities.json`, binding the built-in catalogue to the
exact pristine binary digest. Distribute it with the binary. From `runtime/`, stage native
artifacts at the package-resource paths before building the packer wheel:

```
cmake --install build/android --prefix <stage> --component runtime
cmake --install build/ios --prefix <stage> --component runtime
```

Use the platform build available on the host; the iOS build requires macOS/Xcode. Copy the
staged `rasp_packer/` resources into `packer/src/rasp_packer/`, including each sidecar, and add
the separately built Android stub. The packer validates pristine bytes before config insertion.
Missing metadata means legacy/unknown capabilities; invalid present metadata fails packing.
See [the capability contract](../docs/check-capabilities.md) for trust and backend limits.

## Logs

Only development builds write logs. A release build writes nothing to any log, so a protected app leaves no trace of the runtime in the device's log.

The `RASP_LOGGING` option turns logging on. CMake accepts it only in a Debug build (the build type is compared without case), and only with a single-configuration generator. It refuses every other build type, an empty build type, and multi-configuration generators such as Ninja Multi-Config. On iOS, the development build writes each line to the system log with `os_log`, and the `ios-dev` preset builds it:

```
cd runtime
cmake --preset ios-dev
cmake --build --preset ios-dev
```

The framework is written to `build/ios-dev/ios/RaspRuntime.framework`. Code writes a log line with `rasp::log` (`core/include/rasp/util/logging.h`), and only inside `if constexpr (rasp::kLoggingEnabled)`. In a release build, the compiler still checks the code in that block, but it generates no code for it, so neither the call nor its text is in the framework.

On Android, the development build writes each line to the system log with `__android_log_write`, with the tag `RaspRuntime`, and the `android-dev` preset builds it:

```
cd runtime
cmake --preset android-dev
cmake --build --preset android-dev
```

The library is written to `build/android-dev/android/librasp.so`.

## Format and check

The style is in `.clang-format` and the checks are in `.clang-tidy`.

```
cd runtime
git ls-files -z -- '*.h' '*.cpp' '*.mm' '*.h.in' | xargs -0 clang-format -i
cmake --preset host
run-clang-tidy -quiet -p build/host "^$PWD/(?!build/).*\.cpp$"
```

The host build does not compile the iOS adapters. On a Mac, check the development build too, including Objective-C++ `.mm` sources:

```
cmake --preset ios-dev
run-clang-tidy -quiet -p build/ios-dev "^$PWD/ios/src/.*\.(cpp|mm)$"
```

The Android code, from an Android build, with `ANDROID_NDK_HOME` set:

```
cmake --preset android
run-clang-tidy -quiet -p build/android "^$PWD/android/src/.*\.cpp$"
```

The release build leaves out `logging.cpp`, so check the development build too, the way CI does:

```
cmake --preset android-dev
run-clang-tidy -quiet -p build/android-dev "^$PWD/android/src/.*\.cpp$"
```

CI (`.github/workflows/runtime.yml`) runs:

- clang-format, and clang-tidy on the shared code and the tests (on Linux), the iOS code (on macOS) and the Android code (with the Android builds);
- the three host builds, the iOS release and development builds, and the Android release, development and stub builds.

On the release binaries, it checks that:

- the framework exports no symbols, and the Android library exports only the JVM's `JNI_OnLoad` hook;
- neither imports any of `exit`, `_Exit`, `quick_exit`, `signal`, `sigaction`, `sigprocmask`, `pthread_sigmask`, `setenv`, `putenv`, `unsetenv`, `setlocale` and `setrlimit`. `.clang-tidy` forbids these functions in the source, and also `abort` and `std::terminate`, which the binary check leaves out;
- neither writes logs: the framework imports no symbol with `_os_log` in its name and contains no `{public}` text, and the Android library imports no symbol with `__android_log` in its name and contains no `RaspRuntime` text.

See [the capability contract](../docs/check-capabilities.md) for release metadata validation.

## Independent second-source observations

See [second-source contracts](second_sources.md) for stable source names, error/unsupported semantics, bounds,
platform gates, test boundaries, and expected-source/assessment integration followups. Android `*_syscall` sources
use **libc's hookable syscall entry**, not direct inline assembly. Sources are retained independently, including
contradictory values and errors; agreement is not cryptographic attestation or proof of a clean device.

## Android source Context integration

Hosts can optionally supply their attached Application Context through `RuntimeBridge.initialize(Context)`.
See [integration, compile-only packaging, lifecycle and failure behavior](android/stub/README.md).
Binary-only apps retain existing best-effort measurements; a supported Context is not automatically available.

See [opt-in Android root and environment context](../docs/android-root-context.md) for fixed manager visibility queries, own mount context, public proxy metadata and unsupported developer-settings truth. Existing root/jailbreak refusal observations do not prove an intact stock platform.


Android API31+ hosts can opt in to [bounded Activity/window touch observations](../docs/android-window-observations.md) through RuntimeBridge after supported Context initialization.
