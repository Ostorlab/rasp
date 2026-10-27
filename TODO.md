# To do

Work that is known and not done yet. Each item says what is missing and why it matters.

- Add an item when you find work that doesn't belong in the current pull request.
- Remove the item in the pull request that does the work.
- Link the pull request or issue when there is one.

## Runtime: all platforms

- **`run_plugins` also gives the plugins the observations.** Running the plugins' checks and handing out the observations are one function today, so the plugins' `on_observations` is called from `run_plugins`. The runtime should have its own `on_observations` step, and call the plugins' `on_observations` after its own built-in handling.
- **The Android and iOS monitoring code is duplicated.** Both `monitoring.cpp` files start the thread, run the checks and the plugins every 60 seconds and log the observations, with the same code. The monitoring should be one shared implementation, and each platform should only provide its built-in checks.
- **The runtime is not obfuscated.** The release binaries are easy to read, and they show what each check looks at: the paths the checks look for and the signal names are plain strings that `strings` lists, and the path list tells a bypass tool exactly which paths to hide. Encoding the strings is one example of this work.

## Runtime: iOS

- **The sandbox probe likely misses iOS 15 and later.** `jb.sandbox_escape` creates `/private/.rasp_sandbox_probe`. Since iOS 15 the system volume is sealed and read-only, and `/private` is on it, so the write is likely refused with `EROFS` whether or not the sandbox is in force, and the probe reports `false` on jailbroken devices too. To confirm on a jailbroken device.
- **The traced probe can be lied to.** `dbg.traced` reads the `P_TRACED` flag through the libc `sysctl` function. A hook on `sysctl`, a common debugger bypass, can clear the flag before the probe sees it. Making the same request through a direct system call as a second source, as `jb.fs_paths` reads paths through both `access` and `stat`, would make a hook on libc show as two values that disagree.
- **The parent probe can be lied to.** `dbg.parent` reads the parent's process id through the libc `getppid` function. A hook on `getppid` can return 1, the id of `launchd`, while a debugger started the app. Reading the same id from the process's own `kinfo_proc` entry through sysctl, as a second source, would make a hook on `getppid` show as two values that disagree.
- **The exception-port probe can be lied to.** `dbg.exception_ports` asks for the ports through the `task_get_exception_ports` function of `libsystem_kernel`. A hook on that function can report no ports while a debugger has set them. Sending the same request as a Mach message through the `mach_msg` trap directly, as a second source, would make a hook on the library function show as two values that disagree.
- **The packer accepts apps below the runtime's minimum iOS version.** The runtime supports iOS 12.0 and later, and the packer packs apps that declare an older minimum. On those older devices the runtime would fail to load.

## Runtime: Android

- **Observations aren't sent to the server.** The checks run when the app starts, and only a development build logs what they observe. Android has no transport, install id or monitoring thread yet, so in a release build the root checks run and nobody sees the result.
- **The `/data/adb` paths are never reported.** `root.fs_paths` looks for the Magisk, KernelSU and APatch folders under `/data/adb`. That folder is `drwx------ root`, so `access` and `stat` fail with permission denied on rooted and stock devices alike, and those paths are never reported. Seen on an Android 14 emulator rooted with Magisk v30.7: `/data/adb/magisk`, `magisk.db` and `modules` exist, and the adb shell user can't reach them; an app has fewer rights still. They stay in the list for devices where a root tool loosened the folder's permissions.
- **The SELinux probe may report an error on every device, and misses modern root.** Recent Android versions may forbid apps to read `/sys/fs/selinux/enforce`, and `root.selinux_enforcing` then reports an error on every device. The adb shell user could read it on Android 14 and 17 emulators; whether an app can is not yet confirmed. Even when it can be read, Magisk, KernelSU and APatch keep SELinux enforcing, so the probe only catches older ways of rooting and permissive custom ROMs.
- **Root hiding defeats these checks.** Magisk's DenyList and Shamiko unmount the root tool's files and mounts for the app, and `resetprop` changes the build properties. The checks catch a device that doesn't hide its root. Catching one that does needs probes the hiding doesn't cover, such as the app's own memory map and threads.
- **A Java debugger isn't seen.** `dbg.tracer_pid` sees native debuggers, which attach with ptrace. A Java debugger, such as Android Studio's default one, attaches through JDWP without ptrace, and `TracerPid` stays 0. The runtime contract's `dbg.java_debugger` needs `android.os.Debug.isDebuggerConnected` through JNI.
- **The tracer probe can be lied to.** A hook on `fopen` or `read`, or a kernel patch, can hide the `TracerPid` value. Reading the file through a direct system call as a second source, as `root.fs_paths` reads paths through both `access` and `stat`, would make a hook on libc show as two values that disagree.
- **`id.debuggable` has a single source.** It reads `ApplicationInfo.flags`, which a Java hook can change before the stub reads it. The kernel's dumpable flag (`prctl(PR_GET_DUMPABLE)`) would make a second source: zygote makes a debuggable app dumpable. It likely makes every app dumpable on a debug build of Android too, so what it means on each kind of device is to confirm on an emulator first.
- **Installed root apps aren't checked.** An installed root manager, an app that needs root, or a root-hiding app is a strong signal. RootBeer, an open-source Android root-detection library, lists their package names in its `Const.java`, and KernelSU (`me.weishu.kernelsu`) and HideMyApplist (`com.tsng.hidemyapplist`) belong on that list too. Looking them up needs `PackageManager` through JNI. Since Android 11, an app only sees the packages its manifest declares in `<queries>`, so the packer would have to add them. Magisk can also reinstall its app under a random package name.

## Packer: Android

- **One key encrypts the class map and every business dex.** Recovering that key opens all of them. Each should have its own key.
- **The packer doesn't take Android App Bundles (AAB), only APKs.** Since August 2021, Google Play requires new apps to be published as AABs, so a customer who publishes on Google Play builds an AAB, not an APK, and has nothing the packer can protect.
- **The payload key is in clear text in the protected APK.** `assets/rasp/config.json` holds, as a hex string, the key that decrypts `assets/rasp/payload.bin`. Anyone who unzips the APK can decrypt the app's code without running it. The same key also makes the payload's authentication tag, so they can also replace the app's code with their own and give it a valid tag.
