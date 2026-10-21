# To do

Work that is known and not done yet. Each item says what is missing and why it matters.

- Add an item when you find work that doesn't belong in the current pull request.
- Remove the item in the pull request that does the work.
- Link the pull request or issue when there is one.

## Runtime: all platforms

- **The runtime is not obfuscated.** The release binaries are easy to read, and they show what each check looks at: the paths the checks look for and the signal names are plain strings that `strings` lists, and the path list tells a bypass tool exactly which paths to hide. Encoding the strings is one example of this work.

## Runtime: iOS

- **The sandbox probe likely misses iOS 15 and later.** `jb.sandbox_escape` creates `/private/.rasp_sandbox_probe`. Since iOS 15 the system volume is sealed and read-only, and `/private` is on it, so the write is likely refused with `EROFS` whether or not the sandbox is in force, and the probe reports `false` on jailbroken devices too. To confirm on a jailbroken device.
- **The fork probe counts every failure as a refusal.** `jb.fork_ok` reports `false` for any `fork()` failure, including errors the sandbox doesn't explain, such as `EAGAIN` or `ENOMEM`. `jb.sandbox_escape` reports those as an error.
- **The packer accepts apps below the runtime's minimum iOS version.** The runtime supports iOS 12.0 and later, and the packer packs apps that declare an older minimum. On those older devices the runtime would fail to load.

## Runtime: Android

- **Observations aren't sent to the server.** The checks run when the app starts, and only a development build logs what they observe. Android has no transport, install id or monitoring thread yet, so in a release build the root checks run and nobody sees the result.
- **The checks run once, before the app's code.** `raspStart` runs them on the app's main thread before it decrypts the app, so they must stay fast, and a device rooted after launch isn't seen. Running them again on our own thread belongs with the reporting work.
- **The `/data/adb` paths are never reported.** `root.fs_paths` looks for the Magisk, KernelSU and APatch folders under `/data/adb`. That folder is `drwx------ root`, so `access` and `stat` fail with permission denied on rooted and stock devices alike, and those paths are never reported. Seen on an Android 14 emulator rooted with Magisk v30.7: `/data/adb/magisk`, `magisk.db` and `modules` exist, and the adb shell user can't reach them; an app has fewer rights still. They stay in the list for devices where a root tool loosened the folder's permissions.
- **The SELinux probe may report an error on every device, and misses modern root.** Recent Android versions may forbid apps to read `/sys/fs/selinux/enforce`, and `root.selinux_enforcing` then reports an error on every device. The adb shell user could read it on Android 14 and 17 emulators; whether an app can is not yet confirmed. Even when it can be read, Magisk, KernelSU and APatch keep SELinux enforcing, so the probe only catches older ways of rooting and permissive custom ROMs.
- **Root hiding defeats these checks.** Magisk's DenyList and Shamiko unmount the root tool's files and mounts for the app, and `resetprop` changes the build properties. The checks catch a device that doesn't hide its root. Catching one that does needs probes the hiding doesn't cover, such as the app's own memory map and threads.
- **Installed root apps aren't checked.** An installed root manager, an app that needs root, or a root-hiding app is a strong signal. RootBeer, an open-source Android root-detection library, lists their package names in its `Const.java`, and KernelSU (`me.weishu.kernelsu`) and HideMyApplist (`com.tsng.hidemyapplist`) belong on that list too. Looking them up needs `PackageManager` through JNI. Since Android 11, an app only sees the packages its manifest declares in `<queries>`, so the packer would have to add them. Magisk can also reinstall its app under a random package name.

## Packer: Android

- **The packer doesn't take Android App Bundles (AAB), only APKs.** Since August 2021, Google Play requires new apps to be published as AABs, so a customer who publishes on Google Play builds an AAB, not an APK, and has nothing the packer can protect.
- **The payload key is in clear text in the protected APK.** `assets/rasp/config.json` holds, as a hex string, the key that decrypts `assets/rasp/payload.bin`. Anyone who unzips the APK can decrypt the app's code without running it. The same key also makes the payload's authentication tag, so they can also replace the app's code with their own and give it a valid tag.
