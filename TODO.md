# To do

Work that is known and not done yet. Each item says what is missing and why it matters.

- Add an item when you find work that doesn't belong in the current pull request.
- Remove the item in the pull request that does the work.
- Link the pull request or issue when there is one.

## Runtime: all platforms

- **A lost batch hides a change.** Each batch is sent once, and after the first batch of a session, a batch holds only the observations that changed. When a batch doesn't reach the server, the server doesn't learn of the changes it held until those observations change again, which may not happen for the rest of the session.
- **The runtime is not obfuscated.** The release binaries are easy to read, and they show what each check looks at: the paths the checks look for, the signal names and the server host are plain strings that `strings` lists, and the path list tells a bypass tool exactly which paths to hide. Encoding the strings is one example of this work.

## Runtime: iOS

- **The sandbox probe likely misses iOS 15 and later.** `jb.sandbox_escape` creates `/private/.rasp_sandbox_probe`. Since iOS 15 the system volume is sealed and read-only, and `/private` is on it, so the write is likely refused with `EROFS` whether or not the sandbox is in force, and the probe reports `false` on jailbroken devices too. To confirm on a jailbroken device.
- **The fork probe counts every failure as a refusal.** `jb.fork_ok` reports `false` for any `fork()` failure, including errors the sandbox doesn't explain, such as `EAGAIN` or `ENOMEM`. `jb.sandbox_escape` reports those as an error.
- **The packer accepts apps below the runtime's minimum iOS version.** The runtime supports iOS 12.0 and later, and the packer packs apps that declare an older minimum. On those older devices the runtime would fail to load.

## Packer: Android

- **The packer doesn't take Android App Bundles (AAB), only APKs.** Since August 2021, Google Play requires new apps to be published as AABs, so a customer who publishes on Google Play builds an AAB, not an APK, and has nothing the packer can protect.
