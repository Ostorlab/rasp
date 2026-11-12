# Private runtime storage

Plugins compiled with the runtime's toolchain call `acquire_private_storage` on a worker thread to obtain an owned private queue directory and its matching stable install identity. This additive API is independent of plugin initialization and measurement cycles:

```cpp
std::expected<rasp::PrivateStorage, rasp::StorageError> rasp::acquire_private_storage();
```

**`PrivateStorage`** is a move-only owner of a validated directory descriptor and canonical nonzero lowercase UUID text.

- `native_handle()` borrows the descriptor; consumers must not close it.
- `install_id()` borrows the identity owned by the same capability.
- `close()` releases the descriptor and reports failure. Destruction releases it as a fallback without asserting durability.
- Retain the owner and identity beside queued metadata and payload. Use descriptor-relative operations with bounded regular-file validation; no pathname is a security capability.
- Future transports must pair this queue with its provider identity, rather than a possibly unavailable legacy startup `Config.install_id`.

Call only on a worker thread: acquisition performs bounded JNI/platform calls and filesystem operations. It creates no threads, restarts no monitoring, repeats no plugin initialization, and changes no Config, plugin ABI, existing cycle snapshot, catalogue row or observation mailbox.

The provider never waits for a lock. Contention returns `kBusy`; consumers retry later with bounded backoff. An unavailable early call is not cached, so a later call after supported Application attachment can succeed. Kernel I/O has no hard wall-clock deadline.

## How does the provider select and prove ownership of the directory?

Android uses only the retained public Application supplied through RuntimeBridge, `getNoBackupFilesDir()` and public `java.io.File` APIs. It uses no ActivityThread lookup, process-name/package inference, temporary/shared folder or fallback.

The Application's directory selects the Android user/work profile and storage domain. Only Application Context is retained; a device-protected component Context does not override it. Credential-protected storage may remain inaccessible until unlock. Global process aliases do not change directory selection. Shared UIDs cannot be distinguished by Unix ownership; this capability does not attest identity or defend against code already running as the same UID.

iOS uses a Foundation Application Support URL, creates the fixed private child, applies protection and excludes the child from backup before returning a queue capability. Failed backup exclusion is unavailable; protected-data errors can be retried after unlock. No environment mutation or main-thread-owned global state is used, and the deployment floor remains iOS 12.

Standard sandbox Application Support is the same physical parent as the legacy HOME plus `/Library/Application Support` route, so an existing valid identity there is retained in place. The provider never reads or migrates a custom/overridden legacy HOME. If that startup route selected another parent, its identity can differ; transport must pair the provider identity with its own queue.

The fixed queue directory is `rasp_private`, mode 0700, immediately below the verified platform parent. Identity stays as `rasp_install_id` in that parent, with the existing `rasp_install_id.lock`. Nothing is copied from a guessed path. Android's legacy startup identity may be absent or refer to a process-name-derived location. On iOS the identity must also be excluded from backups before success; queue backup exclusion precedes consumer writes.

The POSIX path checks enforce these preconditions:

1. Directory components are pinned with close-on-exec and no-follow opens. Final-directory and app-controlled intermediate symlinks are rejected.
2. Platform canonicalization may resolve an OS ancestor alias only when both link and parent have privileged platform owners (root/system on Android, root on iOS/macOS), neither is app-owned, and the parent forbids group/other write. Alias inode stability is checked; original and canonical directory descriptors must identify the same inode. This admits real `/data/user/0` and `/var` aliases without admitting mutable app symlinks.
3. Android ancestors use search-only `O_PATH` descriptors, permitting execute-only platform directories; final owned directories use readable descriptors. Darwin uses `O_SEARCH` on iOS 18+/macOS 15+, with readable-directory traversal on older supported versions. An older OS denying ancestor read access returns unavailable.
4. The parent belongs to the effective app UID, permits owner rwx and forbids other write. Group write is allowed only when its GID equals both effective UID and effective GID, covering Android's app-owned 0771 parent. Ordinary sandbox 0755 parents are allowed; the child is rechecked for exact 0700.
5. Regular files require the same UID, mode 0600 and one link. Only a validated canonical nonzero same-parent/same-UID/single-link legacy 0644 identity is hardened in place under lock, followed by inode-stability and metadata-fsync checks. Unknown modes, extra links, nonregular objects and oversized contents fail.

Identity publication preserves competing files:

- Take the nonblocking private cross-process flock and read the identity again under lock.
- When absent, obtain secure random bytes, write a private exclusive temporary file, fsync it and publish with `linkat(temp, identity)` without replacement.
- Remove only the owned temporary inode, and sync file metadata and parent. `EEXIST` preserves competing bytes/inode and returns retryable busy.
- A crash between link and unlink leaves two links. Recovery under the same lock accepts only two verified names of the identical owned canonical identity inode, removes the temporary name and syncs before normal validation. It never removes or replaces an identity name.

Failures never return a zero, guessed or nondurable new identity. Consumers must not unlink the lock or identity names. Corrupt, oversized, noncanonical or zero identities return `kInvalidIdentity` without rotation. Recovery requires deliberate operator/app-owned removal while no consumer holds a queue; the queue must be handled under its original identity. Unsafe objects are never removed as recovery. The old `.tmp` name is not copied or trusted; the writer owns only `rasp_install_id.private.tmp`.

The source-compatible legacy `load_or_create_install_id(directory)` shares this lock and writer. It retries only `kBusy`, with at most 11 attempts and ten 5 ms sleeps: at most 50 ms of requested retry delay during startup. Scheduler delays and filesystem I/O can take longer. Other failures return immediately, and persistent contention still returns `nullopt`; this does not eliminate unavailable legacy identities. The durable provider remains nonblocking.

Entropy comes from `getentropy` on Android/Linux and public Security `SecRandomCopyBytes` on Apple platforms. Failure returns `kRandomUnavailable`, with no predictable fallback. The Apple path supports the existing deployment floor without private or unavailable kernel headers.

`StorageError` distinguishes `kUnavailable`, `kBusy`, `kInvalidDirectory`, `kUnsafeFile`, `kInvalidIdentity`, `kIoError`, `kRandomUnavailable` and `kBackupExclusionFailed`. These capability states are not malware observations. No secret store, encryption or cryptographic attestation is provided.

## How is the storage contract reviewed and validated?

Config, plugin ABI and identity routing remain separate contracts. Native fixtures exercise actual filesystems, concurrent exec processes and syscall-boundary failures. Real-JVM fixtures replace Android services at the Java boundary. Apple CI fixtures exercise the actual iOS adapter with isolated Foundation-selected roots and real backup resource APIs; macOS substitutes data protection at the OS boundary.

The legacy contention regressions use a separately exec'd native lock owner. They cover release within the retry budget, persistent contention without identity replacement, nonbusy failures without retry, descriptor cleanup and a single nonblocking durable-provider attempt. These fixtures do not establish physical-device behavior. macOS/iOS compilation and protected-data/backup behavior still require platform CI and device validation.

## How do compiled-in plugins use the API?

Plugins built with the runtime's own toolchain call `acquire_private_storage` on the worker thread and retain the owner beside their queued snapshots:

```cpp
#include "rasp/private_storage.h"

// On the existing worker/callback thread; retain this owner alongside the queued snapshot.
auto storage = rasp::acquire_private_storage();
if (!storage.has_value()) {
  // Keep pending metadata/payload bounded and retry according to the capability result.
  return;
}
const int queue_directory = storage->native_handle();
const std::string identity(storage->install_id());
// Use openat/fstatat and bounded validated regular files under queue_directory.
// Keep identity with each durable envelope and its transport.
```

This source API requires the runtime's toolchain/libc++; it is not an exported C++ ABI for Apple's system libc++ or another SDK. The build-only consumer selected with `RASP_PLUGINS=tests/plugins/private_storage` checks actual header/symbol linkage in Android and iOS development builds. No plugin gains an observation row, and storage availability implies no malware verdict.

Platform references: [AOSP no-backup directory implementation](https://android.googlesource.com/platform/frameworks/base/+/master/core/java/android/app/ContextImpl.java), [Apple Application Support URL API](https://developer.apple.com/documentation/foundation/filemanager/url(for:in:appropriatefor:create:)), [Apple backup resource key](https://developer.apple.com/documentation/foundation/urlresourcekey/isexcludedfrombackupkey) and [Darwin O_SEARCH definition](https://github.com/apple-oss-distributions/xnu/blob/xnu-11215.1.10/bsd/sys/fcntl.h). These references do not replace platform/device validation.
