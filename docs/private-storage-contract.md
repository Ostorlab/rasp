# Private runtime storage (RT11 / PL03 contract)

The additive `rasp/private_storage.h` API is independent of plugin initialization and measurement cycles:

```cpp
std::expected<rasp::PrivateStorage, rasp::StorageError> rasp::acquire_private_storage();
```

`PrivateStorage` is move-constructible, noncopyable and owns a directory descriptor. `native_handle()` borrows that descriptor; consumers must not close it. `install_id()` borrows the owned canonical nonzero lowercase UUID text. `close()` explicitly releases the descriptor and reports close failure; destruction releases it as a fallback without asserting durability. Consumers retain the handle/identity with queued metadata and payload. They use descriptor-relative operations and their own bounded regular-file validation; no pathname is exposed as a security capability. Future transports must use this identity with this queue, rather than the possibly unavailable legacy startup `Config.install_id`.

Call only on a worker thread: this performs bounded JNI/platform calls and filesystem operations. It creates no threads, does not restart monitoring or repeat plugin init, and does not mutate Config, plugin ABI, existing cycle snapshots, catalogue rows or observation mailboxes. It performs no lock waiting: contention returns `kBusy` and consumers retry later with bounded backoff. Kernel I/O itself has no hard wall-clock deadline. An unavailable early call is not cached: a later call after supported Application attachment can succeed.

## Ownership and identity

Android obtains only the retained public Application supplied through the existing RuntimeBridge and calls `getNoBackupFilesDir()` and public `java.io.File` APIs. No ActivityThread, process-name/package inference, temporary folder, shared folder or fallback is used. The returned directory selects the Android user/work profile and storage domain. Only Application Context is retained; a device-protected component Context does not override it. Credential-protected storage may remain inaccessible until unlock. Global process aliases do not change the selected directory. Shared UIDs cannot be distinguished by Unix ownership; this capability is not an attestation or a defense against code already running as the same UID.

iOS obtains the sandbox's Application Support URL from supported Foundation APIs, creates the fixed private child, sets protection and excludes that child from backup before returning a queue capability. Failure to exclude is unavailable. Protected-data errors can be retried after unlock. No environment mutation or main-thread-owned global state is used. iOS 12 is the deployment floor. Standard sandbox Application Support is the same physical parent used by the legacy HOME + `/Library/Application Support` route, and a valid identity there is retained in place. The new provider never reads or migrates a custom/overridden legacy HOME: if that old startup route selected another parent, the provider identity can differ, and future transport must pair the provider identity with its own queue.

The fixed queue directory is `rasp_private`, mode 0700, immediately below the verified platform directory. Identity remains `rasp_install_id` in that same verified platform parent, preserving an existing valid legacy identity **in place**, with the existing `rasp_install_id.lock`. Nothing is copied from a guessed old path. Android legacy startup identity may be absent or refer to a process-name-derived location; consumers must use the provider identity. On iOS the identity file must also be excluded from backups before success. The queue child's backup exclusion precedes any consumer writes.

The POSIX implementation pins directory components with close-on-exec and no-follow opens. It rejects final-directory and app-controlled intermediate symlinks. Public platform canonicalization may resolve an OS ancestor alias only when both the link and its parent have privileged platform owners (root/system on Android, root on iOS/macOS), neither is app-owned, and the parent has no group/other write permission. It checks alias inode stability and proves the original and canonical directory descriptors refer to the same inode. This covers real `/data/user/0` and `/var` aliases without accepting mutable app symlinks. Android ancestors use search-only O_PATH descriptors to support execute-only platform directories; final owned directories use readable descriptors. Darwin uses O_SEARCH on iOS18+/macOS15+ and a readable-directory fallback on older supported versions; an older OS denying ancestor read access returns unavailable rather than weakening traversal checks.

The verified parent must belong to the effective app UID, permit owner rwx and forbid other write. Group write is accepted only when the directory GID equals both effective UID and effective GID, supporting Android's app-owned 0771 parent; ordinary sandbox 0755 parents are permitted. The child is rechecked for exact0700 before exposure. Regular files require same UID, mode0600 and one link; only a validated canonical nonzero same-parent/sameUID/single-link legacy0644 identity may be hardened in place under the lock. Inode stability and metadata fsync are rechecked after hardening. Unknown/malicious modes, extra links, nonregular objects and oversized contents fail explicitly. Identity creation takes a nonblocking private cross-process flock, reads again under lock, obtains secure random bytes, writes a private exclusive temporary file, fsyncs it, atomically publishes with portable `linkat(temp, identity)` without replacement, removes only its owned temporary inode and fsyncs both file metadata and parent. EEXIST preserves the competing identity's bytes/inode and returns retryable busy. A crash between link and unlink leaves two links: recovery under the same private lock accepts only two verified names of the identical owned canonical identity inode, unlinks the temporary name, and fsyncs before normal validation. No recovery path removes/replaces an identity name. Failures never return a zero, guessed or nondurable new identity. Lock and existing identity names must not be unlinked by consumers.

Corrupt, oversized, noncanonical or zero identities fail explicitly with `kInvalidIdentity`; they are not automatically rotated. Recovery requires deliberate operator/app-owned removal while no consumer holds a queue; the existing queue must be handled under its original identity. Unsafe objects are never removed as recovery. `load_or_create_install_id(directory)` keeps its source signature and now shares this same nonblocking lock/writer. Its observable hardening is deliberate: corrupt/zero/noncanonical values and contention return nullopt instead of automatic rotation or waiting. The old `.tmp` name is neither copied nor trusted; the new writer owns only `rasp_install_id.private.tmp`.

`StorageError` distinguishes absent platform capability (`kUnavailable`), contention (`kBusy`), invalid ownership/path (`kInvalidDirectory`), unsafe files (`kUnsafeFile`), invalid identity (`kInvalidIdentity`), filesystem failure (`kIoError`), secure random failure (`kRandomUnavailable`), and iOS backup exclusion failure (`kBackupExclusionFailed`). These are capability states, not malware observations. No secret store, encryption or cryptographic attestation is provided.

## Review and validation

This interface is frozen early for PL03 consumer review; Config/Plugin ABI or identity-routing changes require root coordination. Exact evidence, platform limitations and final parent integration are tracked in `/tmp/mega-adr/reports/rt11.md`. Native fixtures use actual filesystems, concurrent exec processes and syscall-boundary failures. Real-JVM fixtures replace Android services at the Java boundary. Apple CI fixtures execute the actual iOS adapter against isolated Foundation-selected temporary roots and real backup resource APIs, with iOS data protection substituted at the OS boundary on macOS. None constitutes physical-device evidence. macOS/iOS compilation and real protected-data/backup behavior require platform CI/device validation.


## Compiled-in plugin usage

```cpp
#include "rasp/private_storage.h"

// On the existing worker/callback thread; retain this owner alongside the queued snapshot.
auto storage = rasp::acquire_private_storage();
if (!storage.has_value()) {
  // Retain pending metadata/payload in bounded memory and retry according to the capability result.
  return;
}
const int queue_directory = storage->native_handle();
const std::string identity(storage->install_id());
// Use queue_directory with openat/fstatat and bounded validated regular files.
// Keep identity with each durable envelope and use it for that envelope's transport.
```

This is a source API for plugins compiled with the runtime's own toolchain/libc++; it is not a new exported C++ ABI for code using Apple's system libc++ or a different SDK. A build-only plugin fixture explicitly selected through RASP_PLUGINS verifies actual header/symbol linkage. No plugin gains a new observation row and no malware verdict is inferred from storage availability.


Platform API references: [AOSP public no-backup directory implementation](https://android.googlesource.com/platform/frameworks/base/+/master/core/java/android/app/ContextImpl.java), [Apple Application Support URL API](https://developer.apple.com/documentation/foundation/filemanager/url(for:in:appropriatefor:create:)), [Apple backup resource key](https://developer.apple.com/documentation/foundation/urlresourcekey/isexcludedfrombackupkey), and [Darwin O_SEARCH flag definition](https://github.com/apple-oss-distributions/xnu/blob/xnu-11215.1.10/bsd/sys/fcntl.h). These API references do not substitute for platform/device validation.
