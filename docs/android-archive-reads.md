# Android APK archive read limits

The native runtime reads APK signing blocks and stored payload entries through
bounded `pread` calls. It never maps mutable APK bytes. Truncation between file
metadata checks and a read therefore produces a read failure rather than a
mapped-file SIGBUS in these readers.

## Files and metadata

Paths must be nonempty, contain no embedded NUL and fit within 4,096 bytes.
Symlinks to regular files remain supported; directories, FIFOs, devices and
other nonregular objects are refused before content reads. Archives must be
single-disk ZIP32 files between 22 and 2,147,483,647 bytes inclusive. ZIP64 is
unsupported, including ZIP64 sentinels and extra fields on payload entries.

One descriptor is used for each operation. The resolved path and descriptor
must agree before and after reads on device, inode, mode, size, mtime and ctime,
including nanoseconds. Read-only opens use `O_NONBLOCK | O_CLOEXEC`. A short
read, EOF, EINTR, failed metadata check or failed close discards the result;
partial reads are never accepted. Close is not retried.

These checks do not establish an immutable snapshot or trusted authenticity.
Timestamp granularity, same-UID mutation and inode replacement followed by
restoration can evade endpoint comparisons. They provide no APK signature,
certificate-chain or lineage verification and no general process crash-isolation
guarantee.

## Payload limits

Every production payload caller supplies an explicit limit before allocation:

| Payload | Maximum plaintext bytes | Maximum stored bytes |
| --- | ---: | ---: |
| Raw key | 32, exactly | 32, exactly |
| UTF-8 class map | 8,388,608 | 8,388,636 |
| One business DEX | 67,108,864 | 67,108,892 |

Encrypted frames contain a 12-byte nonce, plaintext-length ciphertext and a
16-byte Poly1305 tag. An authenticated empty map remains supported. Existing
map parsing still skips unusable lines and lets the first occurrence of a
class select its DEX. The generating loader's DEX is embedded in the native
library, so it requires no APK entry read.

The map and DEX caps are **operational compatibility limits**, not DEX or ZIP
format maxima. Both public APK and AAB packing reject oversized split DEX bytes
or UTF-8 map bytes before encryption and output publication. A maximum-size DEX
frame and plaintext require about 128 MiB together, plus existing runtime and
class-index memory. This is a per-call bound, not a global concurrency budget.

## ZIP payload validation

Stored-entry reads accept at most 16 MiB of central-directory metadata and
65,534 entries. The whole bounded directory is checked before the target is
accepted. Names must be canonical and unique, without traversal, file/directory
aliases or symbolic-link entries. Normal unrelated deflated entries are allowed;
the selected target must be stored and unencrypted, with no data descriptor or
unsupported flags. The UTF-8 name flag is supported.

The target's local and central names, flags, CRC fields and stored/uncompressed
sizes must agree. All offsets and lengths must fit before the directory.
Local and central extra fields may differ: the actual APK writer pads local
extras with raw zero bytes for alignment, including one to three trailing bytes.
Ordinary framed extras are supported; malformed extras and ZIP64 extras fail.
CRC field agreement is a structural check, not cryptographic verification.
Payload decryption still uses real ChaCha20-Poly1305 authentication.

Only the tail (at most 65,557 bytes), directory, selected local header/name/extra
and caller-bounded payload are read. The directory and its name index are
released before copying the payload. No full-APK allocation is needed.

The directory cap is another operational limit. It is not applied to certificate
collection, which reads only the bounded tail and signing block. External AAB
conversion/signing tools determine installed APK split metadata; a valid packed
AAB cannot guarantee that those later APKs remain within runtime metadata limits.

## Certificate selection and validation

Both descriptor certificate readers cap the entire signing block at 1 MiB and
copy certificates of at most 64 KiB. The legacy scalar reader retains its first
applicable signer, first certificate and older fallback policy. Complete-set
selection remains separate, with all raw count/byte bounds applied before
normalization. See the [signer observation contract](android-signer-observations.md)
for exact scheme selection, AOSP references and error semantics.

## Reproducible checks

From `runtime/`, using the documented host toolchain:

```sh
cmake --preset host
cmake --build --preset host --parallel 2
ctest --preset host --parallel 2 --output-on-failure -R 'Archive|DexStore'
```

Portable tests cover malformed ZIP metadata, local padding compatibility,
symlink policy and exact/over-limit sparse payloads. On Linux, an additional
subprocess suite injects faults at libc filesystem boundaries, including
truncation before every production region read, mutation, inode replacement,
short reads, EINTR, nanosecond metadata changes and close failure. It changes
no production parser and installs no signal handler.

The host integration driver can compare native payload decryption against a
real public-packer application's expected DEX:

```sh
build/host/tests/rasp_android_archive_probe protected.apk binary.class.Name expected.dex
```

It reads the real key and encrypted map, performs class lookup and decrypts the
selected business DEX through the production readers and PSA implementation.
Host execution is not evidence of physical ART, device or signing efficacy.
