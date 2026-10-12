# Vendored Mbed TLS for Android

The Android runtime sends its reports to the ADR server over TLS that it does itself, inside `librasp.so`. It doesn't use Java's `HttpsURLConnection` or the system's TLS library, because an attacker can hook both easily, for example with Frida, and read or drop the reports. The TLS library is Mbed TLS, built from source with the NDK and linked statically into `librasp.so`. The host builds and iOS don't build it.

This directory holds the Mbed TLS source the build uses, the configuration the runtime builds it with, and the script that makes the source archive.

## What is here

- `mbedtls-3.6.7-source.tar.xz` — the Mbed TLS source. It holds `library/`, `include/` and `LICENSE` from the official 3.6.7 release, and nothing else. The Android build extracts it and builds it; see `runtime/cmake/mbedtls.cmake`.
- `mbedtls_config.h` — the configuration the runtime builds Mbed TLS with, in place of Mbed TLS's default one (explained below).
- `pack.sh` — makes the archive from the official release.

## Where it comes from

| | |
|---|---|
| Library | Mbed TLS 3.6.7, the 3.6 long-term support branch |
| Release archive | `https://github.com/Mbed-TLS/mbedtls/releases/download/mbedtls-3.6.7/mbedtls-3.6.7.tar.bz2` |
| SHA-256 of the release archive | `a7e8bcbec0e6f761b4af24f25677626b35f762f68eef79c08677a363212d11f6`, the value Mbed TLS publishes in the release notes and in `mbedtls-3.6.7-sha256sum.txt` |
| Licence | Apache-2.0 OR GPL-2.0-or-later, at our choice. We use it under Apache-2.0. The full text is the `LICENSE` file inside the archive. |

`pack.sh` downloads the release archive, checks its SHA-256, and keeps only the three paths the build needs. It writes the files sorted, with fixed owners, modes and timestamps, so it always produces the same archive, byte for byte. `cmake/mbedtls.cmake` checks the SHA-256 of the committed archive before it extracts it, so the build fails if the archive was changed.

The archive is committed, rather than downloaded at build time, so the Android build works from a clean checkout without network access. It is committed as one archive, rather than as source files, so the `format` and `tidy` CI jobs never read Mbed TLS's own code: they only look at the files git tracks, and the archive isn't a source file.

## How it is built

`cmake/mbedtls.cmake` runs only for Android. It extracts the archive into the build folder and adds Mbed TLS's own `library/CMakeLists.txt`, with `mbedtls_config.h` as `MBEDTLS_CONFIG_FILE`. That builds three static libraries: `rasp_mbedcrypto`, `rasp_mbedx509` and `rasp_mbedtls`. `librasp.so` links them, and `-Wl,--exclude-libs,ALL` hides every one of their symbols, as it does for libc++. The libraries are also built with hidden visibility.

## The configuration

`mbedtls_config.h` turns on only what the runtime's TLS client needs. Everything else is off, so it isn't in the binary.

- **TLS 1.2 and TLS 1.3, client only.** TLS 1.3 needs PSA crypto, so PSA crypto is on.
- **Key exchange:** ECDHE with X25519, P-256 and P-384.
- **Ciphers:** AES-GCM and ChaCha20-Poly1305.
- **Certificates:** X.509 parsing and verification, with the signatures a server chain uses: ECDSA on P-256 and P-384, and RSA with PKCS#1 v1.5 and PSS, with SHA-256, SHA-384 and SHA-512. TLS 1.3 needs RSA-PSS for any server with an RSA key, so `MBEDTLS_X509_RSASSA_PSS_SUPPORT` is on.
- **Record sizes:** `MBEDTLS_SSL_IN_CONTENT_LEN` is 16384, the largest record a server may send when no smaller size was negotiated. `MBEDTLS_SSL_OUT_CONTENT_LEN` is 4096. The runtime's requests are small, and a longer one is split into several records.
- **Randomness:** Mbed TLS's own entropy source, which seeds PSA crypto's random generator. Mbed TLS calls the `getrandom` system call only on glibc. On Android it reads a device file instead, and `MBEDTLS_PLATFORM_DEV_RANDOM` sets it to `/dev/urandom`. Since 3.6.6, Mbed TLS's default is `/dev/random`, which can block for a long time on Linux kernels older than 5.6, and many Android 8 to 10 devices run such kernels. `/dev/urandom` never blocks. It is only weak right after the kernel boots, and an app always starts long after Android has seeded it. libc's `getrandom` wrapper only exists from API 28, and the minimum is API 26, so the runtime doesn't call it.
- **Off:** the server side, session tickets, renegotiation, file system access, the `net_sockets` module (the runtime has its own socket code), PEM and base64 (the trust anchors are built in as DER), debug output, and the legacy cipher layer.
- **No text that names the library.** `MBEDTLS_ERROR_C`, `MBEDTLS_VERSION_C` and `MBEDTLS_VERSION_FEATURES` stay off, and `MBEDTLS_X509_REMOVE_INFO` is on. The error strings, the version string and the certificate descriptions would tell an attacker which library to hook. What remains are the cipher suite names, such as `TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256`, which Mbed TLS keeps in its cipher suite table and has no option to remove, and the labels of the TLS 1.3 key schedule, which the protocol itself defines.

Mbed TLS checks the configuration when it compiles (`check_config.h`). If you turn an option on or off, build `android` and `android-dev` to see that every option still has what it depends on.

## Updating

To move to a newer 3.6 release:

1. In `pack.sh`, change `mbedtls_version`, and set `mbedtls_sha256` to the SHA-256 that Mbed TLS publishes for the new `.tar.bz2`. Take it from the release notes, not from your own download.
2. Run the script on Linux, with curl, GNU tar, bzip2 and xz on the PATH. It writes the new archive next to itself. Delete the old archive.
3. In `runtime/cmake/mbedtls.cmake`, change `RASP_MBEDTLS_VERSION`, and set `RASP_MBEDTLS_SHA256` to the SHA-256 of the new archive (`sha256sum mbedtls-<version>-source.tar.xz`).
4. Read the release's changelog for configuration changes, then build `android` and `android-dev`.

```
runtime/third_party/mbedtls/pack.sh
```

## How CI checks it

`.github/workflows/mbedtls.yml` runs `pack.sh` and compares the files of the archive it makes with the files of the committed archive. If they differ, the committed archive wasn't made from the official release, and the job fails. This way the archive in git is always provably the official Mbed TLS source, cut down to the three paths the build needs.
