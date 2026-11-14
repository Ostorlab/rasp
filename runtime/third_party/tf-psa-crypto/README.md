# Vendored TF-PSA-Crypto

The packer encrypts the app's own dex files with ChaCha20-Poly1305, as RFC 8439 defines it, and the Android runtime decrypts them in `librasp.so`. The runtime takes ChaCha20-Poly1305 from TF-PSA-Crypto, the cryptography library of the Mbed TLS project, built from source and linked statically into `librasp.so`. It also takes HKDF-SHA-256 from it, for the payload's key schedule, and SHA-256, for the integrity check on Android and the app-identity check on iOS, so the iOS build links it into `RaspRuntime.framework` too. The host builds that run the tests build it too, because the tests of the payload decryption run on a development machine.

Since Mbed TLS 4, the Mbed TLS project ships its cryptography as TF-PSA-Crypto, a library of its own, with the PSA Crypto API. Its 1.1 branch is a long-term support branch, which gets security fixes until March 2029.

This directory holds the TF-PSA-Crypto source the build uses, the configuration the runtime builds it with, and the script that makes the source archive.

## What is here

- `tf-psa-crypto-1.1.1-source.tar.xz` — the TF-PSA-Crypto source. It holds what the build reads from the official 1.1.1 release, the paths `pack.sh` lists, and nothing else: the library sources, the headers, the CMake files they use, and `LICENSE`. The build extracts it and builds it; see `runtime/cmake/tf_psa_crypto.cmake`.
- `crypto_config.h` — the configuration the runtime builds TF-PSA-Crypto with, in place of its default one (explained below).
- `pack.sh` — makes the archive from the official release.

## Where it comes from

| | |
|---|---|
| Library | TF-PSA-Crypto 1.1.1, the 1.1 long-term support branch |
| Release archive | `https://github.com/Mbed-TLS/TF-PSA-Crypto/releases/download/tf-psa-crypto-1.1.1/tf-psa-crypto-1.1.1.tar.bz2` |
| SHA-256 of the release archive | `3236f70e827fa693ae9e97499957a80c6dba25395d4617b7d21ecb60c82a480e`, the value TF-PSA-Crypto publishes in the release notes |
| Licence | Apache-2.0 OR GPL-2.0-or-later, at our choice. We use it under Apache-2.0. The full text is the `LICENSE` file inside the archive. |

`pack.sh` downloads the release archive, checks its SHA-256, and keeps only the paths the build needs. It writes the files sorted, with fixed owners, modes and timestamps, so it always produces the same archive, byte for byte. `cmake/tf_psa_crypto.cmake` checks the SHA-256 of the committed archive before it extracts it, so the build fails if the archive was changed.

The archive is committed, rather than downloaded at build time, so the build works from a clean checkout without network access, and always compiles the exact code that was reviewed. It is committed as one archive, rather than as source files, so the `format` and `tidy` CI jobs never read TF-PSA-Crypto's own code: they only look at the files git tracks, and the archive isn't a source file.

## How it is built

`cmake/tf_psa_crypto.cmake` runs for Android, for iOS and for the builds with tests. It extracts the archive into the build folder and adds TF-PSA-Crypto's own `CMakeLists.txt`, with `crypto_config.h` as `TF_PSA_CRYPTO_CONFIG_FILE`. TF-PSA-Crypto's programs and tests are off, and its compiler warnings are not errors: the warnings are about code we don't own, and a newer compiler must not break our build over them. That builds one static library, `rasp_tfpsacrypto`. `librasp.so` and `RaspRuntime.framework` link it. In `librasp.so`, `-Wl,--exclude-libs,ALL` hides every one of its symbols, as it does for libc++. The library is also built with hidden visibility.

## The configuration

`crypto_config.h` turns on only what the runtime needs: the payload decryption, HKDF-SHA-256 and SHA-256. Everything else is off, so it isn't in the binary.

- **ChaCha20-Poly1305:** the payload's algorithm, and its key type. No other cipher, no public-key cryptography and no key storage is on.
- **HKDF-SHA-256:** the payload key schedule derives its keys with `psa_key_derivation_*`. `PSA_WANT_ALG_HKDF` enables HKDF and pulls in HMAC and its key type through the library's dependency rules.
- **SHA-256:** the hash of the integrity check on Android and of the app-identity check on iOS, computed with `psa_hash_compute`.
- **PSA crypto:** the runtime decrypts with `psa_aead_decrypt`, from the PSA Crypto API. Before any PSA call, `psa_crypto_init` starts PSA's random generator, even though decrypting needs no randomness. So the configuration has a random generator: HMAC_DRBG over SHA-256 (`MBEDTLS_HMAC_DRBG_C`, `MBEDTLS_MD_C` and SHA-256). CTR_DRBG, the other choice, would add AES.
- **Randomness:** TF-PSA-Crypto's own entropy source (`MBEDTLS_PSA_BUILTIN_GET_ENTROPY`). It calls the `getrandom` system call only on glibc. On Android it reads a device file instead, and `MBEDTLS_PLATFORM_DEV_RANDOM` sets it to `/dev/urandom`. TF-PSA-Crypto's default is `/dev/random`, which can block for a long time on Linux kernels older than 5.6, and many Android 8 to 10 devices run such kernels. `/dev/urandom` never blocks. It is only weak right after the kernel boots, and an app always starts long after Android has seeded it.
- **No text that names the library.** The version functions (`TF_PSA_CRYPTO_VERSION`) stay off, so the version string isn't in the binary to tell an attacker which library to hook.
- **Threading:** `MBEDTLS_THREADING_C`, with the pthread mutexes of `MBEDTLS_THREADING_PTHREAD`. The dex store decrypts each dex on whichever thread first asks for it, so two threads can decrypt at the same time. Every decryption imports the key into PSA's key store and removes it afterwards, and that store is global. TF-PSA-Crypto's own documentation says that without `MBEDTLS_THREADING_C` the PSA subsystem is not thread-safe, and two decryptions at once can then corrupt each other or fail. With it, the library locks its key store and its start-up itself. Its global mutexes are set up statically (`PTHREAD_MUTEX_INITIALIZER`), so nothing extra runs when `librasp.so` loads.

TF-PSA-Crypto checks the configuration when it compiles. If you turn an option on or off, build `host`, `android` and `android-dev` to see that every option still has what it depends on.

## Updating

To move to a newer 1.1 release:

1. In `pack.sh`, change `tf_psa_crypto_version`, and set `tf_psa_crypto_sha256` to the SHA-256 that TF-PSA-Crypto publishes for the new `.tar.bz2`. Take it from the release notes, not from your own download.
2. Run the script on Linux, with curl, GNU tar, bzip2 and xz on the PATH. It writes the new archive next to itself. Delete the old archive.
3. In `runtime/cmake/tf_psa_crypto.cmake`, change `RASP_TF_PSA_CRYPTO_VERSION`, and set `RASP_TF_PSA_CRYPTO_SHA256` to the SHA-256 of the new archive (`sha256sum tf-psa-crypto-<version>-source.tar.xz`). In `.github/workflows/tf-psa-crypto.yml`, change the archive name.
4. Read the release's changelog for configuration changes, then build `host`, `android` and `android-dev`, and run the host tests.

```
runtime/third_party/tf-psa-crypto/pack.sh
```

## How CI checks it

`.github/workflows/tf-psa-crypto.yml` runs `pack.sh` and compares the files of the archive it makes with the files of the committed archive. If they differ, the committed archive wasn't made from the official release, and the job fails. This way the archive in git is always provably the official TF-PSA-Crypto source, cut down to the paths the build needs.
