/// The TF-PSA-Crypto configuration of the runtime: ChaCha20-Poly1305 for the Android payload, SHA-256 for the iOS
/// cdhash and code hash, what PSA crypto needs to start, and the library's own locking, so several threads can decrypt
/// at once. The build passes it to TF-PSA-Crypto as TF_PSA_CRYPTO_CONFIG_FILE, in place of its default configuration.
/// See README.md next to it.

#pragma once

#define PSA_WANT_ALG_CHACHA20_POLY1305 1
#define PSA_WANT_KEY_TYPE_CHACHA20 1

#define MBEDTLS_PSA_CRYPTO_C

#define PSA_WANT_ALG_SHA_256 1
#define MBEDTLS_MD_C
#define MBEDTLS_HMAC_DRBG_C
#define MBEDTLS_PSA_BUILTIN_GET_ENTROPY
#define MBEDTLS_PLATFORM_DEV_RANDOM "/dev/urandom"

#define MBEDTLS_THREADING_C
#define MBEDTLS_THREADING_PTHREAD
