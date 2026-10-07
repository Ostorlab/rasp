#ifndef RASP_SECURESTORE_H
#define RASP_SECURESTORE_H

#include <stddef.h>
#include <stdint.h>

/* SecureStore: authenticated local data-at-rest under white-box AES (design §8).
 *
 * Encrypts sensitive data with a white-box AES-128 key (see wbaes.h), so on devices with no hardware keystore
 * the data key is not a contiguous literal in the binary. The sealed blob is framed as
 *   nonce(12) || ciphertext(len) || tag(16)
 * where `tag` is AES-CMAC over `nonce || ciphertext` (encrypt-then-MAC, CTR + CMAC under the one embedded
 * key, in the spirit of CCM). `open` verifies the tag in constant time before decrypting, so any change to
 * the nonce or ciphertext is rejected. The caller supplies a fresh random `nonce` per `seal` (never reuse a
 * nonce with the same key — CTR keystream reuse is catastrophic).
 *
 * SCOPE: confidentiality + integrity. Remaining (see the repo TODO §8): key wipe-on-critical, and the plain
 * white-box tables still do not hide the key (see wbaes.h).
 *
 * PRECONDITIONS: `out` must not overlap `plain`/`sealed`. Confidentiality holds only while the plaintext
 * stays under the CTR length bound in wbaes.h (2^32 blocks per nonce). */

#define RASP_SECURESTORE_NONCE_LEN 12
#define RASP_SECURESTORE_TAG_LEN 16
#define RASP_SECURESTORE_OVERHEAD (RASP_SECURESTORE_NONCE_LEN + RASP_SECURESTORE_TAG_LEN)

/* Seals `len` plaintext bytes. `out` must hold `len + RASP_SECURESTORE_OVERHEAD` bytes. Returns bytes
 * written, or -1 on bad arguments. */
int rasp_secure_store_seal(const uint32_t *type2, const uint8_t *last,
                           const uint8_t nonce[RASP_SECURESTORE_NONCE_LEN], const uint8_t *plain,
                           size_t len, uint8_t *out);

/* Opens a sealed blob (nonce||ciphertext||tag) after verifying the tag. `out` must hold
 * `sealed_len - RASP_SECURESTORE_OVERHEAD` bytes. Returns the plaintext length, or -1 if the blob is too
 * small or the integrity tag does not match (nothing is written to `out` on a tag failure). */
int rasp_secure_store_open(const uint32_t *type2, const uint8_t *last, const uint8_t *sealed,
                           size_t sealed_len, uint8_t *out);

#endif
