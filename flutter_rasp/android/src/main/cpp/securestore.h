#ifndef RASP_SECURESTORE_H
#define RASP_SECURESTORE_H

#include <stddef.h>
#include <stdint.h>

/* SecureStore: local data-at-rest confidentiality under white-box AES (design §8).
 *
 * Encrypts sensitive data with a white-box AES-128 key (see wbaes.h) in CTR mode, so on devices with no
 * hardware keystore the data key is not a contiguous literal in the binary. The sealed blob is framed as
 *   nonce(12) || ciphertext(len)
 * so `open` is self-describing. The caller supplies a fresh random `nonce` per `seal` (never reuse a nonce
 * with the same key — CTR keystream reuse is catastrophic).
 *
 * SCOPE: this first slice is confidentiality only. There is no integrity tag yet, so a sealed blob is
 * malleable; an AEAD/AES-CMAC tag and key wipe-on-critical are the next step (see the repo TODO §8). And the
 * plain white-box tables do not yet hide the key (see wbaes.h).
 *
 * PRECONDITIONS: `out` must not overlap `plain`/`sealed` (seal writes the nonce over the first bytes of `out`
 * before encrypting, so in-place operation would corrupt the data). Confidentiality holds only while the
 * plaintext stays under the CTR length bound in wbaes.h (2^32 blocks per nonce). */

#define RASP_SECURESTORE_NONCE_LEN 12
#define RASP_SECURESTORE_OVERHEAD RASP_SECURESTORE_NONCE_LEN

/* Seals `len` plaintext bytes. `out` must hold `len + RASP_SECURESTORE_OVERHEAD` bytes. Returns bytes
 * written, or -1 on bad arguments. */
int rasp_secure_store_seal(const uint32_t *type2, const uint8_t *last,
                           const uint8_t nonce[RASP_SECURESTORE_NONCE_LEN], const uint8_t *plain,
                           size_t len, uint8_t *out);

/* Opens a sealed blob (nonce||ciphertext). `out` must hold `sealed_len - RASP_SECURESTORE_OVERHEAD` bytes.
 * Returns the plaintext length, or -1 if `sealed_len` is too small. */
int rasp_secure_store_open(const uint32_t *type2, const uint8_t *last, const uint8_t *sealed,
                           size_t sealed_len, uint8_t *out);

#endif
