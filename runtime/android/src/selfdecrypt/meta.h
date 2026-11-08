/// The plaintext metadata the packer writes into librasp.so and the load-time self-decrypt bootstrap reads. It is never
/// encrypted, so the bootstrap can find every encrypted region and the material it needs to derive the content key. It
/// carries no key: the ChaCha20 key is derived at load (see selfdecrypt.cpp), never stored.

#pragma once

#include <cstdint>

namespace rasp::android::selfdecrypt {

/// The largest number of encrypted regions the bootstrap can carry.
inline constexpr std::uint32_t kMaxRegions = 64;

/// One encrypted region: a contiguous byte range of an encrypted section that the packer encrypted and the bootstrap
/// decrypts at load.
struct Region {
  /// Link-time virtual address of the region start.
  std::uint32_t vaddr;
  /// Region length in bytes.
  std::uint32_t size;
  /// 1 when the region is code (restore read+exec and flush the i-cache); 0 for read-only data (restore read).
  std::uint32_t is_code;
  /// Padding that keeps the 16-byte nonce 4-byte aligned and the struct tidy.
  std::uint32_t reserved;
  /// ChaCha20 counter and nonce for this region, distinct per region.
  std::uint8_t nonce[16];
};

/// The metadata the packer fills in post-build. There is no key field: the content key is derived at load from the
/// per-build input keying material (the ikmN words, kept as separate scattered fields rather than one contiguous blob)
/// and a SHA-256 self-hash over the clear .stubcode bytes. The ikmN words live here in .packmeta, outside the hashed
/// .stubcode range, so writing them never perturbs the self-hash.
struct Meta {
  /// 0 when freshly built, 1 after the packer encrypts the library.
  std::uint32_t packed;
  /// IKM word 0 (bytes 0..3 of the HKDF input keying material).
  std::uint32_t ikm0;
  /// Number of valid entries in regions.
  std::uint32_t region_count;
  /// IKM word 1 (bytes 4..7).
  std::uint32_t ikm1;
  /// Link-time vaddr of this struct; the bootstrap uses it to compute the load bias.
  std::uint32_t meta_vaddr;
  /// IKM word 2 (bytes 8..11).
  std::uint32_t ikm2;
  /// Link-time vaddr of the clear .stubcode section (for the self-hash).
  std::uint32_t stubcode_vaddr;
  /// IKM word 3 (bytes 12..15).
  std::uint32_t ikm3;
  /// Byte length of the clear .stubcode section (for the self-hash).
  std::uint32_t stubcode_size;
  /// IKM word 4 (bytes 16..19).
  std::uint32_t ikm4;
  /// IKM word 5 (bytes 20..23).
  std::uint32_t ikm5;
  /// Padding kept between scattered IKM fields.
  std::uint32_t reserved0;
  /// IKM word 6 (bytes 24..27).
  std::uint32_t ikm6;
  /// IKM word 7 (bytes 28..31).
  std::uint32_t ikm7;
  /// The encrypted regions.
  Region regions[kMaxRegions];
};

/// The metadata, in its own plaintext .packmeta section; the packer fills it in post-build.
extern volatile Meta g_meta;

}  // namespace rasp::android::selfdecrypt
