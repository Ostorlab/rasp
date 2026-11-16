/// Tests for the self-decrypt bootstrap, run end to end on the development machine. Each test encrypts a code page and
/// a data page the way the packer encrypts the library, writes the metadata the packer writes, and runs the
/// bootstrap's DT_INIT entry over them, with the key-derivation blob gen_kdf_shovel.py made for this machine. The key
/// it must derive is computed with TF-PSA-Crypto's HKDF, which is checked against a vector the packer's `cryptography`
/// HKDF made.

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <dlfcn.h>
#include <gtest/gtest.h>
#include <optional>
#include <psa/crypto.h>
#include <string>
#include <string_view>
#include <sys/mman.h>
#include <unistd.h>
#include <vector>

#include "selfdecrypt/chacha20.h"
#include "selfdecrypt/meta.h"

extern "C" void rasp_self_decrypt_init();

namespace rasp::android::selfdecrypt {
namespace {

/// A 32-byte key or digest.
using Bytes32 = std::array<std::uint8_t, 32>;

/// The value of the lowercase hex digit `c`.
[[nodiscard]] std::uint32_t nibble(char c) {
  if (c >= '0' && c <= '9') {
    return static_cast<std::uint32_t>(c - '0');
  }
  return static_cast<std::uint32_t>(c - 'a' + 10);
}

/// The 32 bytes that the 64 lowercase hex digits in `hex` stand for.
[[nodiscard]] Bytes32 bytes32_from_hex(std::string_view hex) {
  Bytes32 bytes{};
  for (std::size_t i = 0; i < bytes.size(); ++i) {
    bytes[i] = static_cast<std::uint8_t>((nibble(hex[2 * i]) << 4U) | nibble(hex[(2 * i) + 1]));
  }
  return bytes;
}

/// The number of `.stubcode` bytes the key derivation salts with.
constexpr std::size_t kStubSize = 64;

/// The bytes standing in for the clear `.stubcode`: byte i is (13 * i + 5) mod 256.
[[nodiscard]] std::array<std::uint8_t, kStubSize> stub_bytes() {
  std::array<std::uint8_t, kStubSize> stub{};
  for (std::size_t i = 0; i < stub.size(); ++i) {
    stub[i] = static_cast<std::uint8_t>(((i * 13) + 5) & 0xFFU);
  }
  return stub;
}

/// The input keying material the metadata carries: the bytes 40 to 5f.
[[nodiscard]] Bytes32 ikm_bytes() {
  Bytes32 ikm{};
  for (std::size_t i = 0; i < ikm.size(); ++i) {
    ikm[i] = static_cast<std::uint8_t>(0x40 + i);
  }
  return ikm;
}

/// What the packer's `cryptography` HKDF-SHA256 derives from ikm_bytes(), with SHA-256 of stub_bytes() as the salt, no
/// info and a 32-byte output: the content key the bootstrap must derive.
constexpr std::string_view kPackerContentKey = "75f7860c1c95968a60f8e86ca10da6b1b2072b8deedb5444e16e765be8084446";

/// The counter and nonce of the code region: a counter of 0, as the packer writes it, then 12 nonce bytes.
constexpr std::array<std::uint8_t, 16> kCodeNonce{0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};

/// The counter and nonce of the data region.
constexpr std::array<std::uint8_t, 16> kDataNonce{0, 0, 0, 0, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32};

#if defined(__x86_64__)
/// `mov eax, 42; ret`: a function that returns 42.
constexpr std::array<std::uint8_t, 6> kReturns42{0xb8, 0x2a, 0x00, 0x00, 0x00, 0xc3};
/// The byte of kReturns42 that holds the immediate's low bits, and the bit that turns 42 into 43.
constexpr std::size_t kImmediateByte = 1;
/// The bit of kImmediateByte that turns 42 into 43.
constexpr std::uint8_t kImmediateBit = 0x01;
/// The byte that fills the rest of the code page: int3.
constexpr std::uint8_t kTrapByte = 0xcc;
#elif defined(__aarch64__)
/// `mov w0, #42; ret`: a function that returns 42.
constexpr std::array<std::uint8_t, 8> kReturns42{0x40, 0x05, 0x80, 0x52, 0xc0, 0x03, 0x5f, 0xd6};
/// The byte of kReturns42 that holds the immediate's low bits.
constexpr std::size_t kImmediateByte = 0;
/// The bit of kImmediateByte that turns 42 into 43.
constexpr std::uint8_t kImmediateBit = 0x20;
/// The byte that fills the rest of the code page: zeros, a permanently undefined instruction.
constexpr std::uint8_t kTrapByte = 0x00;
#endif

/// SHA-256 of `bytes`, with TF-PSA-Crypto.
[[nodiscard]] Bytes32 sha256(const std::uint8_t* bytes, std::size_t size) {
  Bytes32 digest{};
  std::size_t length = 0;
  EXPECT_EQ(psa_hash_compute(PSA_ALG_SHA_256, bytes, size, digest.data(), digest.size(), &length), PSA_SUCCESS);
  return digest;
}

/// HKDF-SHA256 of `ikm` with SHA-256 of `stub` as the salt, no info and a 32-byte output, with TF-PSA-Crypto: the
/// derivation the bootstrap's blob runs.
[[nodiscard]] Bytes32 reference_content_key(const std::array<std::uint8_t, kStubSize>& stub, const Bytes32& ikm) {
  const Bytes32 salt = sha256(stub.data(), stub.size());
  psa_key_derivation_operation_t operation = psa_key_derivation_operation_init();
  EXPECT_EQ(psa_key_derivation_setup(&operation, PSA_ALG_HKDF(PSA_ALG_SHA_256)), PSA_SUCCESS);
  EXPECT_EQ(psa_key_derivation_input_bytes(&operation, PSA_KEY_DERIVATION_INPUT_SALT, salt.data(), salt.size()),
            PSA_SUCCESS);
  EXPECT_EQ(psa_key_derivation_input_bytes(&operation, PSA_KEY_DERIVATION_INPUT_SECRET, ikm.data(), ikm.size()),
            PSA_SUCCESS);
  EXPECT_EQ(psa_key_derivation_input_bytes(&operation, PSA_KEY_DERIVATION_INPUT_INFO, nullptr, 0), PSA_SUCCESS);
  Bytes32 key{};
  EXPECT_EQ(psa_key_derivation_output_bytes(&operation, key.data(), key.size()), PSA_SUCCESS);
  psa_key_derivation_abort(&operation);
  return key;
}

/// The four little-endian bytes at `bytes` as a word.
[[nodiscard]] std::uint32_t word_at(const std::uint8_t* bytes) {
  return static_cast<std::uint32_t>(bytes[0]) | (static_cast<std::uint32_t>(bytes[1]) << 8U) |
         (static_cast<std::uint32_t>(bytes[2]) << 16U) | (static_cast<std::uint32_t>(bytes[3]) << 24U);
}

/// The permissions /proc/self/maps lists for the mapping that starts at `page`, such as "r-xp", or nothing when no
/// mapping starts there.
[[nodiscard]] std::optional<std::string> permissions_of(const void* page) {
  std::FILE* maps = std::fopen("/proc/self/maps", "r");
  if (maps == nullptr) {
    return std::nullopt;
  }
  std::array<char, 512> line{};
  std::optional<std::string> found;
  while (std::fgets(line.data(), static_cast<int>(line.size()), maps) != nullptr) {
    unsigned long start = 0;
    unsigned long end = 0;
    std::array<char, 5> permissions{};
    // NOLINTNEXTLINE(cert-err34-c): the maps format is fixed and the fields are checked by the match count.
    if (std::sscanf(line.data(), "%lx-%lx %4s", &start, &end, permissions.data()) == 3 &&
        start == reinterpret_cast<std::uintptr_t>(page)) {
      found = std::string(permissions.data());
      break;
    }
  }
  std::fclose(maps);
  return found;
}

/// Three pages the test maps within 4 GiB above the test binary, where the metadata's 32-bit addresses reach: the
/// stand-in `.stubcode`, the code region and the data region. Unmapped when the object goes away.
class Pages {
 public:
  /// Maps the pages above `floor`, or maps nothing when no free place within 4 GiB of it is found.
  ///
  /// @param floor The address the pages must be above.
  explicit Pages(std::uintptr_t floor) : size_(static_cast<std::size_t>(sysconf(_SC_PAGESIZE))) {
    for (std::uintptr_t offset = std::uintptr_t{1} << 30U; offset < (std::uintptr_t{3} << 30U);
         offset += std::uintptr_t{1} << 28U) {
      const std::uintptr_t hint = (floor + offset) & ~(static_cast<std::uintptr_t>(size_) - 1);
      // NOLINTNEXTLINE(performance-no-int-to-ptr): the hint is an address in the test's own address space.
      void* mapped = mmap(reinterpret_cast<void*>(hint), 3 * size_, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
      if (mapped != MAP_FAILED) {
        base_ = static_cast<std::uint8_t*>(mapped);
        return;
      }
    }
  }

  Pages(const Pages&) = delete;
  Pages& operator=(const Pages&) = delete;
  Pages(Pages&&) = delete;
  Pages& operator=(Pages&&) = delete;

  ~Pages() {
    if (base_ != nullptr) {
      munmap(base_, 3 * size_);
    }
  }

  /// Whether the pages could be mapped.
  [[nodiscard]] bool mapped() const { return base_ != nullptr; }
  /// The size of one page.
  [[nodiscard]] std::size_t size() const { return size_; }
  /// The stand-in `.stubcode` page.
  [[nodiscard]] std::uint8_t* stub() const { return base_; }
  /// The code region's page.
  [[nodiscard]] std::uint8_t* code() const { return base_ + size_; }
  /// The data region's page.
  [[nodiscard]] std::uint8_t* data() const { return base_ + (2 * size_); }

 private:
  /// The size of one page.
  std::size_t size_;
  /// The first of the three pages, or null when they could not be mapped.
  std::uint8_t* base_ = nullptr;
};

/// The address of the bootstrap's metadata.
[[nodiscard]] std::uintptr_t meta_address() {
  return reinterpret_cast<std::uintptr_t>(const_cast<const Meta*>(&g_meta));
}

/// The load base of the test binary, where its ELF header is: the base the bootstrap's load-base gate accepts.
[[nodiscard]] std::uintptr_t binary_base() {
  Dl_info info{};
  if (dladdr(reinterpret_cast<const void*>(meta_address()), &info) == 0) {
    return 0;
  }
  return reinterpret_cast<std::uintptr_t>(info.dli_fbase);
}

/// The plaintext of the data region: byte i is (5 * i + 1) mod 256, a whole page.
[[nodiscard]] std::vector<std::uint8_t> data_plaintext(std::size_t size) {
  std::vector<std::uint8_t> bytes(size);
  for (std::size_t i = 0; i < bytes.size(); ++i) {
    bytes[i] = static_cast<std::uint8_t>(((i * 5) + 1) & 0xFFU);
  }
  return bytes;
}

/// Encrypts the pages the way the packer encrypts the library, under `key`, and writes the metadata the packer
/// writes, with `bias` as the load bias the bootstrap computes.
///
/// @param pages The pages to encrypt; their contents are replaced.
/// @param bias The load bias the metadata's addresses are relative to.
/// @param key The content key to encrypt with.
void pack(const Pages& pages, std::uintptr_t bias, const Bytes32& key) {
  const std::array<std::uint8_t, kStubSize> stub = stub_bytes();
  std::memcpy(pages.stub(), stub.data(), stub.size());

  std::memset(pages.code(), kTrapByte, pages.size());
  std::memcpy(pages.code(), kReturns42.data(), kReturns42.size());
  const Bytes32 text_digest = sha256(pages.code(), pages.size());
  chacha20_xor(pages.code(), pages.size(), key.data(), kCodeNonce.data());

  const std::vector<std::uint8_t> data = data_plaintext(pages.size());
  std::memcpy(pages.data(), data.data(), data.size());
  chacha20_xor(pages.data(), pages.size(), key.data(), kDataNonce.data());

  const Bytes32 ikm = ikm_bytes();
  const auto offset = [bias](const std::uint8_t* address) {
    return static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(address) - bias);
  };
  g_meta.meta_vaddr = static_cast<std::uint32_t>(meta_address() - bias);
  g_meta.ikm0 = word_at(&ikm[0]);
  g_meta.ikm1 = word_at(&ikm[4]);
  g_meta.ikm2 = word_at(&ikm[8]);
  g_meta.ikm3 = word_at(&ikm[12]);
  g_meta.ikm4 = word_at(&ikm[16]);
  g_meta.ikm5 = word_at(&ikm[20]);
  g_meta.ikm6 = word_at(&ikm[24]);
  g_meta.ikm7 = word_at(&ikm[28]);
  g_meta.stubcode_vaddr = offset(pages.stub());
  g_meta.stubcode_size = static_cast<std::uint32_t>(kStubSize);
  g_meta.text_vaddr = offset(pages.code());
  g_meta.text_size = static_cast<std::uint32_t>(pages.size());
  for (std::size_t i = 0; i < text_digest.size(); ++i) {
    g_meta.text_digest[i] = text_digest[i];
  }
  g_meta.region_count = 2;
  g_meta.regions[0].vaddr = offset(pages.code());
  g_meta.regions[0].size = static_cast<std::uint32_t>(pages.size());
  g_meta.regions[0].is_code = 1;
  g_meta.regions[1].vaddr = offset(pages.data());
  g_meta.regions[1].size = static_cast<std::uint32_t>(pages.size());
  g_meta.regions[1].is_code = 0;
  for (std::size_t i = 0; i < kCodeNonce.size(); ++i) {
    g_meta.regions[0].nonce[i] = kCodeNonce[i];
    g_meta.regions[1].nonce[i] = kDataNonce[i];
  }
  g_meta.packed = 1;
}

/// Calls the function at the start of the code page.
///
/// @param pages The pages whose code page to call into.
/// @return What the function returned.
[[nodiscard]] int call_code(const Pages& pages) {
  using Function = int (*)();
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): the page holds the machine code the test packed.
  const auto function = reinterpret_cast<Function>(pages.code());
  return function();
}

/// The test fixture: TF-PSA-Crypto started, the pages mapped above the test binary, and the metadata cleared after
/// each test, so the next one starts from an unpacked library.
class SelfDecryptTest : public ::testing::Test {
 protected:
  void SetUp() override {
    ASSERT_EQ(psa_crypto_init(), PSA_SUCCESS);
    ASSERT_NE(base_, 0U);
    if (!pages_.mapped()) {
      GTEST_SKIP() << "no free pages within 4 GiB above the test binary";
    }
  }

  void TearDown() override { g_meta.packed = 0; }

  /// The pages the test packs.
  [[nodiscard]] const Pages& pages() const { return pages_; }
  /// The test binary's load base.
  [[nodiscard]] std::uintptr_t base() const { return base_; }

 private:
  /// The test binary's load base.
  std::uintptr_t base_ = binary_base();
  /// The pages the test packs.
  Pages pages_{binary_base()};
};

TEST(ContentKey, referenceKey_whenGivenThePackersInputs_matchesThePackersKey) {
  ASSERT_EQ(psa_crypto_init(), PSA_SUCCESS);

  EXPECT_EQ(reference_content_key(stub_bytes(), ikm_bytes()), bytes32_from_hex(kPackerContentKey));
}

TEST_F(SelfDecryptTest, selfDecrypt_whenTheLibraryIsIntact_runsTheDecryptedCode) {
  pack(pages(), base(), reference_content_key(stub_bytes(), ikm_bytes()));

  rasp_self_decrypt_init();

  EXPECT_EQ(permissions_of(pages().code()), "r-xp");
  EXPECT_EQ(call_code(pages()), 42);
}

TEST_F(SelfDecryptTest, selfDecrypt_whenTheLibraryIsIntact_decryptsItsData) {
  pack(pages(), base(), reference_content_key(stub_bytes(), ikm_bytes()));

  rasp_self_decrypt_init();

  const std::vector<std::uint8_t> expected = data_plaintext(pages().size());
  EXPECT_EQ(std::memcmp(pages().data(), expected.data(), expected.size()), 0);
  EXPECT_EQ(permissions_of(pages().data()), "r--p");
}

TEST_F(SelfDecryptTest, selfDecrypt_whenTheCiphertextIsPatchedIntoOtherValidCode_leavesTheCodeWithNoAccess) {
  pack(pages(), base(), reference_content_key(stub_bytes(), ikm_bytes()));
  pages().code()[kImmediateByte] = static_cast<std::uint8_t>(pages().code()[kImmediateByte] ^ kImmediateBit);

  rasp_self_decrypt_init();

  EXPECT_EQ(permissions_of(pages().code()), "---p");
}

TEST_F(SelfDecryptTest, selfDecrypt_whenTheCiphertextIsPatchedIntoOtherValidCode_neverRunsIt) {
  GTEST_FLAG_SET(death_test_style, "threadsafe");
  pack(pages(), base(), reference_content_key(stub_bytes(), ikm_bytes()));
  pages().code()[kImmediateByte] = static_cast<std::uint8_t>(pages().code()[kImmediateByte] ^ kImmediateBit);

  rasp_self_decrypt_init();

  EXPECT_DEATH(static_cast<void>(call_code(pages())), "");
}

TEST_F(SelfDecryptTest, selfDecrypt_whenTheTextDigestDoesNotMatch_leavesTheCodeWithNoAccess) {
  pack(pages(), base(), reference_content_key(stub_bytes(), ikm_bytes()));
  g_meta.text_digest[0] = static_cast<std::uint8_t>(g_meta.text_digest[0] ^ 1U);

  rasp_self_decrypt_init();

  EXPECT_EQ(permissions_of(pages().code()), "---p");
}

TEST_F(SelfDecryptTest, selfDecrypt_whenAGateTrips_leavesTheCodeWithNoAccess) {
  pack(pages(), meta_address(), reference_content_key(stub_bytes(), ikm_bytes()));

  rasp_self_decrypt_init();

  EXPECT_EQ(permissions_of(pages().code()), "---p");
}

TEST_F(SelfDecryptTest, selfDecrypt_whenTheLibraryIsNotPacked_leavesItAsItIs) {
  pack(pages(), base(), reference_content_key(stub_bytes(), ikm_bytes()));
  g_meta.packed = 0;
  std::vector<std::uint8_t> before(pages().code(), pages().code() + pages().size());

  rasp_self_decrypt_init();

  EXPECT_EQ(std::memcmp(pages().code(), before.data(), before.size()), 0);
}

}  // namespace
}  // namespace rasp::android::selfdecrypt
