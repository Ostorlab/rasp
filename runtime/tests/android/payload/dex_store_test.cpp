/// Tests for the dex store, against a map and dexes the packer's cipher made, stored in a zip the test builds. The
/// frames are fixed bytes the packer's ChaCha20-Poly1305 produced, the same way cipher_test fixes its frames.

#include "payload/dex_store.h"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <gtest/gtest.h>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include "payload/assets.h"
#include "support/files.h"
#include "support/zip.h"

namespace rasp::android::payload {
namespace {

using test_support::StoredEntry;
using test_support::TemporaryDirectory;
using test_support::write_file;
using test_support::zip_with_stored_entries;

/// The value of the lowercase hex digit `c`.
///
/// @param c A hex digit, `0`-`9` or `a`-`f`.
/// @return Its numeric value, 0 to 15.
[[nodiscard]] std::uint32_t nibble(char c) {
  if (c >= '0' && c <= '9') {
    return static_cast<std::uint32_t>(c - '0');
  }
  return static_cast<std::uint32_t>(c - 'a' + 10);
}

/// Decodes a lowercase-hex string into bytes.
///
/// @param hex The hex digits, two per byte.
/// @return The bytes they stand for.
[[nodiscard]] std::vector<std::uint8_t> from_hex(std::string_view hex) {
  std::vector<std::uint8_t> bytes;
  bytes.reserve(hex.size() / 2);
  for (std::size_t i = 0; i + 1 < hex.size(); i += 2) {
    bytes.push_back(static_cast<std::uint8_t>((nibble(hex[i]) << 4U) | nibble(hex[i + 1])));
  }
  return bytes;
}

/// The bytes a lowercase-hex string stands for, as a std::string, so they can be stored as a zip entry's content.
///
/// @param hex The hex digits, two per byte.
/// @return The decoded bytes as a std::string.
[[nodiscard]] std::string bytes_of(std::string_view hex) {
  const std::vector<std::uint8_t> bytes = from_hex(hex);
  return {bytes.begin(), bytes.end()};
}

/// The same byte with its lowest bit flipped, so a frame's authentication tag no longer verifies.
///
/// @param byte The byte to change.
/// @return The byte with its lowest bit flipped.
[[nodiscard]] char flip_low_bit(char byte) { return static_cast<char>(static_cast<unsigned char>(byte) ^ 0x01U); }

/// The key the packer's cipher used to make every frame below.
constexpr std::string_view kKey = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

/// A frame holding the class map, made by the packer's cipher under kKey. Its plaintext is:
///   com.example.Alpha,business/0.dex   com.example.Beta,business/0.dex
///   com.example.Gamma,business/1.dex   com.example.Alpha,business/1.dex (a repeat the first line must win over)
constexpr std::string_view kMapFrame =
    "000102030405060708090a0bea94652e4c6fc42dc7ef5addd9717e0ba85cd092221dc3dc95e400f55ba4c344e6e3439ec8"
    "7bc9f95a421abd4bd6ea571fa8cb018e41d6fe61cbf637be2bfbae731bd3a0cb715488a96621d9363bbd9cb7bf6b501a19"
    "99506b248321e95366da35d40f9c9af7428cd03683dbc7bff6ec99073714eb283391210847ac560e9122c41ec9b675d8d8"
    "98e7a0714e247496c9e0bbcc";

/// A frame holding a map whose only usable line is `com.example.Kept,business/0.dex`, made under kKey. Its other four
/// lines are each skipped for a different reason:
///   com.example.NoComma         no comma
///   ,business/0.dex             nothing before the comma
///   com.example.NoPath,         nothing after the comma
///   <empty line>                no comma
constexpr std::string_view kMalformedMapFrame =
    "303132333435363738393a3b359b2764a199b688187edc223bf76b6da6aeb11fe1e3645af56b817133e024c9fa9f21ba0a"
    "d456a388ac097649de133cbfe5b9445d22dc8451627e35d9b042b9c236365c4fc7e1881ded802c18c7e5eed243c66d27a9"
    "2dc646d89926f880321ff608cfb471f9eb91";

/// The dex at business/0.dex: its frame and its plaintext bytes.
constexpr std::string_view kDex0Frame =
    "101112131415161718191a1b3cbf366e687cb51a3ba2561bf9d1d007155cd54bfdb6b307a2e7df6c989cc7839ff8f909add"
    "bdfb90db59699f6d923ae757c257fda40520cf9f5e6a9c28638c152a684f534c5de6f5da142e7d4ebb9";
constexpr std::string_view kDex0Plaintext = "business dex zero: bytes that decrypt_dex must return verbatim\n";

/// The dex at business/1.dex: its frame and its plaintext bytes.
constexpr std::string_view kDex1Frame =
    "202122232425262728292a2b1192fb157f8a8f49bba1c8b06950e1dd714798ce5c7203e77fb53042ece2de4b15";
constexpr std::string_view kDex1Plaintext = "business dex one\n";

/// The entry name, inside the APK, of each business dex the map points at.
constexpr std::string_view kDex0Entry = "assets/business/0.dex";
constexpr std::string_view kDex1Entry = "assets/business/1.dex";

/// How many threads decrypt at the same time in the concurrency test, and how many dexes each one decrypts.
constexpr int kThreads = 4;
constexpr int kDecryptionsPerThread = 50;

/// Decrypts the clean map's two business dexes in turns, the way one of several threads that load business classes at
/// the same time would.
///
/// @param store A store opened over the clean map and both business dexes.
/// @param start Which dex to decrypt first: an even number for business/0.dex, an odd one for business/1.dex.
/// @return How many of its kDecryptionsPerThread decryptions came back missing or with the wrong bytes.
[[nodiscard]] int decrypt_both_in_turns(const DexStore& store, int start) {
  const EncryptedDex* first = dex_of(store, "com.example.Alpha");
  const EncryptedDex* second = dex_of(store, "com.example.Gamma");
  if (first == nullptr || second == nullptr) {
    return kDecryptionsPerThread;
  }
  int failures = 0;
  for (int round = 0; round < kDecryptionsPerThread; ++round) {
    const bool use_first = (start + round) % 2 == 0;
    const std::optional<std::vector<std::uint8_t>> dex = decrypt_dex(store, use_first ? *first : *second);
    const std::string_view expected = use_first ? kDex0Plaintext : kDex1Plaintext;
    if (!dex.has_value() || std::string(dex->begin(), dex->end()) != expected) {
      ++failures;
    }
  }
  return failures;
}

/// Builds the APKs these tests read, each in its own temporary directory, so a test says only which frames go in.
class DexStoreTest : public testing::Test {
 protected:
  /// Writes an APK holding `entries` and returns its path. The caller keeps the entries' backing bytes alive.
  ///
  /// @param entries The stored entries to put in the APK.
  /// @return The APK's path, or empty when the write failed.
  [[nodiscard]] std::string write_apk(std::span<const StoredEntry> entries) {
    const std::string path = directory_.path() + "/base.apk";
    return write_file(path, zip_with_stored_entries(entries)) ? path : std::string();
  }

  /// Writes an APK holding the map and both business dexes as the given frames. Each frame lives for the call, so a
  /// caller may pass a tampered copy or a freshly decoded fixture.
  ///
  /// @param map The stored map frame.
  /// @param dex0 The stored business/0.dex frame.
  /// @param dex1 The stored business/1.dex frame.
  /// @return The APK's path, or empty when the write failed.
  [[nodiscard]] std::string write_full_apk(std::string_view map, std::string_view dex0, std::string_view dex1) {
    const std::vector<StoredEntry> entries = {
        {.name = kMapEntry, .content = map},
        {.name = kDex0Entry, .content = dex0},
        {.name = kDex1Entry, .content = dex1},
    };
    return write_apk(entries);
  }

  /// Opens a store over an APK with the clean map and both business dexes.
  ///
  /// @return The store, which has a value whenever the APK was written and the map decrypted.
  [[nodiscard]] std::optional<DexStore> open_clean_store() {
    return open_dex_store(write_full_apk(bytes_of(kMapFrame), bytes_of(kDex0Frame), bytes_of(kDex1Frame)),
                          from_hex(kKey));
  }

 private:
  /// The directory each APK is written into; removed when the test ends.
  TemporaryDirectory directory_;
};

TEST_F(DexStoreTest, openDexStore_whenTheMapIsPresent_indexesEveryClassToItsDex) {
  const std::optional<DexStore> store = open_clean_store();
  ASSERT_TRUE(store.has_value());

  const EncryptedDex* alpha = dex_of(*store, "com.example.Alpha");
  const EncryptedDex* beta = dex_of(*store, "com.example.Beta");
  const EncryptedDex* gamma = dex_of(*store, "com.example.Gamma");
  ASSERT_NE(alpha, nullptr);
  ASSERT_NE(beta, nullptr);
  ASSERT_NE(gamma, nullptr);
  EXPECT_EQ(store->dexes.size(), 2U);
  EXPECT_EQ(alpha->entry, kDex0Entry);
  EXPECT_EQ(beta, alpha);
  EXPECT_EQ(gamma->entry, kDex1Entry);
}

TEST_F(DexStoreTest, dexOf_whenAClassIsNotInTheMap_returnsNull) {
  const std::optional<DexStore> store = open_clean_store();
  ASSERT_TRUE(store.has_value());

  EXPECT_EQ(dex_of(*store, "com.example.NotProtected"), nullptr);
}

TEST_F(DexStoreTest, dexOf_whenAClassIsOnTwoLines_returnsTheDexOfTheFirstLine) {
  const std::optional<DexStore> store = open_clean_store();
  ASSERT_TRUE(store.has_value());

  const EncryptedDex* alpha = dex_of(*store, "com.example.Alpha");
  ASSERT_NE(alpha, nullptr);
  EXPECT_EQ(alpha->entry, kDex0Entry);
}

TEST_F(DexStoreTest, openDexStore_whenALineIsMalformed_skipsItAndKeepsTheRest) {
  const std::string map = bytes_of(kMalformedMapFrame);
  const std::string dex0 = bytes_of(kDex0Frame);
  const std::vector<StoredEntry> entries = {
      {.name = kMapEntry, .content = map},
      {.name = kDex0Entry, .content = dex0},
  };
  const std::string apk = write_apk(entries);
  ASSERT_FALSE(apk.empty());

  const std::optional<DexStore> store = open_dex_store(apk, from_hex(kKey));

  ASSERT_TRUE(store.has_value());
  EXPECT_EQ(store->dexes.size(), 1U);
  const EncryptedDex* kept = dex_of(*store, "com.example.Kept");
  ASSERT_NE(kept, nullptr);
  EXPECT_EQ(kept->entry, kDex0Entry);
  EXPECT_EQ(dex_of(*store, "com.example.NoComma"), nullptr);
  EXPECT_EQ(dex_of(*store, "com.example.NoPath"), nullptr);
}

TEST_F(DexStoreTest, openDexStore_whenAClassIsOnTwoLines_listsItOnlyUnderTheDexOfTheFirstLine) {
  const std::optional<DexStore> store = open_clean_store();
  ASSERT_TRUE(store.has_value());

  const EncryptedDex* first = dex_of(*store, "com.example.Alpha");
  const EncryptedDex* second = dex_of(*store, "com.example.Gamma");
  ASSERT_NE(first, nullptr);
  ASSERT_NE(second, nullptr);
  EXPECT_EQ(first->classes, (std::vector<std::string>{"com.example.Alpha", "com.example.Beta"}));
  EXPECT_EQ(second->classes, (std::vector<std::string>{"com.example.Gamma"}));
}

TEST_F(DexStoreTest, decryptDex_whenGivenAMappedClass_returnsItsDexPlaintext) {
  const std::optional<DexStore> store = open_clean_store();
  ASSERT_TRUE(store.has_value());

  const EncryptedDex* alpha = dex_of(*store, "com.example.Alpha");
  const EncryptedDex* gamma = dex_of(*store, "com.example.Gamma");
  ASSERT_NE(alpha, nullptr);
  ASSERT_NE(gamma, nullptr);

  const std::optional<std::vector<std::uint8_t>> first = decrypt_dex(*store, *alpha);
  const std::optional<std::vector<std::uint8_t>> second = decrypt_dex(*store, *gamma);
  ASSERT_TRUE(first.has_value());
  ASSERT_TRUE(second.has_value());
  EXPECT_EQ(std::string(first->begin(), first->end()), std::string(kDex0Plaintext));
  EXPECT_EQ(std::string(second->begin(), second->end()), std::string(kDex1Plaintext));
}

TEST_F(DexStoreTest, decryptDex_whenCalledFromSeveralThreadsAtOnce_decryptsEveryDex) {
  const std::optional<DexStore> store = open_clean_store();
  ASSERT_TRUE(store.has_value());

  std::atomic<int> failures{0};
  std::vector<std::thread> workers;
  workers.reserve(kThreads);
  for (int index = 0; index < kThreads; ++index) {
    workers.emplace_back([&store, &failures, index] { failures.fetch_add(decrypt_both_in_turns(*store, index)); });
  }
  for (std::thread& worker : workers) {
    worker.join();
  }

  EXPECT_EQ(failures.load(), 0);
}

TEST_F(DexStoreTest, decryptDex_whenTheDexFrameIsTampered_returnsNothing) {
  std::string dex0 = bytes_of(kDex0Frame);
  dex0.back() = flip_low_bit(dex0.back());
  const std::optional<DexStore> store =
      open_dex_store(write_full_apk(bytes_of(kMapFrame), dex0, bytes_of(kDex1Frame)), from_hex(kKey));
  ASSERT_TRUE(store.has_value());

  const EncryptedDex* alpha = dex_of(*store, "com.example.Alpha");
  ASSERT_NE(alpha, nullptr);
  EXPECT_FALSE(decrypt_dex(*store, *alpha).has_value());
}

TEST_F(DexStoreTest, decryptDex_whenTheDexEntryIsAbsent_returnsNothing) {
  const std::string map = bytes_of(kMapFrame);
  const std::string dex0 = bytes_of(kDex0Frame);
  const std::vector<StoredEntry> entries = {
      {.name = kMapEntry, .content = map},
      {.name = kDex0Entry, .content = dex0},
  };
  const std::string apk = write_apk(entries);
  ASSERT_FALSE(apk.empty());
  const std::optional<DexStore> store = open_dex_store(apk, from_hex(kKey));
  ASSERT_TRUE(store.has_value());

  const EncryptedDex* gamma = dex_of(*store, "com.example.Gamma");
  ASSERT_NE(gamma, nullptr);
  EXPECT_FALSE(decrypt_dex(*store, *gamma).has_value());
}

TEST_F(DexStoreTest, openDexStore_whenTheMapFrameIsTampered_returnsNothing) {
  std::string map = bytes_of(kMapFrame);
  map.back() = flip_low_bit(map.back());

  EXPECT_FALSE(
      open_dex_store(write_full_apk(map, bytes_of(kDex0Frame), bytes_of(kDex1Frame)), from_hex(kKey)).has_value());
}

TEST_F(DexStoreTest, openDexStore_whenTheMapEntryIsAbsent_returnsNothing) {
  const std::string dex0 = bytes_of(kDex0Frame);
  const std::vector<StoredEntry> entries = {
      {.name = kDex0Entry, .content = dex0},
  };
  const std::string apk = write_apk(entries);
  ASSERT_FALSE(apk.empty());

  EXPECT_FALSE(open_dex_store(apk, from_hex(kKey)).has_value());
}

}  // namespace
}  // namespace rasp::android::payload
