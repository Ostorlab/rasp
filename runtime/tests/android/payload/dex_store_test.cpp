/// Tests for the dex store, against a map and dexes the packer's schedule made, stored in a zip the test builds. The
/// frames are the fixed vectors the packer's tests check too (key_schedule_test.py): the map and both dexes were
/// sealed under the schedule over a fixed root, so open_dex_store's map key and decrypt_dex's dex keys are exercised
/// exactly as the packer produced them.

#include "payload/dex_store.h"

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <gtest/gtest.h>
#include <optional>
#include <ranges>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include "payload/assets.h"
#include "payload/key_schedule.h"
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

/// The root key of the vectors, made by the packer's schedule over a fixed library and shares.
constexpr std::string_view kRootHex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

/// A frame holding the class map, made by the packer's schedule under kRoot. Its plaintext is:
///   com.example.Alpha,business/0.dex   com.example.Beta,business/0.dex
///   com.example.Gamma,business/1.dex   com.example.Alpha,business/1.dex (a repeat the first line must win over)
constexpr std::string_view kMapFrameHex =
    "000102030405060708090a0bfa778ca58fe9a3129eb01f255c3f58b75132615e4a4fbdce"
    "9a57a5c9b8f2ddc5099d30effa98d3c123c032a7f98fcc8164af6e17296abe4fea2f1ac7"
    "0ef47c9e378a9380aabc9acffdd578afe22364488843158031b90902b5c6641af81ce706"
    "f994da417c658b0406c21eea5c9236bb6aa18798a655a86776437e8309fda8c48c154b21"
    "2877a652cd3963fa7c0d59c8b620aa";

/// A frame holding a map whose only usable line is `com.example.Kept,business/0.dex`, made under kRoot. Its other
/// lines are each skipped for a different reason:
///   com.example.NoComma         no comma
///   ,business/0.dex             nothing before the comma
///   com.example.NoPath,         nothing after the comma
///   <empty line>                no comma
constexpr std::string_view kMalformedMapFrameHex =
    "303132333435363738393a3b326e7a0942924c385d0626dd783d0018f41cd777880d9fad3"
    "add5524fb22f1b4411d610df6ae5c38aa336bafd4a1b6f7862d78dd7c90209a1a1ebec786"
    "a36388c6ed72ae9752e66257d707d57932b5e3585972fb0f8a2a673b4e397ffcafac4472d"
    "3a7abbcafd97fdf";

/// The dex at business/0.dex: its frame and its plaintext bytes.
constexpr std::string_view kDex0FrameHex =
    "101112131415161718191a1b8b1ee9ab64248cd5df0472dcf17e727a38b00d8eb15b986e"
    "4c67ab8fb78952634d1d963055ec9a7f04b5f4d27b99c6080c34b0001e76661051ca1997"
    "8ffbaa862837613153b36f311592744af503ee";
constexpr std::string_view kDex0Plaintext = "business dex zero: bytes that decrypt_dex must return verbatim\n";

/// The dex at business/1.dex: its frame and its plaintext bytes.
constexpr std::string_view kDex1FrameHex =
    "202122232425262728292a2ba2851fa4da0a9d8ff2ababc947146ff64a8c8516c66ee543"
    "11f1721f9dd1b6a3ee";
constexpr std::string_view kDex1Plaintext = "business dex one\n";

/// The entry name, inside the APK, of each business dex the map points at.
constexpr std::string_view kDex0Entry = "assets/business/0.dex";
constexpr std::string_view kDex1Entry = "assets/business/1.dex";

/// How many threads decrypt at the same time in the concurrency test, and how many dexes each one decrypts.
constexpr int kThreads = 4;
constexpr int kDecryptionsPerThread = 50;

/// The root key of the vectors, decoded.
///
/// @return The root key.
[[nodiscard]] Key root() {
  Key key{};
  std::ranges::copy(from_hex(kRootHex) | std::views::take(key.size()), key.begin());
  return key;
}

/// A root key that is not the vectors': the vectors' root with its first byte flipped.
///
/// @return The wrong root key.
[[nodiscard]] Key wrong_root() {
  Key key = root();
  key[0] = static_cast<std::uint8_t>(key[0] ^ 0x01U);
  return key;
}

/// The same byte with its lowest bit flipped, so a frame's authentication tag no longer verifies.
///
/// @param byte The byte to change.
/// @return The byte with its lowest bit flipped.
[[nodiscard]] char flip_low_bit(char byte) { return static_cast<char>(static_cast<unsigned char>(byte) ^ 0x01U); }

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
    return open_dex_store(write_full_apk(bytes_of(kMapFrameHex), bytes_of(kDex0FrameHex), bytes_of(kDex1FrameHex)),
                          root());
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
  const std::string map = bytes_of(kMalformedMapFrameHex);
  const std::string dex0 = bytes_of(kDex0FrameHex);
  const std::vector<StoredEntry> entries = {
      {.name = kMapEntry, .content = map},
      {.name = kDex0Entry, .content = dex0},
  };
  const std::string apk = write_apk(entries);
  ASSERT_FALSE(apk.empty());

  const std::optional<DexStore> store = open_dex_store(apk, root());

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
  std::string dex0 = bytes_of(kDex0FrameHex);
  dex0.back() = flip_low_bit(dex0.back());
  const std::optional<DexStore> store =
      open_dex_store(write_full_apk(bytes_of(kMapFrameHex), dex0, bytes_of(kDex1FrameHex)), root());
  ASSERT_TRUE(store.has_value());

  const EncryptedDex* alpha = dex_of(*store, "com.example.Alpha");
  ASSERT_NE(alpha, nullptr);
  EXPECT_FALSE(decrypt_dex(*store, *alpha).has_value());
}

TEST_F(DexStoreTest, decryptDex_whenTheDexEntryIsAbsent_returnsNothing) {
  const std::string map = bytes_of(kMapFrameHex);
  const std::string dex0 = bytes_of(kDex0FrameHex);
  const std::vector<StoredEntry> entries = {
      {.name = kMapEntry, .content = map},
      {.name = kDex0Entry, .content = dex0},
  };
  const std::string apk = write_apk(entries);
  ASSERT_FALSE(apk.empty());
  const std::optional<DexStore> store = open_dex_store(apk, root());
  ASSERT_TRUE(store.has_value());

  const EncryptedDex* gamma = dex_of(*store, "com.example.Gamma");
  ASSERT_NE(gamma, nullptr);
  EXPECT_FALSE(decrypt_dex(*store, *gamma).has_value());
}

TEST_F(DexStoreTest, openDexStore_whenTheMapFrameIsTampered_returnsNothing) {
  std::string map = bytes_of(kMapFrameHex);
  map.back() = flip_low_bit(map.back());

  EXPECT_FALSE(
      open_dex_store(write_full_apk(map, bytes_of(kDex0FrameHex), bytes_of(kDex1FrameHex)), root()).has_value());
}

TEST_F(DexStoreTest, openDexStore_whenTheRootIsWrong_returnsNothing) {
  const std::optional<DexStore> store = open_clean_store();
  ASSERT_TRUE(store.has_value());

  EXPECT_FALSE(open_dex_store(write_full_apk(bytes_of(kMapFrameHex), bytes_of(kDex0FrameHex), bytes_of(kDex1FrameHex)),
                              wrong_root())
                   .has_value());
}

TEST_F(DexStoreTest, decryptDex_whenTheRootWasWrongAtOpenTime_cannotDecryptAnyDex) {
  const std::optional<DexStore> store = open_dex_store(
      write_full_apk(bytes_of(kMapFrameHex), bytes_of(kDex0FrameHex), bytes_of(kDex1FrameHex)), wrong_root());
  EXPECT_FALSE(store.has_value());
}

TEST_F(DexStoreTest, openDexStore_whenTheMapEntryIsAbsent_returnsNothing) {
  const std::string dex0 = bytes_of(kDex0FrameHex);
  const std::vector<StoredEntry> entries = {
      {.name = kDex0Entry, .content = dex0},
  };
  const std::string apk = write_apk(entries);
  ASSERT_FALSE(apk.empty());

  EXPECT_FALSE(open_dex_store(apk, root()).has_value());
}

}  // namespace
}  // namespace rasp::android::payload
