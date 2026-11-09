/// Tests for the dex store, against a map and dexes the packer's fold made, stored in a zip the test builds. The
/// frames are the fixed vectors the packer's tests check too (key_schedule_test.py), sealed under the fold's root
/// and the sensor guard of a clean process, so open_dex_store's map key and decrypt_dex's guarded keys are
/// exercised exactly as the packer produced them. The decryption's sensors are observed live: a host test process
/// is not traced and cannot check its own code section, so it reads as the clean process the packer folds in.

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

/// The root key of the vectors, made by the packer's fold over a fixed library and program.
constexpr std::string_view kRootHex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

/// A frame holding the class map, made by the packer's fold under kRoot. Its plaintext is:
///   com.example.Alpha,business/0.dex   com.example.Beta,business/0.dex
///   com.example.Gamma,business/1.dex   com.example.Alpha,business/1.dex (a repeat the first line must win over)
constexpr std::string_view kMapFrameHex =
    "000102030405060708090a0bde978b4c0bf489db7f49fe2d7443b65923f17ec4ec53367633"
    "fcb37d50a6ac53509eac1971608f2803a46e0c45224480474a4b73650209f23787a7f57c44"
    "75153a88f127977732363fb99424c2bc83c778eac5def57c814214af0155fd95594d36df73"
    "8bba5c17f86dcfb6a37a27e96ba26c14031d02d10a3a731fa9a2b7d8f8241f07ab51dba377"
    "cd24e3c78d0439271208f1";

/// A frame holding a map whose only usable line is `com.example.Kept,business/0.dex`, made under kRoot. Its other
/// lines are each skipped for a different reason:
///   com.example.NoComma         no comma
///   ,business/0.dex             nothing before the comma
///   com.example.NoPath,         nothing after the comma
///   <empty line>                no comma
constexpr std::string_view kMalformedMapFrameHex =
    "303132333435363738393a3b6f6ff810d62725cc4601b435d1f0462cadd3ebfe802d68b956"
    "7250f51b6351c0684331299aa346c0a65833edf922a414fb41a4af45623e5ce9bac9bf4294"
    "ebe40c241d29142879892e2a3604883fd1becb110add6cf06ec01f321deb4a9ab33ab083a7"
    "7dce618e2955";

/// The dex at business/0.dex: its frame and its plaintext bytes.
constexpr std::string_view kDex0FrameHex =
    "101112131415161718191a1b3bd54b643d169e43202ad27100cb29c136c937d69ecf4279"
    "7c66003decd2eb93859a42526a25bd33c117d2bf13c70f4e48cb716bf6e5b6f6823988cf"
    "a71313a19be2c81c8b6d391caa2d65507b522b";
constexpr std::string_view kDex0Plaintext = "business dex zero: bytes that decrypt_dex must return verbatim\n";

/// The dex at business/1.dex: its frame and its plaintext bytes.
constexpr std::string_view kDex1FrameHex =
    "202122232425262728292a2be6f82c2b5559d83e8e37632b307c749a6b8eda5efdad11e8"
    "d677ef75b10fea0174";
constexpr std::string_view kDex1Plaintext = "business dex one\n";

/// The vectors' Java program: the frame it ships as (sealed under the root, at assets/rasp/j.bin), the share its
/// steps yield on a runtime that resolves them as the packer predicted, and the encoded steps inside the frame.
constexpr std::string_view kJFrameHex =
    "303132333435363738393a3b6e4d4bbca466657713459031be2d98b30172d467d4f16b5f"
    "4b00e02717cc7ea271d3c909c4cff1b0452dc435fc29be838f6a92f61d172f4b94ba1aa4"
    "69b47b8535e3b2d813bfadd77532e2af989efca6a479380fb39f17044aa4a79f5a59edd7"
    "1ea5f318d06b69febd60c2dd2ef04a9b43";
constexpr std::string_view kJShareHex = "063f7eca0167a1c524f862d0f1fd64d44ee47f502dcf8c97fbb4dc7ef16e631a";
constexpr std::string_view kJProgramHex =
    "0400020313006a6176612e7574696c2e41727261794c697374010010006a6176612e6c616e672e537472696e6701001900636f2e6f"
    "73746f726c61622e726173702e5261737053747562020213006a6176612e6c616e672e457863657074696f6e";
constexpr std::string_view kJProgramEntry = "assets/rasp/j.bin";

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

/// The vectors' Java share, decoded: what the stub's program yields on a real runtime.
///
/// @return The Java share.
[[nodiscard]] Key share() {
  Key key{};
  std::ranges::copy(from_hex(kJShareHex) | std::views::take(key.size()), key.begin());
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

  /// The stored frames a full APK holds: the class map, the Java program, and both business dexes. One struct, so
  /// a frame cannot be passed in another frame's place.
  struct Frames {
    /// The stored map frame.
    std::string_view map;
    /// The stored Java program frame, or empty to ship none.
    std::string_view program;
    /// The stored business/0.dex frame.
    std::string_view dex0;
    /// The stored business/1.dex frame.
    std::string_view dex1;
  };

  /// Writes an APK holding the map, the Java program, and both business dexes as `frames` holds them. Each frame
  /// lives for the call, so a caller may pass a tampered copy or a freshly decoded fixture.
  ///
  /// @param frames The stored frames to put in the APK.
  /// @return The APK's path, or empty when the write failed.
  [[nodiscard]] std::string write_full_apk(const Frames& frames) {
    std::vector<StoredEntry> entries = {
        {.name = kMapEntry, .content = frames.map},
        {.name = kDex0Entry, .content = frames.dex0},
        {.name = kDex1Entry, .content = frames.dex1},
    };
    if (!frames.program.empty()) {
      entries.push_back({.name = kJProgramEntry, .content = frames.program});
    }
    return write_apk(entries);
  }

  /// Opens a store over an APK with the clean map, the Java program, and both business dexes.
  ///
  /// @return The store, which has a value whenever the APK was written and the map decrypted.
  [[nodiscard]] std::optional<DexStore> open_clean_store() {
    return open_dex_store(write_full_apk({.map = bytes_of(kMapFrameHex),
                                          .program = bytes_of(kJFrameHex),
                                          .dex0 = bytes_of(kDex0FrameHex),
                                          .dex1 = bytes_of(kDex1FrameHex)}),
                          root());
  }

  /// Opens the clean store and arms it with the vectors' Java share, the way the stub arms a real runtime.
  ///
  /// @return The armed store, which has a value whenever the store opened.
  [[nodiscard]] std::optional<DexStore> armed_store() {
    std::optional<DexStore> store = open_clean_store();
    if (store.has_value()) {
      arm_j_store(*store, share());
    }
    return store;
  }

  /// Opens the clean store and arms it with a share no real runtime would produce.
  ///
  /// @return The wrongly armed store, which has a value whenever the store opened.
  [[nodiscard]] std::optional<DexStore> wrongly_armed_store() {
    std::optional<DexStore> store = open_clean_store();
    if (store.has_value()) {
      arm_j_store(*store, Key{});
    }
    return store;
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
  const std::optional<DexStore> store = armed_store();
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
  const std::optional<DexStore> store = armed_store();
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
  std::optional<DexStore> store = open_dex_store(write_full_apk({.map = bytes_of(kMapFrameHex),
                                                                 .program = bytes_of(kJFrameHex),
                                                                 .dex0 = dex0,
                                                                 .dex1 = bytes_of(kDex1FrameHex)}),
                                                 root());
  ASSERT_TRUE(store.has_value());
  arm_j_store(*store, share());

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
  std::optional<DexStore> store = open_dex_store(apk, root());
  ASSERT_TRUE(store.has_value());
  arm_j_store(*store, share());

  const EncryptedDex* gamma = dex_of(*store, "com.example.Gamma");
  ASSERT_NE(gamma, nullptr);
  EXPECT_FALSE(decrypt_dex(*store, *gamma).has_value());
}

TEST_F(DexStoreTest, openDexStore_whenTheMapFrameIsTampered_returnsNothing) {
  std::string map = bytes_of(kMapFrameHex);
  map.back() = flip_low_bit(map.back());

  EXPECT_FALSE(open_dex_store(write_full_apk({.map = map,
                                              .program = bytes_of(kJFrameHex),
                                              .dex0 = bytes_of(kDex0FrameHex),
                                              .dex1 = bytes_of(kDex1FrameHex)}),
                              root())
                   .has_value());
}

TEST_F(DexStoreTest, openDexStore_whenTheRootIsWrong_returnsNothing) {
  const std::optional<DexStore> store = open_clean_store();
  ASSERT_TRUE(store.has_value());

  EXPECT_FALSE(open_dex_store(write_full_apk({.map = bytes_of(kMapFrameHex),
                                              .program = bytes_of(kJFrameHex),
                                              .dex0 = bytes_of(kDex0FrameHex),
                                              .dex1 = bytes_of(kDex1FrameHex)}),
                              wrong_root())
                   .has_value());
}

TEST_F(DexStoreTest, decryptDex_whenTheRootWasWrongAtOpenTime_cannotDecryptAnyDex) {
  const std::optional<DexStore> store = open_dex_store(write_full_apk({.map = bytes_of(kMapFrameHex),
                                                                       .program = bytes_of(kJFrameHex),
                                                                       .dex0 = bytes_of(kDex0FrameHex),
                                                                       .dex1 = bytes_of(kDex1FrameHex)}),
                                                       wrong_root());
  EXPECT_FALSE(store.has_value());
}

TEST_F(DexStoreTest, decryptDex_beforeTheStoreIsArmed_returnsNothing) {
  const std::optional<DexStore> store = open_clean_store();
  ASSERT_TRUE(store.has_value());

  const EncryptedDex* alpha = dex_of(*store, "com.example.Alpha");
  ASSERT_NE(alpha, nullptr);
  EXPECT_FALSE(decrypt_dex(*store, *alpha).has_value());
}

TEST_F(DexStoreTest, armJStore_whenTheShareIsNotWhatTheRuntimePredicted_cannotDecryptAnyDex) {
  const std::optional<DexStore> store = wrongly_armed_store();
  ASSERT_TRUE(store.has_value());

  const EncryptedDex* alpha = dex_of(*store, "com.example.Alpha");
  const EncryptedDex* gamma = dex_of(*store, "com.example.Gamma");
  ASSERT_NE(alpha, nullptr);
  ASSERT_NE(gamma, nullptr);
  EXPECT_FALSE(decrypt_dex(*store, *alpha).has_value());
  EXPECT_FALSE(decrypt_dex(*store, *gamma).has_value());
}

TEST_F(DexStoreTest, openDexStore_whenTheProgramEntryIsPresent_keepsItForTheStub) {
  const std::optional<DexStore> store = open_clean_store();
  ASSERT_TRUE(store.has_value());

  const std::string program = bytes_of(kJProgramHex);
  EXPECT_EQ(store->j_program, std::vector<std::uint8_t>(program.begin(), program.end()));
}

TEST_F(DexStoreTest, openDexStore_whenTheAppShippedNoProgram_keepsNoProgram) {
  const std::optional<DexStore> store = open_dex_store(write_full_apk({.map = bytes_of(kMapFrameHex),
                                                                       .program = "",
                                                                       .dex0 = bytes_of(kDex0FrameHex),
                                                                       .dex1 = bytes_of(kDex1FrameHex)}),
                                                       root());
  ASSERT_TRUE(store.has_value());

  EXPECT_TRUE(store->j_program.empty());
  EXPECT_FALSE(store->armed.has_value());
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
