/// Tests for the CBOR encoder against hand-computed test vectors and server cross-validation.

#include "rasp/reporting/cbor.h"

#include <cstdint>
#include <gtest/gtest.h>
#include <string>
#include <vector>

#include "rasp/observation.h"

namespace rasp::reporting {
namespace {

TEST(Cbor, encodeObservations_whenEmpty_encodesEmptyArray) {
  const std::vector<Observation> observations;

  const std::vector<std::uint8_t> result = encode_observations(observations);

  // CBOR empty array: major 4, argument 0 → 0x80
  EXPECT_EQ(result, std::vector<std::uint8_t>{0x80});
}

TEST(Cbor, encodeObservations_whenBoolValue_encodesCorrectly) {
  const std::vector<Observation> observations = {
      observed("sig", "src", true),
  };

  const std::vector<std::uint8_t> result = encode_observations(observations);

  // Outer array of 1: 0x81
  // Inner array of 4: 0x84
  // "sig" (3 bytes): 0x63 's' 'i' 'g'
  // "src" (3 bytes): 0x63 's' 'r' 'c'
  // status 0 (kOk): 0x00
  // true: 0xF5
  const std::vector<std::uint8_t> expected = {
      0x81, 0x84, 0x63, 's', 'i', 'g', 0x63, 's', 'r', 'c', 0x00, 0xF5,
  };
  EXPECT_EQ(result, expected);
}

TEST(Cbor, encodeObservations_whenIntegerValue_encodesCorrectly) {
  const std::vector<Observation> observations = {
      observed("s", "r", static_cast<std::int64_t>(42)),
  };

  const std::vector<std::uint8_t> result = encode_observations(observations);

  // Outer array of 1: 0x81
  // Inner array of 4: 0x84
  // "s" (1 byte): 0x61 's'
  // "r" (1 byte): 0x61 'r'
  // status 0: 0x00
  // unsigned 42: 0x18 0x2A (24 < 42 < 256, so additional=24 then 1 byte)
  const std::vector<std::uint8_t> expected = {
      0x81, 0x84, 0x61, 's', 0x61, 'r', 0x00, 0x18, 0x2A,
  };
  EXPECT_EQ(result, expected);
}

TEST(Cbor, encodeObservations_whenNegativeInteger_encodesCorrectly) {
  const std::vector<Observation> observations = {
      observed("s", "r", static_cast<std::int64_t>(-1)),
  };

  const std::vector<std::uint8_t> result = encode_observations(observations);

  // Outer array of 1: 0x81
  // Inner array of 4: 0x84
  // "s": 0x61 's'
  // "r": 0x61 'r'
  // status 0: 0x00
  // negative -1 → major 1, argument 0 → 0x20
  const std::vector<std::uint8_t> expected = {
      0x81, 0x84, 0x61, 's', 0x61, 'r', 0x00, 0x20,
  };
  EXPECT_EQ(result, expected);
}

TEST(Cbor, encodeObservations_whenStringValue_encodesCorrectly) {
  const std::vector<Observation> observations = {
      observed("s", "r", std::string("hello")),
  };

  const std::vector<std::uint8_t> result = encode_observations(observations);

  // "hello" (5 bytes): 0x65 'h' 'e' 'l' 'l' 'o'
  const std::vector<std::uint8_t> expected = {
      0x81, 0x84, 0x61, 's', 0x61, 'r', 0x00, 0x65, 'h', 'e', 'l', 'l', 'o',
  };
  EXPECT_EQ(result, expected);
}

TEST(Cbor, encodeObservations_whenStringListValue_encodesCorrectly) {
  const std::vector<Observation> observations = {
      observed("s", "r", std::vector<std::string>{"a", "bb"}),
  };

  const std::vector<std::uint8_t> result = encode_observations(observations);

  // Inner value is array of 2: 0x82
  // "a" (1 byte): 0x61 'a'
  // "bb" (2 bytes): 0x62 'b' 'b'
  const std::vector<std::uint8_t> expected = {
      0x81, 0x84, 0x61, 's', 0x61, 'r', 0x00, 0x82, 0x61, 'a', 0x62, 'b', 'b',
  };
  EXPECT_EQ(result, expected);
}

TEST(Cbor, encodeObservations_whenNoValue_encodesNull) {
  const std::vector<Observation> observations = {
      unsupported("s", "r"),
  };

  const std::vector<std::uint8_t> result = encode_observations(observations);

  // status 1 (kUnsupported): 0x01
  // null: 0xF6
  const std::vector<std::uint8_t> expected = {
      0x81, 0x84, 0x61, 's', 0x61, 'r', 0x01, 0xF6,
  };
  EXPECT_EQ(result, expected);
}

TEST(Cbor, encodeObservations_whenMultipleObservations_encodesAll) {
  // Matches the server's conftest.py test data:
  // [["jb.sandbox_escape", "open", 0, true],
  //  ["jb.fs_paths", "access", 0, ["/Applications/Cydia.app"]]]
  const std::vector<Observation> observations = {
      observed("jb.sandbox_escape", "open", true),
      observed("jb.fs_paths", "access", std::vector<std::string>{"/Applications/Cydia.app"}),
  };

  const std::vector<std::uint8_t> result = encode_observations(observations);

  // Hand-computed CBOR bytes:
  // 0x82 — outer array of 2
  //
  // First observation:
  // 0x84 — inner array of 4
  // 0x71 + "jb.sandbox_escape" (17 bytes) — text(17)
  // 0x64 + "open" (4 bytes) — text(4)
  // 0x00 — unsigned 0 (status ok)
  // 0xF5 — true
  //
  // Second observation:
  // 0x84 — inner array of 4
  // 0x6B + "jb.fs_paths" (11 bytes) — text(11)
  // 0x66 + "access" (6 bytes) — text(6)
  // 0x00 — unsigned 0
  // 0x81 — array of 1
  // 0x77 + "/Applications/Cydia.app" (23 bytes) — text(23)
  const std::vector<std::uint8_t> expected = {
      // outer array(2)
      0x82,
      // first: array(4)
      0x84,
      // "jb.sandbox_escape" (17 bytes)
      0x71,
      'j',
      'b',
      '.',
      's',
      'a',
      'n',
      'd',
      'b',
      'o',
      'x',
      '_',
      'e',
      's',
      'c',
      'a',
      'p',
      'e',
      // "open" (4 bytes)
      0x64,
      'o',
      'p',
      'e',
      'n',
      // status 0
      0x00,
      // true
      0xF5,
      // second: array(4)
      0x84,
      // "jb.fs_paths" (11 bytes)
      0x6B,
      'j',
      'b',
      '.',
      'f',
      's',
      '_',
      'p',
      'a',
      't',
      'h',
      's',
      // "access" (6 bytes)
      0x66,
      'a',
      'c',
      'c',
      'e',
      's',
      's',
      // status 0
      0x00,
      // array(1)
      0x81,
      // "/Applications/Cydia.app" (23 bytes)
      0x77,
      '/',
      'A',
      'p',
      'p',
      'l',
      'i',
      'c',
      'a',
      't',
      'i',
      'o',
      'n',
      's',
      '/',
      'C',
      'y',
      'd',
      'i',
      'a',
      '.',
      'a',
      'p',
      'p',
  };
  EXPECT_EQ(result, expected);
}

TEST(Cbor, encodeObservations_whenLargeInteger_usesShortestForm) {
  // 255 needs additional=24 + 1 byte (2 bytes total for the integer)
  // 256 needs additional=25 + 2 bytes big-endian (3 bytes total)
  // 65536 needs additional=26 + 4 bytes big-endian (5 bytes total)
  const std::vector<Observation> observations = {
      observed("a", "b", static_cast<std::int64_t>(255)),
      observed("a", "b", static_cast<std::int64_t>(256)),
      observed("a", "b", static_cast<std::int64_t>(65536)),
  };

  const std::vector<std::uint8_t> result = encode_observations(observations);

  // Outer array of 3: 0x83
  // Each inner observation is: 0x84, 0x61 'a', 0x61 'b', 0x00, <value>
  const std::vector<std::uint8_t> prefix = {0x84, 0x61, 'a', 0x61, 'b', 0x00};

  // 255: 0x18 0xFF
  const std::vector<std::uint8_t> val_255 = {0x18, 0xFF};
  // 256: 0x19 0x01 0x00
  const std::vector<std::uint8_t> val_256 = {0x19, 0x01, 0x00};
  // 65536: 0x1A 0x00 0x01 0x00 0x00
  const std::vector<std::uint8_t> val_65536 = {0x1A, 0x00, 0x01, 0x00, 0x00};

  std::vector<std::uint8_t> expected;
  expected.push_back(0x83);
  expected.insert(expected.end(), prefix.begin(), prefix.end());
  expected.insert(expected.end(), val_255.begin(), val_255.end());
  expected.insert(expected.end(), prefix.begin(), prefix.end());
  expected.insert(expected.end(), val_256.begin(), val_256.end());
  expected.insert(expected.end(), prefix.begin(), prefix.end());
  expected.insert(expected.end(), val_65536.begin(), val_65536.end());

  EXPECT_EQ(result, expected);
}

}  // namespace
}  // namespace rasp::reporting
