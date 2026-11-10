/// Tests for the CBOR encoder against hand-computed test vectors and server cross-validation.

#include "cbor.h"

#include <cstdint>
#include <gtest/gtest.h>
#include <string>
#include <vector>

#include "rasp/observation.h"

namespace rasp::plugins::dns_reporting {
namespace {

TEST(Cbor, encodeObservations_whenEmpty_encodesEmptyArray) {
  const std::vector<rasp::Observation> observations;

  const std::vector<std::uint8_t> result = encode_observations(observations);

  // CBOR empty array: major 4, argument 0 → 0x80
  EXPECT_EQ(result, std::vector<std::uint8_t>{0x80});
}

TEST(Cbor, encodeObservations_whenBoolTrue_encodesTrue) {
  const std::vector<rasp::Observation> observations = {
      rasp::observed("sig", "src", true),
  };

  const std::vector<std::uint8_t> result = encode_observations(observations);

  const std::vector<std::uint8_t> expected = {
      0x81, 0x84, 0x63, 's', 'i', 'g', 0x63, 's', 'r', 'c', 0x00, 0xF5,
  };
  EXPECT_EQ(result, expected);
}

TEST(Cbor, encodeObservations_whenBoolFalse_encodesFalse) {
  const std::vector<rasp::Observation> observations = {
      rasp::observed("sig", "src", false),
  };

  const std::vector<std::uint8_t> result = encode_observations(observations);

  // 0xF4 is CBOR false
  const std::vector<std::uint8_t> expected = {
      0x81, 0x84, 0x63, 's', 'i', 'g', 0x63, 's', 'r', 'c', 0x00, 0xF4,
  };
  EXPECT_EQ(result, expected);
}

TEST(Cbor, encodeObservations_whenIntegerValue_encodesCorrectly) {
  const std::vector<rasp::Observation> observations = {
      rasp::observed("s", "r", static_cast<std::int64_t>(42)),
  };

  const std::vector<std::uint8_t> result = encode_observations(observations);

  const std::vector<std::uint8_t> expected = {
      0x81, 0x84, 0x61, 's', 0x61, 'r', 0x00, 0x18, 0x2A,
  };
  EXPECT_EQ(result, expected);
}

TEST(Cbor, encodeObservations_whenNegativeInteger_encodesCorrectly) {
  const std::vector<rasp::Observation> observations = {
      rasp::observed("s", "r", static_cast<std::int64_t>(-1)),
  };

  const std::vector<std::uint8_t> result = encode_observations(observations);

  const std::vector<std::uint8_t> expected = {
      0x81, 0x84, 0x61, 's', 0x61, 'r', 0x00, 0x20,
  };
  EXPECT_EQ(result, expected);
}

TEST(Cbor, encodeObservations_whenStringValue_encodesCorrectly) {
  const std::vector<rasp::Observation> observations = {
      rasp::observed("s", "r", std::string("hello")),
  };

  const std::vector<std::uint8_t> result = encode_observations(observations);

  const std::vector<std::uint8_t> expected = {
      0x81, 0x84, 0x61, 's', 0x61, 'r', 0x00, 0x65, 'h', 'e', 'l', 'l', 'o',
  };
  EXPECT_EQ(result, expected);
}

TEST(Cbor, encodeObservations_whenStringListValue_encodesCorrectly) {
  const std::vector<rasp::Observation> observations = {
      rasp::observed("s", "r", std::vector<std::string>{"a", "bb"}),
  };

  const std::vector<std::uint8_t> result = encode_observations(observations);

  const std::vector<std::uint8_t> expected = {
      0x81, 0x84, 0x61, 's', 0x61, 'r', 0x00, 0x82, 0x61, 'a', 0x62, 'b', 'b',
  };
  EXPECT_EQ(result, expected);
}

TEST(Cbor, encodeObservations_whenNoValue_encodesNull) {
  const std::vector<rasp::Observation> observations = {
      rasp::unsupported("s", "r"),
  };

  const std::vector<std::uint8_t> result = encode_observations(observations);

  const std::vector<std::uint8_t> expected = {
      0x81, 0x84, 0x61, 's', 0x61, 'r', 0x01, 0xF6,
  };
  EXPECT_EQ(result, expected);
}

TEST(Cbor, encodeObservations_whenErrorStatus_encodesStatusTwo) {
  const std::vector<rasp::Observation> observations = {
      rasp::failed("s", "r"),
  };

  const std::vector<std::uint8_t> result = encode_observations(observations);

  // status 2 = kError, value = null (0xF6)
  const std::vector<std::uint8_t> expected = {
      0x81, 0x84, 0x61, 's', 0x61, 'r', 0x02, 0xF6,
  };
  EXPECT_EQ(result, expected);
}

TEST(Cbor, encodeObservations_whenTimeoutStatus_encodesStatusThree) {
  const std::vector<rasp::Observation> observations = {
      {.signal = "s", .source = "r", .status = rasp::Status::kTimeout, .value = {}},
  };

  const std::vector<std::uint8_t> result = encode_observations(observations);

  // status 3 = kTimeout, value = null (0xF6)
  const std::vector<std::uint8_t> expected = {
      0x81, 0x84, 0x61, 's', 0x61, 'r', 0x03, 0xF6,
  };
  EXPECT_EQ(result, expected);
}

TEST(Cbor, encodeObservations_whenMultipleObservations_encodesAll) {
  const std::vector<rasp::Observation> observations = {
      rasp::observed("jb.sandbox_escape", "open", true),
      rasp::observed("jb.fs_paths", "access", std::vector<std::string>{"/Applications/Cydia.app"}),
  };

  const std::vector<std::uint8_t> result = encode_observations(observations);

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
  const std::vector<rasp::Observation> observations = {
      rasp::observed("a", "b", static_cast<std::int64_t>(255)),
      rasp::observed("a", "b", static_cast<std::int64_t>(256)),
      rasp::observed("a", "b", static_cast<std::int64_t>(65536)),
      rasp::observed("a", "b", static_cast<std::int64_t>(4294967296)),
  };

  const std::vector<std::uint8_t> result = encode_observations(observations);

  const std::vector<std::uint8_t> prefix = {0x84, 0x61, 'a', 0x61, 'b', 0x00};

  // 255: 1-byte argument → 0x18 0xFF
  const std::vector<std::uint8_t> val_255 = {0x18, 0xFF};
  // 256: 2-byte argument → 0x19 0x01 0x00
  const std::vector<std::uint8_t> val_256 = {0x19, 0x01, 0x00};
  // 65536: 4-byte argument → 0x1A 0x00 0x01 0x00 0x00
  const std::vector<std::uint8_t> val_65536 = {0x1A, 0x00, 0x01, 0x00, 0x00};
  // 4294967296 (2^32): 8-byte argument → 0x1B 0x00 0x00 0x00 0x01 0x00 0x00 0x00 0x00
  const std::vector<std::uint8_t> val_2_32 = {0x1B, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00};

  std::vector<std::uint8_t> expected;
  expected.push_back(0x84);
  expected.insert(expected.end(), prefix.begin(), prefix.end());
  expected.insert(expected.end(), val_255.begin(), val_255.end());
  expected.insert(expected.end(), prefix.begin(), prefix.end());
  expected.insert(expected.end(), val_256.begin(), val_256.end());
  expected.insert(expected.end(), prefix.begin(), prefix.end());
  expected.insert(expected.end(), val_65536.begin(), val_65536.end());
  expected.insert(expected.end(), prefix.begin(), prefix.end());
  expected.insert(expected.end(), val_2_32.begin(), val_2_32.end());

  EXPECT_EQ(result, expected);
}

TEST(Cbor, encodeObservations_whenInt64Min_encodesEightByteNegative) {
  const std::vector<rasp::Observation> observations = {
      rasp::observed("a", "b", INT64_MIN),
  };

  const std::vector<std::uint8_t> result = encode_observations(observations);

  // INT64_MIN = -9223372036854775808
  // CBOR negative: -(value + 1) = 9223372036854775807 = 0x7FFFFFFFFFFFFFFF
  // major 1, 8-byte argument: 0x3B 0x7F 0xFF 0xFF 0xFF 0xFF 0xFF 0xFF 0xFF
  const std::vector<std::uint8_t> expected = {
      0x81, 0x84, 0x61, 'a', 0x61, 'b', 0x00, 0x3B, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
  };
  EXPECT_EQ(result, expected);
}

}  // namespace
}  // namespace rasp::plugins::dns_reporting
