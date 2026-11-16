/// Regression tests for constant indices in untrusted fold programs.

#include <array>
#include <cstddef>
#include <cstdint>
#include <gtest/gtest.h>
#include <limits>

#include "payload/key_schedule.h"

namespace rasp::android::payload {
namespace {

/// Encodes one constant record with an all-zero mask.
[[nodiscard]] std::array<std::uint8_t, kProgramSize> program_naming_constant(std::uint16_t index) {
  std::array<std::uint8_t, kProgramSize> program{};
  program[16] = 1;
  program[20] = static_cast<std::uint8_t>(RecordKind::kConstant);
  program[22] = static_cast<std::uint8_t>(index & 0xFFU);
  program[23] = static_cast<std::uint8_t>(index >> 8U);
  return program;
}

TEST(KeyScheduleBounds, decodeProgram_whenTheLastConstantIsNamed_decodesAllElevenConstants) {
  const auto program = decode_program(program_naming_constant(10));
  EXPECT_TRUE(program.has_value() && program->constants.size() == std::size_t{11});
}

TEST(KeyScheduleBounds, decodeProgram_whenConstantExceedsTheBlob_returnsNothing) {
  EXPECT_FALSE(decode_program(program_naming_constant(11)).has_value());
}

TEST(KeyScheduleBounds, decodeProgram_whenConstantIndexIsMaximal_returnsNothing) {
  EXPECT_FALSE(decode_program(program_naming_constant(std::numeric_limits<std::uint16_t>::max())).has_value());
}

}  // namespace
}  // namespace rasp::android::payload
