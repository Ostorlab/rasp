/// Checked portable conversion for the private suspend-inclusive clock, without platform APIs.
#pragma once
#include <cstdint>
#include <limits>
#include <optional>
namespace rasp::policy_internal {
/// Native clock conversion scale.
struct ClockTimebase {
  std::uint32_t numerator;
  std::uint32_t denominator;
};
/// Convert ticks using a uint32 timebase without multiply/add overflow or fake default time.
/// @param ticks Observed native ticks, never device wall time.
/// @param timebase Native numerator/denominator; either zero is unavailable.
/// @return Nonnegative signed nanoseconds, or unavailable beyond representable range.
[[nodiscard]] inline std::optional<std::int64_t> clock_nanoseconds(std::uint64_t ticks, ClockTimebase timebase) {
  const auto [numerator, denominator] = timebase;
  if (numerator == 0 || denominator == 0) {
    return std::nullopt;
  }
  constexpr auto kMaximum = static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max());
  const std::uint64_t quotient = ticks / denominator;
  const std::uint64_t remainder = ticks % denominator;
  if (quotient > kMaximum / numerator) {
    return std::nullopt;
  }
  const std::uint64_t whole = quotient * numerator;
  const std::uint64_t fraction = remainder * numerator / denominator;
  if (fraction > kMaximum - whole) {
    return std::nullopt;
  }
  return static_cast<std::int64_t>(whole + fraction);
}
}  // namespace rasp::policy_internal
