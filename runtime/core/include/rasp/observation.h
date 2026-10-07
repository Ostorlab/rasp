#pragma once

#include <cstdint>
#include <string>
#include <variant>
#include <vector>

namespace rasp {

/// Whether a check produced a value, and if not, why.
enum class Status : std::uint8_t { kOk, kUnsupported, kError, kTimeout };

/// The value of an observation: none, or exactly one of the contract's value types.
using Value = std::variant<std::monostate, bool, std::int32_t, std::int64_t, std::string, std::vector<std::string>>;

/// One raw fact observed by one check, read through one source.
struct Observation {
  std::string signal;
  std::string source;
  Status status = Status::kOk;
  Value value;

  [[nodiscard]] friend bool operator==(const Observation&, const Observation&) = default;
};

/// The observation as one line of text, for logs.
[[nodiscard]] std::string describe(const Observation& observation);

}  // namespace rasp
