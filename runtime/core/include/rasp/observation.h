/// Observation, the raw fact a check reports, and its description for logs.

#pragma once

#include <cstdint>
#include <string>
#include <variant>
#include <vector>

namespace rasp {

/// Whether a check produced a value, and if not, why.
enum class Status : std::uint8_t {
  /// The check ran and produced a value.
  kOk,
  /// The check cannot run here, for example on a simulator.
  kUnsupported,
  /// The check ran but failed, for example because a system call returned an error.
  kError,
  /// The check did not finish in time.
  kTimeout,
};

/// The value of an observation: none, or exactly one of the contract's value types.
using Value = std::variant<std::monostate, bool, std::int64_t, std::string, std::vector<std::string>>;

/// One raw fact observed by one check, read through one source.
struct Observation {
  /// What was observed, such as jb.fork_ok.
  std::string signal;
  /// How it was read, such as stat or fork. One signal can be read through several sources.
  std::string source;
  /// Whether the check produced a value, and if not, why.
  Status status = Status::kOk;
  /// What the check found. It is empty when the check produced no value.
  Value value;

  /// Compares two observations field by field.
  ///
  /// @param left The first observation.
  /// @param right The second observation.
  /// @return `true` when both have the same signal, source, status and value.
  [[nodiscard]] friend bool operator==(const Observation& left, const Observation& right) = default;
};

/// Writes an observation as one line of text, for development logs.
///
/// The line is `<signal>/<source> <status>`, then a space and the value when the value has text. For example,
/// `jb.fs_paths/stat ok [/bin/sh, /var/jb]`, or `jb.fork_ok/fork unsupported` for an observation with no value.
/// The status is written in lowercase: `ok`, `unsupported`, `error` or `timeout`. A boolean is written as `true` or
/// `false`, an integer in decimal, a string as it is, and a list of strings as `[a, b]`. An empty string has no text,
/// so it is left out, like a missing value.
///
/// @param observation The observation to describe.
/// @return The line, with no newline at the end.
[[nodiscard]] std::string describe(const Observation& observation);

}  // namespace rasp
