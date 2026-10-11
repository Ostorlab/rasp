/// Observation, the raw fact a check reports, the helpers that build one, and its description for logs.

#pragma once

#include <cstdint>
#include <string>
#include <string_view>
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

/// An observation for a check that ran and produced `value`.
///
/// @param signal What was observed, such as jb.fork_ok.
/// @param source How it was read, such as fork.
/// @param value What the check found.
/// @return The observation, with status `kOk`.
[[nodiscard]] Observation observed(std::string_view signal, std::string_view source, Value value);

/// An observation for a check that cannot run here, with no value.
///
/// @param signal What the check would observe, such as jb.fork_ok.
/// @param source How the check would read it, such as fork.
/// @return The observation, with status `kUnsupported` and an empty value.
[[nodiscard]] Observation unsupported(std::string_view signal, std::string_view source);

/// An observation for a check that ran but failed, with no value.
///
/// @param signal What the check tried to observe, such as jb.sandbox_escape.
/// @param source How the check tried to read it, such as open.
/// @return The observation, with status `kError` and an empty value.
[[nodiscard]] Observation failed(std::string_view signal, std::string_view source);

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
