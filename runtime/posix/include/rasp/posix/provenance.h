/// Bounded, path-free provenance values shared by the inactive platform collectors.
#pragma once

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "rasp/observation.h"

namespace rasp::provenance {
/// Failure reasons describe collection availability, never a security verdict.
enum class Error : std::uint8_t {
  kNone = 0,
  kPlatform = 1,
  kContextAbsent = 2,
  kNativeUnavailable = 3,
  kDenied = 4,
  kIo = 5,
  kMalformed = 6,
  kInputLimit = 7,
  kJni = 8,
  kCleanup = 9,
  kRace = 10,
  kDeadline = 11,
  /// Explicit foreign-boundary sentinel; normalized to an I/O error before wire formatting.
  kUnrecognized = 255,
};
/// A source operation either returns owned data or a concrete failure.
template <typename T>
using Result = std::expected<T, Error>;
/// A replaceable monotonic nanosecond clock; negative readings are unavailable.
using Clock = std::int64_t (*)();
/// Reads monotonic time without consulting wall-clock identity or freshness.
[[nodiscard]] inline std::int64_t monotonic_ns() {
  return std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::steady_clock::now().time_since_epoch())
      .count();
}
/// Cooperative work budget; it never cancels a blocked native operation.
class Budget {
 public:
  /// Starts a100ms bounded operation counter.
  /// @param clock Monotonic source, borrowed for this call only.
  /// @param limit Maximum native/JNI/iteration operations.
  explicit Budget(Clock clock = monotonic_ns, std::size_t limit = 131072)
      : clock_(clock), limit_(limit), start_(clock_ != nullptr ? clock_() : -1), previous_(start_) {
    if (start_ < 0) {
      error_ = Error::kIo;
    }
  }
  /// Reserves one operation before performing it; failure is sticky.
  /// @return Whether the operation remains inside time and count bounds.
  [[nodiscard]] bool step() {
    if (error_ != Error::kNone) {
      return false;
    }
    const auto now = clock_();
    if (now < previous_ || now < 0) {
      error_ = Error::kIo;
    } else if (now - start_ >= 100000000) {
      error_ = Error::kDeadline;
    } else if (operations_ == limit_) {
      error_ = Error::kInputLimit;
    }
    previous_ = now;
    if (error_ != Error::kNone) {
      return false;
    }
    ++operations_;
    return true;
  }
  /// Returns the first work-budget failure, or none.
  [[nodiscard]] Error error() const { return error_; }

 private:
  Clock clock_;
  std::size_t limit_;
  std::size_t operations_ = 0;
  std::int64_t start_;
  std::int64_t previous_;
  Error error_ = Error::kNone;
};
/// Public location roots are lexical evidence, not trusted ownership.
struct Locations {
  std::vector<std::string> apk_paths;
  std::string native_directory;
  std::string bundle_directory;
  bool available = false;
};
/// Complete source accounting; counts are omitted on a failed source.
struct Metadata {
  std::size_t seen = 0;
  std::size_t eligible = 0;
  bool scope_available = false;
  std::string_view correlation = "unavailable";
  std::string_view stability = "na";
};
/// Two fixed output identities, including explicit failure metadata.
using Pair = std::array<Observation, 2>;
/// Validates every reduced row against producer wire limits before constructing a value.
[[nodiscard]] inline Error row_error(std::string_view signal, const std::vector<std::string>& rows, Metadata metadata) {
  const std::size_t cap = signal == "hook.loader_chain" ? 16 : 32;
  const std::size_t row_cap = signal == "hook.loader_chain" ? 96 : 192;
  if (rows.size() > cap || metadata.seen > 8192 || metadata.eligible > 8192) {
    return Error::kInputLimit;
  }
  for (const auto& row : rows) {
    if (row.size() > row_cap) {
      return Error::kInputLimit;
    }
    for (const auto byte : row) {
      if (byte < 32 || byte > 126) {
        return Error::kMalformed;
      }
    }
  }
  return Error::kNone;
}
/// Converts a validated collection failure to the existing four-value observation status.
[[nodiscard]] inline Status status(Error error) {
  if (error == Error::kNone) {
    return Status::kOk;
  }
  if (error == Error::kPlatform || error == Error::kContextAbsent || error == Error::kNativeUnavailable) {
    return Status::kUnsupported;
  }
  return error == Error::kDeadline ? Status::kTimeout : Status::kError;
}
/// Formats only fixed diagnostic labels and bounded counts, never native data.
[[nodiscard]] inline std::string metadata_text(Error error, std::size_t emitted, Metadata metadata) {
  constexpr std::array kReasons{
      "none", "platform", "context_absent", "native_unavailable", "denied", "io", "malformed", "input_limit",
      "jni",  "cleanup",  "race",           "deadline",
  };
  constexpr std::array kOutcomes{
      "complete",
      "unsupported",
      "error",
      "timeout",
  };
  const bool ok = error == Error::kNone;
  return "v=1;outcome=" + std::string(std::span(kOutcomes)[static_cast<std::size_t>(status(error))]) +
         ";reason=" + std::span(kReasons)[static_cast<std::size_t>(error)] +
         ";seen=" + (ok ? std::to_string(metadata.seen) : "na") +
         ";eligible=" + (ok ? std::to_string(metadata.eligible) : "na") + ";emitted=" + std::to_string(emitted) +
         ";sample_truncated=" + (ok && metadata.eligible > emitted ? "1" : "0") +
         ";scope=" + (metadata.scope_available ? "available" : "unavailable") +
         ";correlation=" + std::string(metadata.correlation) + ";stability=" + std::string(metadata.stability);
}
/// Reports one bounded reduced source; raw paths are never accepted as diagnostics.
/// @param signal Data identity; metadata appends `_meta`.
/// @param source Fixed source identity.
/// @param rows Owned bounded successful rows, or a collection error.
/// @param metadata Complete-source accounting.
/// @return A data/metadata pair with non-OK data carrying monostate.
[[nodiscard]] inline Pair pair(std::string_view signal, std::string_view source, Result<std::vector<std::string>> rows,
                               Metadata metadata = {}) {
  auto error = rows ? row_error(signal, *rows, metadata) : rows.error();
  if (static_cast<std::size_t>(error) > static_cast<std::size_t>(Error::kDeadline) ||
      (!rows && error == Error::kNone)) {
    error = Error::kIo;
  }
  const auto emitted = error == Error::kNone ? rows->size() : 0;
  return {
      Observation{
          .signal = std::string(signal),
          .source = std::string(source),
          .status = status(error),
          .value = error == Error::kNone ? Value(std::move(*rows)) : Value{},
      },
      observed(std::string(signal) + "_meta", source, metadata_text(error, emitted, metadata)),
  };
}
/// Checks a canonical absolute lexical path without resolving the filesystem.
/// @param path Borrowed path, maximum4096bytes.
/// @return Whether components are unambiguous and contain no controls or escapes.
[[nodiscard]] inline bool location_path(std::string_view path) {
  if (path.empty() || path.size() > 4096 || path.front() != '/' || path.back() == '/') {
    return false;
  }
  for (const auto byte : path) {
    if (static_cast<unsigned char>(byte) < 32 || byte == 127 || byte == '\\') {
      return false;
    }
  }
  std::size_t position = 1;
  while (position < path.size()) {
    const auto next = path.find('/', position);
    const auto component =
        path.substr(position, next == std::string_view::npos ? path.size() - position : next - position);
    if (component.empty() || component == "." || component == "..") {
      return false;
    }
    if (next == std::string_view::npos) {
      break;
    }
    position = next + 1;
  }
  return true;
}
/// Reduces a path to a lexical scope, without returning identifying bytes.
/// @param path Borrowed native path or loader name.
/// @param locations Bounded public app location metadata.
/// @param apple Whether to use Apple's OS location prefixes.
/// @return One of the four fixed scope labels.
[[nodiscard]] inline std::string_view scope(std::string_view path, const Locations& locations, bool apple = false) {
  if (!location_path(path)) {
    return "unresolved";
  }
  const auto child = [path](std::string_view root) {
    return !root.empty() && path.size() > root.size() && path.starts_with(root) && path[root.size()] == '/';
  };
  if (apple ? child("/System/Library") || child("/usr/lib")
            : child("/system") || child("/apex") || child("/vendor") || child("/product") || child("/odm") ||
                  child("/system_ext")) {
    return "os_location";
  }
  if (!locations.available) {
    return "unresolved";
  }
  if (apple && child(locations.bundle_directory)) {
    return "app_location";
  }
  if (!apple) {
    if (child(locations.native_directory)) {
      return "app_location";
    }
    for (const auto& apk : locations.apk_paths) {
      if (path == apk || (path.starts_with(apk) && path.substr(apk.size()).starts_with("!/lib/") &&
                          location_path(path.substr(apk.size() + 1)))) {
        return "app_location";
      }
    }
  }
  return "other_location";
}
/// Validates all public root bounds before any location classification.
/// @param locations Public metadata, or an explicitly unavailable set.
/// @return Whether the roots fit the complete-source contract.
[[nodiscard]] inline bool valid_locations(const Locations& locations) {
  if (!locations.available) {
    return true;
  }
  if (locations.apk_paths.size() > 65) {
    return false;
  }
  std::size_t size = locations.native_directory.size() + locations.bundle_directory.size();
  if ((!locations.native_directory.empty() && !location_path(locations.native_directory)) ||
      (!locations.bundle_directory.empty() && !location_path(locations.bundle_directory))) {
    return false;
  }
  for (const auto& path : locations.apk_paths) {
    if (!location_path(path) || path.size() > 262144 - size) {
      return false;
    }
    size += path.size();
  }
  return size <= 262144;
}
}  // namespace rasp::provenance
