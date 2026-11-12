/// Strict bounded normalization of Android component metadata, independent of JNI ownership.

#include "util/service_components.h"

#include <algorithm>
#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace rasp::android::util {
namespace {
/// Validates dot-separated ASCII Java names without accepting separators from the record format.
[[nodiscard]] bool valid_name(std::string_view name) {
  bool start = true;
  for (const char character : name) {
    if (character == '.') {
      if (start) {
        return false;
      }
      start = true;
    } else {
      const bool letter = (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
                          character == '_' || character == '$';
      if (!letter && (start || character < '0' || character > '9')) {
        return false;
      }
      start = false;
    }
  }
  return !start;
}

}  // namespace

/// Normalizes ComponentName's package/relative-class representation into package/fully.qualified.Class.
[[nodiscard]] std::optional<std::string> normalize_component(std::string_view raw) {
  const std::size_t slash = raw.find('/');
  if (slash == std::string_view::npos || raw.size() > kMaxComponentBytes) {
    return std::nullopt;
  }
  const std::string_view package = raw.substr(0, slash);
  const std::string_view component = raw.substr(slash + 1);
  if (!valid_name(package) || component.empty()) {
    return std::nullopt;
  }
  const bool relative = component.starts_with('.');
  if (!valid_name(relative ? component.substr(1) : component)) {
    return std::nullopt;
  }
  std::string result(package);
  result += '/';
  if (relative) {
    result += package;
  }
  result += component;
  return result.size() <= kMaxComponentBytes ? std::optional(std::move(result)) : std::nullopt;
}

std::optional<std::vector<std::string>> parse_notification_components(std::string_view raw) {
  if (raw.size() > kMaxObservationBytes) {
    return std::nullopt;
  }
  std::vector<std::string> result;
  if (raw.empty()) {
    return result;
  }
  std::size_t start = 0;
  std::size_t bytes = 0;
  while (start <= raw.size()) {
    if (result.size() == kMaxComponents) {
      return std::nullopt;
    }
    const std::size_t end = raw.find(':', start);
    auto component = normalize_component(raw.substr(start, end == std::string::npos ? end : end - start));
    if (!component.has_value() || component->size() > kMaxObservationBytes - bytes) {
      return std::nullopt;
    }
    bytes += component->size();
    result.push_back(std::move(*component));
    if (end == std::string::npos) {
      break;
    }
    start = end + 1;
  }
  std::ranges::sort(result);
  const auto duplicates = std::ranges::unique(result);
  result.erase(duplicates.begin(), duplicates.end());
  return result;
}
}  // namespace rasp::android::util
