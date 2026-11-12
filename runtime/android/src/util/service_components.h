/// Bounded structural component records shared by the public Android metadata collectors.

#pragma once

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace rasp::android::util {
/// Maximum raw list entries, including duplicates, per observation.
inline constexpr std::size_t kMaxComponents = 128;
/// Maximum raw and normalized ASCII bytes per component, excluding accessibility flag suffixes.
inline constexpr std::size_t kMaxComponentBytes = 1024;
/// Maximum raw setting and summed complete record bytes, independently, per observation.
inline constexpr std::size_t kMaxObservationBytes = 131072;
/// Validates and expands a flattened component without truncating.
/// @param raw Package/class, optionally using a relative class name.
/// @return Canonical package/fully.qualified.Class, or nothing for invalid/over-limit names.
[[nodiscard]] std::optional<std::string> normalize_component(std::string_view raw);
/// Parses the AndroidX-compatible colon-separated setting with no partial-success result.
/// @param raw Explicit non-null setting bytes; empty is a valid empty list.
/// @return Sorted unique canonical components, or nothing for malformed/over-limit input.
[[nodiscard]] std::optional<std::vector<std::string>> parse_notification_components(std::string_view raw);
}  // namespace rasp::android::util
