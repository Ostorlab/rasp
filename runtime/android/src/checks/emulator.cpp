/// The Android emulator checks: the build-property probe that reports emulator tells, and its unsupported result off
/// Android.

#include "checks/emulator.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "rasp/observation.h"

#ifdef __ANDROID__
#include <cstdint>
#include <sys/system_properties.h>
#endif

namespace rasp::android::checks {

namespace {

#ifdef __ANDROID__
/// Whether this build runs on Android, the only place the probe means anything.
constexpr bool kOnAndroid = true;
#else
/// Whether this build runs on Android, the only place the probe means anything.
constexpr bool kOnAndroid = false;
#endif

/// The signal of the build-property probe.
constexpr std::string_view kPropsSignal = "emu.props";
/// The source of the build-property probe.
constexpr std::string_view kPropsSource = "system_property";

/// The build properties the probe reads. Each one's value, on an emulator, carries a tell such as `goldfish` or `sdk`.
constexpr auto kEmulatorProperties = std::to_array<std::string_view>({
    "ro.hardware",
    "ro.product.model",
    "ro.product.device",
    "ro.product.name",
    "ro.product.brand",
    "ro.kernel.qemu",
    "ro.boot.qemu",
    "ro.boot.hardware",
    "ro.build.characteristics",
});

/// The substrings that mark a property value as an emulator's. `generic` is left out: it is matched as a whole token
/// instead, because real AOSP-based devices use product values such as `aosp_generic_x86` that only contain it.
constexpr auto kEmulatorMarkers = std::to_array<std::string_view>({
    "goldfish",
    "ranchu",
    "emulator",
    "sdk_gphone",
    "sdk_google",
    "sdk built for",
    "vbox",
    "genymotion",
});

/// The emulator marker matched as a whole token rather than a substring.
constexpr std::string_view kGenericMarker = "generic";

/// The QEMU flag properties, which a real device leaves unset: any value at all is a tell.
constexpr auto kQemuProperties = std::to_array<std::string_view>({
    "ro.kernel.qemu",
    "ro.boot.qemu",
});

/// Whether `name` is a QEMU flag property, whose mere presence is a tell.
[[nodiscard]] bool is_qemu_flag(std::string_view name) {
  return std::ranges::any_of(kQemuProperties, [name](std::string_view flag) { return flag == name; });
}

/// Whether `character` is part of an identifier token: a letter, a digit or an underscore. A product value joins its
/// parts with underscores, so `generic` inside `aosp_generic_x86` is one token with its neighbours, not a token on its
/// own. A marker that is a whole token is bounded by characters that aren't token characters, or by the ends of the
/// string.
[[nodiscard]] bool is_token_character(char character) {
  const auto byte = static_cast<unsigned char>(character);
  return std::isalnum(byte) != 0 || character == '_';
}

/// Whether `text` holds `token` bounded by non-token characters or the ends of the string, so `generic` matches
/// `vbox generic` but not `aosp_generic_x86`.
[[nodiscard]] bool holds_token(std::string_view text, std::string_view token) {
  std::size_t position = text.find(token);
  while (position != std::string_view::npos) {
    const bool left = position == 0 || !is_token_character(text[position - 1]);
    const std::size_t after = position + token.size();
    const bool right = after == text.size() || !is_token_character(text[after]);
    if (left && right) {
      return true;
    }
    position = text.find(token, position + 1);
  }
  return false;
}

/// Whether the property `value` holds an emulator marker, compared case-insensitively. The substring markers match
/// anywhere; `generic` matches only as a whole token.
[[nodiscard]] bool holds_marker(std::string_view value) {
  std::string lowered(value);
  std::ranges::transform(lowered, lowered.begin(), [](char character) {
    return static_cast<char>(std::tolower(static_cast<unsigned char>(character)));
  });
  if (std::ranges::any_of(kEmulatorMarkers, [&lowered](std::string_view marker) { return lowered.contains(marker); })) {
    return true;
  }
  return holds_token(lowered, kGenericMarker);
}

}  // namespace

Observation observe_emulator_props(PropertyReader read_property) {
  std::vector<std::string> properties;
  for (const std::string_view name : kEmulatorProperties) {
    const std::optional<std::string> value = read_property(name);
    if (!value) {
      continue;
    }
    if (is_qemu_flag(name) || holds_marker(*value)) {
      properties.push_back(std::string(name) + "=" + *value);
    }
  }
  return observed(kPropsSignal, kPropsSource, std::move(properties));
}

namespace {

#ifdef __ANDROID__
/// Reads the system property `name` through the property store, or nothing when it is unset. A property that is set but
/// empty returns the empty string, not nothing, so a bare QEMU flag is still reported.
[[nodiscard]] std::optional<std::string> read_system_property(std::string_view name) {
  const std::string key(name);
  const prop_info* const info = __system_property_find(key.c_str());
  if (info == nullptr) {
    return std::nullopt;
  }
  std::string value;
  __system_property_read_callback(
      info,
      [](void* cookie, const char* /*name*/, const char* property_value, std::uint32_t /*serial*/) {
        *static_cast<std::string*>(cookie) = property_value;
      },
      &value);
  return value;
}
#else
/// Off Android there is no property store.
[[nodiscard]] std::optional<std::string> read_system_property([[maybe_unused]] std::string_view name) {
  return std::nullopt;
}
#endif

}  // namespace

std::vector<Observation> emulator() {
  if (!kOnAndroid) {
    return {unsupported(kPropsSignal, kPropsSource)};
  }
  return {observe_emulator_props(read_system_property)};
}

}  // namespace rasp::android::checks
