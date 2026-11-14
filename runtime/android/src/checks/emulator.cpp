/// The Android emulator checks: the build-property probe that reports emulator tells, and its unsupported result off
/// Android.

#include "checks/emulator.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "rasp/observation.h"
#include "util/system_property.h"

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

/// The substrings that mark a property value as an emulator's. `generic` and `sdk` are left out: they are matched as
/// whole tokens instead (see kTokenMarkers), because real values embed them in longer words such as `aosp_generic_x86`.
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

/// The emulator markers matched as whole tokens rather than substrings. `generic` is the stock emulator's product name,
/// but `aosp_generic_x86` on a real AOSP device only contains it; `sdk` is the classic emulator's product name and
/// model, but a real value can embed it in a longer token. Matching them bounded by non-token characters avoids both.
constexpr auto kTokenMarkers = std::to_array<std::string_view>({
    "generic",
    "sdk",
});

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
/// anywhere; the token markers (`generic`, `sdk`) match only as whole tokens.
[[nodiscard]] bool holds_marker(std::string_view value) {
  std::string lowered(value);
  std::ranges::transform(lowered, lowered.begin(), [](char character) {
    return static_cast<char>(std::tolower(static_cast<unsigned char>(character)));
  });
  if (std::ranges::any_of(kEmulatorMarkers, [&lowered](std::string_view marker) { return lowered.contains(marker); })) {
    return true;
  }
  return std::ranges::any_of(kTokenMarkers,
                             [&lowered](std::string_view marker) { return holds_token(lowered, marker); });
}

}  // namespace

Observation observe_emulator_props(util::PropertyReader read_property) {
  std::vector<std::string> properties;
  std::ranges::for_each(kEmulatorProperties, [&](const std::string_view name) {
    const std::optional<std::string> value = read_property(name);
    if (!value) {
      return;
    }
    if (is_qemu_flag(name) || holds_marker(*value)) {
      properties.push_back(std::string(name) + "=" + *value);
    }
  });
  return observed(kPropsSignal, kPropsSource, std::move(properties));
}

std::vector<Observation> emulator() {
  if (!kOnAndroid) {
    return {unsupported(kPropsSignal, kPropsSource)};
  }
  return {observe_emulator_props(util::read_system_property)};
}

}  // namespace rasp::android::checks
