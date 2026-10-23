/// The Android emulator checks: the build-property probe that reports emulator tells, and its unsupported result off
/// Android.

#include "checks/emulator.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "rasp/observation.h"

#ifdef __ANDROID__
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

/// The substrings that mark a property value as an emulator's. `=1` isn't needed: the QEMU flags are reported whenever
/// they are set at all, which only an emulator does.
constexpr auto kEmulatorMarkers = std::to_array<std::string_view>({
    "goldfish",
    "ranchu",
    "emulator",
    "generic",
    "sdk_gphone",
    "sdk_google",
    "sdk built for",
    "vbox",
    "genymotion",
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

/// Whether the property `value` holds an emulator marker, compared case-insensitively.
[[nodiscard]] bool holds_marker(std::string_view value) {
  std::string lowered(value);
  std::ranges::transform(lowered, lowered.begin(), [](char character) {
    return static_cast<char>(std::tolower(static_cast<unsigned char>(character)));
  });
  return std::ranges::any_of(kEmulatorMarkers,
                             [&lowered](std::string_view marker) { return lowered.contains(marker); });
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
/// Reads the system property `name` through the property store, or nothing when it is unset.
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
  if (value.empty()) {
    return std::nullopt;
  }
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
