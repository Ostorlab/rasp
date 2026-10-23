/// Tests for the Android emulator checks: the build-property probe that reports the properties whose value is an
/// emulator tell.

#include "checks/emulator.h"

#include <gtest/gtest.h>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "rasp/observation.h"

namespace rasp::android::checks {
namespace {

/// The emu.props observation that reports `properties`.
[[nodiscard]] Observation props(std::vector<std::string> properties) {
  return {.signal = "emu.props", .source = "system_property", .status = Status::kOk, .value = std::move(properties)};
}

/// A property reader for a real device: its build properties carry its own hardware and product names, no tell, and the
/// QEMU flags are unset.
[[nodiscard]] std::optional<std::string> real_device(std::string_view name) {
  if (name == "ro.hardware") {
    return "qcom";
  }
  if (name == "ro.product.model") {
    return "Pixel 8";
  }
  if (name == "ro.product.device") {
    return "shiba";
  }
  if (name == "ro.product.brand") {
    return "google";
  }
  return std::nullopt;
}

/// A property reader for the Android emulator: goldfish/ranchu hardware, an sdk_gphone model, and a set QEMU flag.
[[nodiscard]] std::optional<std::string> emulator_device(std::string_view name) {
  if (name == "ro.hardware") {
    return "ranchu";
  }
  if (name == "ro.product.model") {
    return "sdk_gphone64_x86_64";
  }
  if (name == "ro.kernel.qemu") {
    return "1";
  }
  return std::nullopt;
}

/// A property reader whose model carries an uppercase tell.
[[nodiscard]] std::optional<std::string> uppercase_tell(std::string_view name) {
  if (name == "ro.product.model") {
    return "Android SDK built for x86";
  }
  return std::nullopt;
}

/// A property reader whose only set property is the QEMU boot flag.
[[nodiscard]] std::optional<std::string> qemu_flag_only(std::string_view name) {
  if (name == "ro.boot.qemu") {
    return "1";
  }
  return std::nullopt;
}

TEST(Emulator, observeEmulatorProps_whenOnARealDevice_reportsNothing) {
  EXPECT_EQ(observe_emulator_props(real_device), props({}));
}

TEST(Emulator, observeEmulatorProps_whenOnTheEmulator_reportsTheTellProperties) {
  EXPECT_EQ(observe_emulator_props(emulator_device),
            props({"ro.hardware=ranchu", "ro.product.model=sdk_gphone64_x86_64", "ro.kernel.qemu=1"}));
}

TEST(Emulator, observeEmulatorProps_whenATellIsUppercase_matchesCaseInsensitively) {
  EXPECT_EQ(observe_emulator_props(uppercase_tell), props({"ro.product.model=Android SDK built for x86"}));
}

TEST(Emulator, observeEmulatorProps_whenOnlyAQemuFlagIsSet_reportsIt) {
  EXPECT_EQ(observe_emulator_props(qemu_flag_only), props({"ro.boot.qemu=1"}));
}

TEST(Emulator, emulator_whenOffAndroid_reportsTheCheckAsUnsupported) {
  EXPECT_EQ(emulator(),
            (std::vector<Observation>{
                {.signal = "emu.props", .source = "system_property", .status = Status::kUnsupported, .value = {}},
            }));
}

}  // namespace
}  // namespace rasp::android::checks
