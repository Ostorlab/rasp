/// Tests for the iOS emulator check.

#include "checks/emulator.h"

#include <gtest/gtest.h>
#include <vector>

#include "rasp/observation.h"

namespace rasp::ios::checks {
namespace {

TEST(Emulator, observeMachineTell_whenSimulatorArchitecture_reportsTrue) {
  EXPECT_EQ(observe_machine_tell("x86_64"),
            (Observation{.signal = "emu.simulator", .source = "sysctl", .status = Status::kOk, .value = true}));
  EXPECT_EQ(observe_machine_tell("arm64"),
            (Observation{.signal = "emu.simulator", .source = "sysctl", .status = Status::kOk, .value = true}));
}

TEST(Emulator, observeMachineTell_whenDeviceModel_reportsFalse) {
  EXPECT_EQ(observe_machine_tell("iPhone15,2"),
            (Observation{.signal = "emu.simulator", .source = "sysctl", .status = Status::kOk, .value = false}));
  EXPECT_EQ(observe_machine_tell("iPad13,1"),
            (Observation{.signal = "emu.simulator", .source = "sysctl", .status = Status::kOk, .value = false}));
}

TEST(Emulator, observeMachineTell_whenEmpty_reportsFalse) {
  EXPECT_EQ(observe_machine_tell(""),
            (Observation{.signal = "emu.simulator", .source = "sysctl", .status = Status::kOk, .value = false}));
}

TEST(Emulator, observeMachineTell_whenModelEmbedsArchitecture_reportsFalse) {
  EXPECT_EQ(observe_machine_tell("arm64e_device"),
            (Observation{.signal = "emu.simulator", .source = "sysctl", .status = Status::kOk, .value = false}));
}

#ifndef __APPLE__
TEST(Emulator, emulator_whenOffAnAppleHost_reportsEveryTellAsUnsupported) {
  EXPECT_EQ(
      emulator(),
      (std::vector<Observation>{
          {.signal = "emu.simulator", .source = "target_conditionals", .status = Status::kUnsupported, .value = {}},
          {.signal = "emu.simulator", .source = "sysctl", .status = Status::kUnsupported, .value = {}},
      }));
}
#endif

}  // namespace
}  // namespace rasp::ios::checks
