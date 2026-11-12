/// Tests for the iOS code-signing status check.

#include "checks/codesign.h"

#include <cstdint>
#include <gtest/gtest.h>
#include <vector>

#include "rasp/observation.h"

namespace rasp::ios::checks {
namespace {

/// The `CS_*` status flags the check reports, mirrored from codesign.cpp so the tests set known inputs.
constexpr std::uint32_t kCsValid = 0x00000001;
constexpr std::uint32_t kCsGetTaskAllow = 0x00000004;
constexpr std::uint32_t kCsRequireLibraryValidation = 0x00002000;
constexpr std::uint32_t kCsDebugged = 0x10000000;

TEST(Codesign, observeCodesign_whenNoFlagIsSet_reportsEverySignalFalse) {
  EXPECT_EQ(observe_codesign(0),
            (std::vector<Observation>{
                {.signal = "cs.valid", .source = "csops", .status = Status::kOk, .value = false},
                {.signal = "cs.debugged", .source = "csops", .status = Status::kOk, .value = false},
                {.signal = "cs.get_task_allow", .source = "csops", .status = Status::kOk, .value = false},
                {.signal = "cs.library_validation", .source = "csops", .status = Status::kOk, .value = false},
            }));
}

TEST(Codesign, observeCodesign_whenEveryFlagIsSet_reportsEverySignalTrue) {
  const std::uint32_t flags = kCsValid | kCsGetTaskAllow | kCsRequireLibraryValidation | kCsDebugged;
  EXPECT_EQ(observe_codesign(flags),
            (std::vector<Observation>{
                {.signal = "cs.valid", .source = "csops", .status = Status::kOk, .value = true},
                {.signal = "cs.debugged", .source = "csops", .status = Status::kOk, .value = true},
                {.signal = "cs.get_task_allow", .source = "csops", .status = Status::kOk, .value = true},
                {.signal = "cs.library_validation", .source = "csops", .status = Status::kOk, .value = true},
            }));
}

TEST(Codesign, observeCodesign_whenOnlyDebuggedIsSet_reportsDebuggedTrueAndTheRestFalse) {
  EXPECT_EQ(observe_codesign(kCsDebugged),
            (std::vector<Observation>{
                {.signal = "cs.valid", .source = "csops", .status = Status::kOk, .value = false},
                {.signal = "cs.debugged", .source = "csops", .status = Status::kOk, .value = true},
                {.signal = "cs.get_task_allow", .source = "csops", .status = Status::kOk, .value = false},
                {.signal = "cs.library_validation", .source = "csops", .status = Status::kOk, .value = false},
            }));
}

TEST(Codesign, codesign_whenOffAPhysicalDevice_reportsEverySignalAsUnsupported) {
  EXPECT_EQ(codesign(),
            (std::vector<Observation>{
                {.signal = "cs.valid", .source = "csops", .status = Status::kUnsupported, .value = {}},
                {.signal = "cs.debugged", .source = "csops", .status = Status::kUnsupported, .value = {}},
                {.signal = "cs.get_task_allow", .source = "csops", .status = Status::kUnsupported, .value = {}},
                {.signal = "cs.library_validation", .source = "csops", .status = Status::kUnsupported, .value = {}},
            }));
}

}  // namespace
}  // namespace rasp::ios::checks
