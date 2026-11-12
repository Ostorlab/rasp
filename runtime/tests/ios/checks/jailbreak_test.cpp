/// Tests for the iOS jailbreak checks.

#include "checks/jailbreak.h"

#include <array>
#include <filesystem>
#include <gtest/gtest.h>
#include <string>
#include <string_view>
#include <unistd.h>
#include <vector>

#include "rasp/observation.h"
#include "support/files.h"

namespace rasp::ios::checks {
namespace {

using test_support::TemporaryDirectory;
using test_support::write_file;

TEST(Jailbreak, observePaths_whenOnePathExists_reportsItThroughBothSources) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  const std::string present = directory.path() + "/present";
  const std::string missing = directory.path() + "/missing";
  ASSERT_TRUE(write_file(present, "x"));
  const std::array<std::string_view, 2> paths = {present, missing};

  const std::vector<Observation> observations = observe_paths(paths);

  const std::vector<std::string> found = {present};
  EXPECT_EQ(observations, (std::vector<Observation>{
                              {.signal = "jb.fs_paths", .source = "access", .status = Status::kOk, .value = found},
                              {.signal = "jb.fs_paths", .source = "stat", .status = Status::kOk, .value = found},
                          }));
}

TEST(Jailbreak, observePaths_whenNoPathExists_reportsEmptyListsThroughBothSources) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  const std::string missing = directory.path() + "/missing";
  const std::array<std::string_view, 1> paths = {missing};

  const std::vector<Observation> observations = observe_paths(paths);

  const std::vector<std::string> none;
  EXPECT_EQ(observations, (std::vector<Observation>{
                              {.signal = "jb.fs_paths", .source = "access", .status = Status::kOk, .value = none},
                              {.signal = "jb.fs_paths", .source = "stat", .status = Status::kOk, .value = none},
                          }));
}

TEST(Jailbreak, observeSandboxWrite_whenWritable_reportsTrueAndRemovesTheProbe) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  const std::string probe = directory.path() + "/probe";

  const Observation observation = observe_sandbox_write(probe);

  EXPECT_EQ(observation,
            (Observation{.signal = "jb.sandbox_escape", .source = "open", .status = Status::kOk, .value = true}));
  EXPECT_FALSE(std::filesystem::exists(probe));
}

TEST(Jailbreak, observeSandboxWrite_whenRefused_reportsFalse) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  const std::string probe = directory.path() + "/missing-directory/probe";

  const Observation observation = observe_sandbox_write(probe);

  EXPECT_EQ(observation,
            (Observation{.signal = "jb.sandbox_escape", .source = "open", .status = Status::kOk, .value = false}));
}

TEST(Jailbreak, observePaths_whenLookupLoops_reportsErrorRatherThanClean) {
  const TemporaryDirectory directory;
  const std::string path = directory.path() + "/loop";
  ASSERT_EQ(symlink("loop", path.c_str()), 0);
  const std::array<std::string_view, 1> paths = {path};
  for (const auto& observation : observe_paths(paths)) {
    EXPECT_EQ(observation.status, Status::kError);
  }
}

TEST(Jailbreak, observeSandboxWrite_whenProbeExists_preservesExistingContent) {
  const TemporaryDirectory directory;
  const std::string path = directory.path() + "/existing";
  ASSERT_TRUE(write_file(path, "host-owned"));
  EXPECT_EQ(observe_sandbox_write(path).status, Status::kError);
  EXPECT_EQ(test_support::read_file(path), "host-owned");
}

TEST(Jailbreak, observeFork_whenForkIsAllowed_reportsTrue) {
  EXPECT_EQ(observe_fork(),
            (Observation{.signal = "jb.fork_ok", .source = "fork", .status = Status::kOk, .value = true}));
}

TEST(Jailbreak, jailbreak_whenOffAPhysicalDevice_reportsEveryCheckAsUnsupported) {
  EXPECT_EQ(jailbreak(),
            (std::vector<Observation>{
                {.signal = "jb.fs_paths", .source = "access", .status = Status::kUnsupported, .value = {}},
                {.signal = "jb.fs_paths", .source = "stat", .status = Status::kUnsupported, .value = {}},
                {.signal = "jb.sandbox_escape", .source = "open", .status = Status::kUnsupported, .value = {}},
                {.signal = "jb.fork_ok", .source = "fork", .status = Status::kUnsupported, .value = {}},
            }));
}

}  // namespace
}  // namespace rasp::ios::checks
