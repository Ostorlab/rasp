#include "rasp/checks/ios/jailbreak.h"

#include <array>
#include <fcntl.h>
#include <filesystem>
#include <gtest/gtest.h>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

#include "rasp/observation.h"

namespace rasp::checks::ios {
namespace {

class Jailbreak : public testing::Test {
 protected:
  void SetUp() override {
    directory_ =
        std::filesystem::path(testing::TempDir()) / testing::UnitTest::GetInstance()->current_test_info()->name();
    std::filesystem::remove_all(directory_);
    std::filesystem::create_directories(directory_);
  }

  void TearDown() override { std::filesystem::remove_all(directory_); }

  [[nodiscard]] const std::filesystem::path& directory() const { return directory_; }

 private:
  std::filesystem::path directory_;
};

void write_file(const std::string& path) {
  const int descriptor = creat(path.c_str(), S_IRUSR | S_IWUSR);
  ASSERT_GE(descriptor, 0);
  ASSERT_EQ(write(descriptor, "x", 1), 1);
  close(descriptor);
}

TEST_F(Jailbreak, observePaths_whenOnePathExists_reportsItThroughBothSources) {
  const std::string present = (directory() / "present").string();
  const std::string missing = (directory() / "missing").string();
  write_file(present);
  const std::array<std::string_view, 2> paths = {present, missing};

  const std::vector<Observation> observations = observe_paths(paths);

  const std::vector<std::string> found = {present};
  EXPECT_EQ(observations, (std::vector<Observation>{
                              {.signal = "jb.fs_paths", .source = "access", .status = Status::kOk, .value = found},
                              {.signal = "jb.fs_paths", .source = "stat", .status = Status::kOk, .value = found},
                          }));
}

TEST_F(Jailbreak, observeSandboxWrite_whenWritable_reportsTrueAndRemovesTheProbe) {
  const std::string probe = (directory() / "probe").string();

  const Observation observation = observe_sandbox_write(probe);

  EXPECT_EQ(observation,
            (Observation{.signal = "jb.sandbox_escape", .source = "open", .status = Status::kOk, .value = true}));
  EXPECT_FALSE(std::filesystem::exists(probe));
}

TEST_F(Jailbreak, observeSandboxWrite_whenRefused_reportsFalse) {
  const std::string probe = (directory() / "missing-directory" / "probe").string();

  const Observation observation = observe_sandbox_write(probe);

  EXPECT_EQ(observation,
            (Observation{.signal = "jb.sandbox_escape", .source = "open", .status = Status::kOk, .value = false}));
}

TEST_F(Jailbreak, observeFork_whenForkIsAllowed_reportsTrue) {
  EXPECT_EQ(observe_fork(),
            (Observation{.signal = "jb.fork_ok", .source = "fork", .status = Status::kOk, .value = true}));
}

TEST_F(Jailbreak, jailbreak_whenOffAPhysicalDevice_reportsEveryCheckAsUnsupported) {
  EXPECT_EQ(jailbreak(),
            (std::vector<Observation>{
                {.signal = "jb.fs_paths", .source = "access", .status = Status::kUnsupported, .value = {}},
                {.signal = "jb.fs_paths", .source = "stat", .status = Status::kUnsupported, .value = {}},
                {.signal = "jb.sandbox_escape", .source = "open", .status = Status::kUnsupported, .value = {}},
                {.signal = "jb.fork_ok", .source = "fork", .status = Status::kUnsupported, .value = {}},
            }));
}

}  // namespace
}  // namespace rasp::checks::ios
