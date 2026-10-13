/// Tests for the iOS jailbreak checks.

#include "checks/jailbreak.h"

#include <array>
#include <cstdlib>
#include <fcntl.h>
#include <filesystem>
#include <gtest/gtest.h>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <system_error>
#include <unistd.h>
#include <vector>

#include "rasp/observation.h"

namespace rasp::ios::checks {
namespace {

/// An empty temporary directory, removed with everything in it when the object goes away.
class TemporaryDirectory {
 public:
  /// Creates the directory. Its path is empty when it couldn't be created.
  TemporaryDirectory() {
    std::error_code error;
    std::string pattern = (std::filesystem::temp_directory_path(error) / "rasp-jailbreak-XXXXXX").string();
    if (mkdtemp(pattern.data()) != nullptr) {
      path_ = pattern;
    }
  }
  /// Deleted: a copy would remove the same directory twice.
  TemporaryDirectory(const TemporaryDirectory&) = delete;
  /// Deleted: a copy would remove the same directory twice.
  TemporaryDirectory& operator=(const TemporaryDirectory&) = delete;
  /// Deleted: a moved-from object would still remove the directory.
  TemporaryDirectory(TemporaryDirectory&&) = delete;
  /// Deleted: a moved-from object would still remove the directory.
  TemporaryDirectory& operator=(TemporaryDirectory&&) = delete;
  /// Removes the directory and everything in it.
  ~TemporaryDirectory() {
    std::error_code error;
    std::filesystem::remove_all(path_, error);
  }

  /// The path of the directory, or empty when it couldn't be created.
  [[nodiscard]] const std::string& path() const { return path_; }

 private:
  /// The path of the directory.
  std::string path_;
};

/// Creates a one-byte file at `path`, failing the test when it can't.
void write_file(const std::string& path) {
  const int descriptor = creat(path.c_str(), S_IRUSR | S_IWUSR);
  ASSERT_GE(descriptor, 0);
  ASSERT_EQ(write(descriptor, "x", 1), 1);
  close(descriptor);
}

TEST(Jailbreak, observePaths_whenOnePathExists_reportsItThroughBothSources) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  const std::string present = directory.path() + "/present";
  const std::string missing = directory.path() + "/missing";
  write_file(present);
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
