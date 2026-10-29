/// Tests for the installation id: generate, persist, and reload.

#include "rasp/install_id.h"

#include <array>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <gtest/gtest.h>
#include <optional>
#include <string>

namespace rasp {
namespace {

/// A temporary directory that is removed when the test ends.
class TempDir {
 public:
  TempDir() {
    std::string pattern = std::filesystem::temp_directory_path().string() + "/rasp_test_XXXXXX";
    char* result = mkdtemp(pattern.data());
    if (result != nullptr) {
      path_ = result;
    }
  }

  ~TempDir() {
    if (!path_.empty()) {
      std::filesystem::remove_all(path_);
    }
  }

  TempDir(const TempDir&) = delete;
  TempDir& operator=(const TempDir&) = delete;

  [[nodiscard]] const std::string& path() const { return path_; }

 private:
  std::string path_;
};

TEST(InstallId, getOrCreate_whenNoFileExists_generatesAndPersistsAnId) {
  TempDir dir;
  ASSERT_FALSE(dir.path().empty());

  const std::optional<InstallId> id = get_or_create_install_id(dir.path());

  ASSERT_TRUE(id.has_value());
  // UUID v4: version nibble must be 0x4, variant bits must be 0b10.
  EXPECT_EQ(((*id)[6] >> 4U) & 0x0FU, 0x04U);
  EXPECT_EQ(((*id)[8] >> 6U) & 0x03U, 0x02U);
}

TEST(InstallId, getOrCreate_whenCalledTwice_returnsSameId) {
  TempDir dir;
  ASSERT_FALSE(dir.path().empty());

  const std::optional<InstallId> first = get_or_create_install_id(dir.path());
  const std::optional<InstallId> second = get_or_create_install_id(dir.path());

  ASSERT_TRUE(first.has_value());
  ASSERT_TRUE(second.has_value());
  EXPECT_EQ(*first, *second);
}

TEST(InstallId, getOrCreate_whenDirDoesNotExist_returnsNothing) {
  const std::optional<InstallId> id = get_or_create_install_id("/nonexistent/path");

  EXPECT_FALSE(id.has_value());
}

TEST(InstallId, getOrCreate_whenFileIsCorrupt_replacesIt) {
  TempDir dir;
  ASSERT_FALSE(dir.path().empty());

  const std::string file = dir.path() + "/.rasp_install_id";
  FILE* f = std::fopen(file.c_str(), "w");
  ASSERT_NE(f, nullptr);
  std::fputs("corrupt", f);
  std::fclose(f);

  const std::optional<InstallId> id = get_or_create_install_id(dir.path());

  ASSERT_TRUE(id.has_value());
  EXPECT_EQ(((*id)[6] >> 4U) & 0x0FU, 0x04U);
}

TEST(InstallId, getOrCreate_whenTwoDifferentDirs_generatesDifferentIds) {
  TempDir dir1;
  TempDir dir2;
  ASSERT_FALSE(dir1.path().empty());
  ASSERT_FALSE(dir2.path().empty());

  const std::optional<InstallId> id1 = get_or_create_install_id(dir1.path());
  const std::optional<InstallId> id2 = get_or_create_install_id(dir2.path());

  ASSERT_TRUE(id1.has_value());
  ASSERT_TRUE(id2.has_value());
  EXPECT_NE(*id1, *id2);
}

}  // namespace
}  // namespace rasp
