/// Tests for load_install_id, which keeps the install id in a file.

#include "reporting/install_id.h"

#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <ios>
#include <iterator>
#include <string>
#include <string_view>
#include <system_error>
#include <unistd.h>

#include "rasp/util/uuid.h"

namespace rasp::ios {
namespace {

/// An empty temporary directory, removed with everything in it when the object goes away.
class TemporaryDirectory {
 public:
  /// Creates the directory. Its path is empty when it couldn't be created.
  TemporaryDirectory() {
    std::error_code error;
    std::string pattern = (std::filesystem::temp_directory_path(error) / "rasp-install-id-XXXXXX").string();
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

  /// The directory's path, empty when it couldn't be created.
  [[nodiscard]] const std::string& path() const { return path_; }

 private:
  /// The directory's path.
  std::string path_;
};

/// The path of the install id file in `directory`.
[[nodiscard]] std::string file_in(const std::string& directory) {
  return directory + "/" + std::string(kInstallIdFileName);
}

/// Writes `bytes` as the whole content of the file at `path`.
void write_file(const std::string& path, std::string_view bytes) {
  std::ofstream file(path, std::ios::binary);
  file.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
  ASSERT_TRUE(file.good());
}

/// Reads the whole content of the file at `path`, empty when it can't be opened.
[[nodiscard]] std::string read_file(const std::string& path) {
  std::ifstream file(path, std::ios::binary);
  return {std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>()};
}

/// The bytes of `id`, as a string, to compare with a file's content.
[[nodiscard]] std::string bytes_of(const Uuid& id) {
  std::string bytes;
  for (const auto byte : id.bytes) {
    bytes.push_back(static_cast<char>(byte));
  }
  return bytes;
}

TEST(InstallId, loadInstallId_whenNoIdIsStored_storesANewOneForTheNextLaunch) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());

  const Uuid first = load_install_id(directory.path());
  const Uuid second = load_install_id(directory.path());

  EXPECT_EQ(first, second);
  EXPECT_EQ(read_file(file_in(directory.path())), bytes_of(first));
  EXPECT_FALSE(std::filesystem::exists(file_in(directory.path()) + ".tmp"));
}

TEST(InstallId, loadInstallId_whenTheFileHoldsAnId_returnsIt) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  Uuid stored;
  std::ranges::fill(stored.bytes, std::uint8_t{0x5a});
  write_file(file_in(directory.path()), bytes_of(stored));

  EXPECT_EQ(load_install_id(directory.path()), stored);
}

TEST(InstallId, loadInstallId_whenTheDirectoryIsMissing_createsItAndStoresTheId) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  const std::string missing = directory.path() + "/support";

  const Uuid first = load_install_id(missing);

  EXPECT_TRUE(std::filesystem::is_directory(missing));
  EXPECT_EQ(load_install_id(missing), first);
}

TEST(InstallId, loadInstallId_whenTheFileIsNotSixteenBytesLong_replacesItWithANewId) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  write_file(file_in(directory.path()), "short");

  const Uuid first = load_install_id(directory.path());

  EXPECT_EQ(read_file(file_in(directory.path())), bytes_of(first));
  EXPECT_EQ(load_install_id(directory.path()), first);
}

TEST(InstallId, loadInstallId_whenTheFileCantBeRead_givesATemporaryIdAndLeavesTheFileUntouched) {
  if (geteuid() == 0) {
    GTEST_SKIP() << "root reads files without read permission";
  }
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  Uuid stored;
  std::ranges::fill(stored.bytes, std::uint8_t{0x5a});
  write_file(file_in(directory.path()), bytes_of(stored));
  std::error_code error;
  std::filesystem::permissions(file_in(directory.path()), std::filesystem::perms::none, error);
  ASSERT_FALSE(error);

  const Uuid first = load_install_id(directory.path());
  const Uuid second = load_install_id(directory.path());

  std::filesystem::permissions(file_in(directory.path()), std::filesystem::perms::owner_read, error);
  EXPECT_NE(first, stored);
  EXPECT_NE(first, second);
  EXPECT_EQ(read_file(file_in(directory.path())), bytes_of(stored));
}

}  // namespace
}  // namespace rasp::ios
