/// Tests for load_or_create_install_id, which reads the install id kept in a folder, or creates and keeps one.

#include "rasp/install_id.h"

#include <array>
#include <chrono>
#include <cstddef>
#include <fcntl.h>
#include <filesystem>
#include <gtest/gtest.h>
#include <latch>
#include <optional>
#include <spawn.h>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>
#include <vector>

#include "rasp/util/read_file.h"
#include "support/files.h"

namespace rasp {
namespace {

using test_support::TemporaryDirectory;
using test_support::write_file;

/// An id as load_or_create_install_id writes it.
constexpr std::string_view kKeptId = "0f8e5b8e-6c1a-4b7e-9d3a-2a4c5e6f7a8b";

/// The path of the install id's file in `directory`.
[[nodiscard]] std::string id_path(const TemporaryDirectory& directory) {
  return directory.path() + "/" + std::string(kInstallIdFileName);
}

/// Whether `id` is the text of a version 4 UUID with the RFC variant, in lowercase.
[[nodiscard]] bool is_uuid_v4(std::string_view id) {
  constexpr std::string_view kHexDigits = "0123456789abcdef";
  if (id.size() != 36 || id[8] != '-' || id[13] != '-' || id[18] != '-' || id[23] != '-' || id[14] != '4' ||
      !std::string_view("89ab").contains(id[19])) {
    return false;
  }
  for (std::size_t index = 0; index < id.size(); ++index) {
    if (index != 8 && index != 13 && index != 18 && index != 23 && !kHexDigits.contains(id[index])) {
      return false;
    }
  }
  return true;
}

TEST(InstallId, loadOrCreateInstallId_whenNoIdIsKept_createsAUuidV4AndKeepsIt) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());

  const std::optional<std::string> id = load_or_create_install_id(directory.path());

  ASSERT_TRUE(id.has_value());
  EXPECT_TRUE(is_uuid_v4(*id)) << *id;
  EXPECT_EQ(util::read_file(id_path(directory), 64), id);
}

TEST(InstallId, loadOrCreateInstallId_whenAnIdIsKept_returnsIt) {
  const TemporaryDirectory directory;
  ASSERT_TRUE(write_file(id_path(directory), kKeptId));

  const std::optional<std::string> id = load_or_create_install_id(directory.path());

  EXPECT_EQ(id, kKeptId);
}

TEST(InstallId, loadOrCreateInstallId_whenCalledAgain_returnsTheSameId) {
  const TemporaryDirectory directory;
  const std::optional<std::string> first = load_or_create_install_id(directory.path());

  const std::optional<std::string> second = load_or_create_install_id(directory.path());

  ASSERT_TRUE(first.has_value());
  EXPECT_EQ(second, first);
}

TEST(InstallId, loadOrCreateInstallId_whenTwoInstallsCreateAnId_givesThemDifferentIds) {
  const TemporaryDirectory first_install;
  const TemporaryDirectory second_install;

  const std::optional<std::string> first = load_or_create_install_id(first_install.path());
  const std::optional<std::string> second = load_or_create_install_id(second_install.path());

  ASSERT_TRUE(first.has_value());
  ASSERT_TRUE(second.has_value());
  EXPECT_NE(*first, *second);
}

/// Bounds the concurrent fixture beyond the legacy API's own finite busy-contention budget.
std::optional<std::string> retry_identity(std::string_view directory) {
  for (int attempt = 0; attempt < 100; ++attempt) {
    auto identity = load_or_create_install_id(directory);
    if (identity.has_value()) {
      return identity;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }
  return std::nullopt;
}

TEST(InstallId, loadOrCreateInstallId_whenProcessesCreateAnIdAtOnce_givesThemAllTheKeptId) {
  constexpr std::size_t kProcesses = 2;
  const TemporaryDirectory directory;
  std::array<std::optional<std::string>, kProcesses> ids;
  std::latch start(kProcesses);
  std::vector<std::thread> processes;
  processes.reserve(kProcesses);

  for (std::optional<std::string>& id : ids) {
    processes.emplace_back([&directory, &start, &id] {
      start.arrive_and_wait();
      id = retry_identity(directory.path());
    });
  }
  for (std::thread& process : processes) {
    process.join();
  }

  const std::optional<std::string> kept = util::read_file(id_path(directory), 64);
  ASSERT_TRUE(kept.has_value());
  for (const std::optional<std::string>& id : ids) {
    EXPECT_EQ(id, kept);
  }
  for (const std::filesystem::directory_entry& entry : std::filesystem::directory_iterator(directory.path())) {
    EXPECT_NE(entry.path().extension(), ".tmp") << entry.path();
  }
}

TEST(InstallId, loadOrCreateInstallId_whenACrashLeftATemporaryFile_reusesItsName) {
  const TemporaryDirectory directory;
  ASSERT_TRUE(write_file(id_path(directory) + ".private.tmp", "0f8e5b8e-6c1a"));

  const std::optional<std::string> id = load_or_create_install_id(directory.path());

  ASSERT_TRUE(id.has_value());
  EXPECT_EQ(util::read_file(id_path(directory), 64), id);
  for (const std::filesystem::directory_entry& entry : std::filesystem::directory_iterator(directory.path())) {
    EXPECT_NE(entry.path().extension(), ".tmp") << entry.path();
  }
}

TEST(InstallId, loadOrCreateInstallId_whenTheKeptFileIsNotAnId_preservesItAndReturnsUnavailable) {
  for (const std::string_view kept : {
           std::string_view(""),
           std::string_view("not an id"),
           std::string_view("00000000-0000-0000-0000-000000000000"),
           std::string_view("0F8E5B8E-6C1A-4B7E-9D3A-2A4C5E6F7A8B"),
           std::string_view("0f8e5b8e-6c1a-4b7e-9d3a-2a4c5e6f7a8b\n"),
       }) {
    const TemporaryDirectory directory;
    ASSERT_TRUE(write_file(id_path(directory), kept));

    const std::optional<std::string> id = load_or_create_install_id(directory.path());

    EXPECT_FALSE(id.has_value()) << kept;
    EXPECT_EQ(util::read_file(id_path(directory), 64), kept);
  }
}

/// Spawns a separate lock owner and waits for its ready byte, closing both pipe ends on every path.
[[nodiscard]] std::optional<pid_t> spawn_lock_holder(const std::string& root, bool short_lock) {
  std::array<int, 2> ready{};
  if (pipe(ready.data()) != 0) {
    return std::nullopt;
  }
  posix_spawn_file_actions_t actions;
  if (posix_spawn_file_actions_init(&actions) != 0) {
    static_cast<void>(close(ready[0]));
    static_cast<void>(close(ready[1]));
    return std::nullopt;
  }
  const std::string lock_path = root + "/rasp_install_id.lock";
  const bool prepared = posix_spawn_file_actions_adddup2(&actions, ready[1], STDOUT_FILENO) == 0 &&
                        posix_spawn_file_actions_addclose(&actions, ready[0]) == 0 &&
                        posix_spawn_file_actions_addclose(&actions, ready[1]) == 0 &&
                        posix_spawn_file_actions_addopen(&actions, 3, lock_path.c_str(), O_RDWR, 0) == 0;
  std::string executable = RASP_STORAGE_PROBE;
  std::string path = root;
  std::string mode = short_lock ? "--lock-short" : "--lock-long";
  std::string unused;
  std::array<char*, 5> arguments{executable.data(), path.data(), mode.data(), unused.data(), nullptr};
  std::array<char*, 1> environment{nullptr};
  pid_t child = -1;
  const bool spawned =
      prepared && posix_spawn(&child, executable.c_str(), &actions, nullptr, arguments.data(), environment.data()) == 0;
  const bool destroyed = posix_spawn_file_actions_destroy(&actions) == 0;
  const bool write_closed = close(ready[1]) == 0;
  char byte = 0;
  const bool received = spawned && read(ready[0], &byte, 1) == 1 && byte == '!';
  const bool read_closed = close(ready[0]) == 0;
  if (received && destroyed && write_closed && read_closed) {
    return child;
  }
  if (spawned) {
    int status = -1;
    static_cast<void>(waitpid(child, &status, 0));
  }
  return std::nullopt;
}

/// Checks the child's normal exit before any assertion can abandon a live process.
void wait_lock_holder(pid_t child) {
  int status = -1;
  ASSERT_EQ(waitpid(child, &status, 0), child);
  EXPECT_TRUE(WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

/// Confirms unavailable or retried reads never replace or change an existing identity.
void check_kept_identity(const TemporaryDirectory& directory, const struct stat& before,
                         const std::optional<std::string>& identity) {
  struct stat after{};
  ASSERT_EQ(stat(id_path(directory).c_str(), &after), 0);
  EXPECT_EQ(after.st_ino, before.st_ino);
  EXPECT_EQ(test_support::read_file(id_path(directory)), identity);
}

/// Runs the real legacy entry while an independently exec'd child owns the validated private lock.
void check_process_contention(bool release_within_budget) {
  const TemporaryDirectory directory;
  const auto identity = load_or_create_install_id(directory.path());
  ASSERT_TRUE(identity.has_value());
  struct stat before{};
  ASSERT_EQ(stat(id_path(directory).c_str(), &before), 0);
  const auto child = spawn_lock_holder(directory.path(), release_within_budget);
  ASSERT_TRUE(child.has_value());
  const auto result = load_or_create_install_id(directory.path());
  wait_lock_holder(*child);
  EXPECT_EQ(result.has_value(), release_within_budget);
  if (result.has_value()) {
    EXPECT_EQ(result, identity);
  }
  check_kept_identity(directory, before, identity);
}

TEST(InstallId, loadOrCreateInstallId_whenChildReleasesLockWithinBudget_returnsExistingIdentity) {
  check_process_contention(true);
}

TEST(InstallId, loadOrCreateInstallId_whenChildKeepsLockBeyondBudget_returnsUnavailableWithoutReplacingIdentity) {
  check_process_contention(false);
}

TEST(InstallId, loadOrCreateInstallId_whenTheFolderDoesNotExist_returnsNothing) {
  const TemporaryDirectory directory;

  const std::optional<std::string> id = load_or_create_install_id(directory.path() + "/missing");

  EXPECT_FALSE(id.has_value());
}

}  // namespace
}  // namespace rasp

namespace rasp {
namespace {
TEST(InstallId, loadOrCreateInstallId_whenLegacyIdentityIsOversized_preservesItAndReturnsUnavailable) {
  const TemporaryDirectory directory;
  const std::string oversized(4097, 'a');
  ASSERT_TRUE(write_file(id_path(directory), oversized));
  EXPECT_FALSE(load_or_create_install_id(directory.path()).has_value());
  EXPECT_EQ(test_support::read_file(id_path(directory)), oversized);
}
}  // namespace
}  // namespace rasp
