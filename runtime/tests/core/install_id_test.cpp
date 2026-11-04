/// Tests for load_or_create_install_id, which reads the install id kept in a folder, or creates and keeps one.

#include "rasp/install_id.h"

#include <array>
#include <cstddef>
#include <filesystem>
#include <gtest/gtest.h>
#include <latch>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
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

TEST(InstallId, loadOrCreateInstallId_whenProcessesCreateAnIdAtOnce_givesThemAllTheKeptId) {
  constexpr std::size_t kProcesses = 8;
  const TemporaryDirectory directory;
  std::array<std::optional<std::string>, kProcesses> ids;
  std::latch start(kProcesses);
  std::vector<std::thread> processes;
  processes.reserve(kProcesses);

  for (std::optional<std::string>& id : ids) {
    processes.emplace_back([&directory, &start, &id] {
      start.arrive_and_wait();
      id = load_or_create_install_id(directory.path());
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

TEST(InstallId, loadOrCreateInstallId_whenTheKeptFileIsNotAnId_replacesIt) {
  for (const std::string_view kept : {
           std::string_view(""),
           std::string_view("not an id"),
           std::string_view("0F8E5B8E-6C1A-4B7E-9D3A-2A4C5E6F7A8B"),
           std::string_view("0f8e5b8e-6c1a-4b7e-9d3a-2a4c5e6f7a8b\n"),
       }) {
    const TemporaryDirectory directory;
    ASSERT_TRUE(write_file(id_path(directory), kept));

    const std::optional<std::string> id = load_or_create_install_id(directory.path());

    ASSERT_TRUE(id.has_value()) << kept;
    EXPECT_TRUE(is_uuid_v4(*id)) << kept;
    EXPECT_EQ(util::read_file(id_path(directory), 64), id) << kept;
  }
}

TEST(InstallId, loadOrCreateInstallId_whenTheFolderDoesNotExist_returnsNothing) {
  const TemporaryDirectory directory;

  const std::optional<std::string> id = load_or_create_install_id(directory.path() + "/missing");

  EXPECT_FALSE(id.has_value());
}

}  // namespace
}  // namespace rasp
