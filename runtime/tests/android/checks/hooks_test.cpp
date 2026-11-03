/// Tests for the Android hooking checks: the memory-map probe that reports instrumentation-framework mappings and
/// writable-executable regions, and the thread probe that reports Frida's threads.

#include "checks/hooks.h"

#include <filesystem>
#include <gtest/gtest.h>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include "rasp/observation.h"
#include "support/files.h"

namespace rasp::android::checks {
namespace {

using test_support::TemporaryDirectory;
using test_support::write_file;

/// A clean app's memory map: its own library, libc, the stack and the heap, none of them writable-executable.
constexpr std::string_view kCleanMaps =
    "7f0000000000-7f0000010000 r-xp 00001000 fd:00 100  /data/app/~~a==/co.app-1/lib/arm64/librasp.so\n"
    "7f0000010000-7f0000011000 r--p 00011000 fd:00 100  /data/app/~~a==/co.app-1/lib/arm64/librasp.so\n"
    "7f0000020000-7f0000120000 r-xp 00000000 fd:00 200  /apex/com.android.runtime/lib64/bionic/libc.so\n"
    "7ffffffdd000-7ffffffff000 rw-p 00000000 00:00 0    [stack]\n"
    "7f0000200000-7f0000400000 rw-p 00000000 00:00 0    [anon:libc_malloc]\n";

/// The hook.maps_hits observation that reports `lines`.
[[nodiscard]] Observation maps_hits(std::vector<std::string> lines) {
  return {.signal = "hook.maps_hits", .source = "proc_maps", .status = Status::kOk, .value = std::move(lines)};
}

/// The hook.rwx_regions observation that reports `lines`.
[[nodiscard]] Observation rwx_regions(std::vector<std::string> lines) {
  return {.signal = "hook.rwx_regions", .source = "proc_maps", .status = Status::kOk, .value = std::move(lines)};
}

/// The observation of a memory map that couldn't be read, for `signal`.
[[nodiscard]] Observation unreadable(std::string_view signal) {
  return {.signal = std::string(signal), .source = "proc_maps", .status = Status::kError, .value = {}};
}

/// Writes `content` to a maps file in `directory` and returns its path.
[[nodiscard]] std::string write_maps(const TemporaryDirectory& directory, std::string_view content) {
  const std::string path = directory.path() + "/maps";
  return write_file(path, content) ? path : std::string();
}

/// The hook.threads observation that reports `names`.
[[nodiscard]] Observation threads(std::vector<std::string> names) {
  return {.signal = "hook.threads", .source = "proc_task", .status = Status::kOk, .value = std::move(names)};
}

/// Writes a thread folder named `id` in `task_path`, whose `comm` file holds `name` and a line break.
///
/// @param task_path The folder of the threads.
/// @param id The thread's id, the name of its folder.
/// @param name The thread's name.
/// @return `true` when the folder and the file were written.
[[nodiscard]] bool write_thread(const std::string& task_path, int id, std::string_view name) {
  const std::filesystem::path folder = std::filesystem::path(task_path) / std::to_string(id);
  std::error_code error;
  std::filesystem::create_directories(folder, error);
  return !error && write_file((folder / "comm").string(), std::string(name) + "\n");
}

TEST(Hooks, observeMaps_whenMapIsClean_reportsEmptyLists) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  const std::string path = write_maps(directory, kCleanMaps);
  ASSERT_FALSE(path.empty());

  EXPECT_EQ(observe_maps(path), (std::vector<Observation>{maps_hits({}), rwx_regions({})}));
}

TEST(Hooks, observeMaps_whenFridaAgentIsMapped_reportsItUnderMapsHits) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  const std::string line =
      "7f0000500000-7f0000600000 r-xp 00000000 fd:00 300  /data/local/tmp/re.frida.server/frida-agent-64.so";
  const std::string path = write_maps(directory, std::string(kCleanMaps) + line + "\n");
  ASSERT_FALSE(path.empty());

  const std::vector<Observation> observations = observe_maps(path);

  EXPECT_EQ(observations.at(0), maps_hits({line}));
}

TEST(Hooks, observeMaps_whenAMarkerIsUppercase_matchesCaseInsensitively) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  const std::string line = "7f0000500000-7f0000600000 r-xp 00000000 fd:00 300  /data/app/XposedBridge.jar";
  const std::string path = write_maps(directory, line + "\n");
  ASSERT_FALSE(path.empty());

  EXPECT_EQ(observe_maps(path).at(0), maps_hits({line}));
}

TEST(Hooks, observeMaps_whenARegionIsWritableExecutable_reportsItUnderRwxRegions) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  const std::string line = "7f0000700000-7f0000800000 rwxp 00000000 00:00 0 ";
  const std::string path = write_maps(directory, std::string(kCleanMaps) + line + "\n");
  ASSERT_FALSE(path.empty());

  const std::vector<Observation> observations = observe_maps(path);

  EXPECT_EQ(observations.at(1), rwx_regions({line}));
}

TEST(Hooks, observeMaps_whenARegionIsWritableButNotExecutable_doesNotReportIt) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  const std::string line = "7f0000700000-7f0000800000 rw-p 00000000 00:00 0  [anon:something]";
  const std::string path = write_maps(directory, line + "\n");
  ASSERT_FALSE(path.empty());

  EXPECT_EQ(observe_maps(path).at(1), rwx_regions({}));
}

TEST(Hooks, observeMaps_whenTheFileIsMissing_reportsAnErrorForBoth) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());

  EXPECT_EQ(observe_maps(directory.path() + "/missing"),
            (std::vector<Observation>{unreadable("hook.maps_hits"), unreadable("hook.rwx_regions")}));
}

TEST(Hooks, observeThreads_whenNoThreadIsFrida_reportsAnEmptyList) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  ASSERT_TRUE(write_thread(directory.path(), 100, "co.app"));
  ASSERT_TRUE(write_thread(directory.path(), 101, "RenderThread"));

  EXPECT_EQ(observe_threads(directory.path()), threads({}));
}

TEST(Hooks, observeThreads_whenFridasThreadsRun_reportsTheirNamesSortedOnce) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  ASSERT_TRUE(write_thread(directory.path(), 100, "co.app"));
  ASSERT_TRUE(write_thread(directory.path(), 101, "pool-frida"));
  ASSERT_TRUE(write_thread(directory.path(), 102, "gum-js-loop"));
  ASSERT_TRUE(write_thread(directory.path(), 103, "pool-frida"));

  EXPECT_EQ(observe_threads(directory.path()), threads({"gum-js-loop", "pool-frida"}));
}

TEST(Hooks, observeThreads_whenAMarkerIsUppercase_matchesCaseInsensitively) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  ASSERT_TRUE(write_thread(directory.path(), 100, "Frida-Main"));

  EXPECT_EQ(observe_threads(directory.path()), threads({"Frida-Main"}));
}

TEST(Hooks, observeThreads_whenAThreadHasNoName_leavesItOut) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  std::error_code error;
  std::filesystem::create_directories(std::filesystem::path(directory.path()) / "100", error);
  ASSERT_FALSE(error);
  ASSERT_TRUE(write_thread(directory.path(), 101, "gum-js-loop"));

  EXPECT_EQ(observe_threads(directory.path()), threads({"gum-js-loop"}));
}

TEST(Hooks, observeThreads_whenTheFolderIsMissing_reportsAnError) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());

  EXPECT_EQ(observe_threads(directory.path() + "/missing"),
            (Observation{.signal = "hook.threads", .source = "proc_task", .status = Status::kError, .value = {}}));
}

TEST(Hooks, hooks_whenOffAndroid_reportsEveryCheckAsUnsupported) {
  EXPECT_EQ(hooks(),
            (std::vector<Observation>{
                {.signal = "hook.maps_hits", .source = "proc_maps", .status = Status::kUnsupported, .value = {}},
                {.signal = "hook.rwx_regions", .source = "proc_maps", .status = Status::kUnsupported, .value = {}},
                {.signal = "hook.threads", .source = "proc_task", .status = Status::kUnsupported, .value = {}},
            }));
}

}  // namespace
}  // namespace rasp::android::checks
