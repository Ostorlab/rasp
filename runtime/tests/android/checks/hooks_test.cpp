/// Tests for the Android hooking checks: the memory-map probe that reports instrumentation-framework mappings,
/// writable-executable regions and foreign libraries, and the thread-name probe.

#include "checks/hooks.h"

#include <cstddef>
#include <filesystem>
#include <gtest/gtest.h>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include "rasp/observation.h"
#include "rasp/util/read_file.h"
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

/// The hook.foreign_libs observation that reports `lines`.
[[nodiscard]] Observation foreign_libs(std::vector<std::string> lines) {
  return {.signal = "hook.foreign_libs", .source = "proc_maps", .status = Status::kOk, .value = std::move(lines)};
}

/// The hook.threads observation that reports `names`.
[[nodiscard]] Observation threads(std::vector<std::string> names) {
  return {.signal = "hook.threads", .source = "proc_task", .status = Status::kOk, .value = std::move(names)};
}

/// The hook.threads observation of a thread list that couldn't be read whole.
[[nodiscard]] Observation unreadable_threads() {
  return {.signal = "hook.threads", .source = "proc_task", .status = Status::kError, .value = {}};
}

/// Adds a folder named `name` to the thread list `task`, with `comm` as its name file's content.
[[nodiscard]] bool add_folder(const std::string& task, const std::string& name, std::string_view comm) {
  const std::string folder = task + "/" + name;
  std::error_code error;
  return std::filesystem::create_directory(folder, error) && write_file(folder + "/comm", comm);
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

TEST(Hooks, observeMaps_whenMapIsClean_reportsEmptyLists) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  const std::string path = write_maps(directory, kCleanMaps);
  ASSERT_FALSE(path.empty());

  EXPECT_EQ(observe_maps(path, rasp::util::read_file),
            (std::vector<Observation>{maps_hits({}), rwx_regions({}), foreign_libs({})}));
}

TEST(Hooks, observeMaps_whenFridaAgentIsMapped_reportsItUnderMapsHits) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  const std::string line =
      "7f0000500000-7f0000600000 r-xp 00000000 fd:00 300  /data/local/tmp/re.frida.server/frida-agent-64.so";
  const std::string path = write_maps(directory, std::string(kCleanMaps) + line + "\n");
  ASSERT_FALSE(path.empty());

  const std::vector<Observation> observations = observe_maps(path, rasp::util::read_file);

  EXPECT_EQ(observations.at(0), maps_hits({line}));
}

TEST(Hooks, observeMaps_whenAMarkerIsUppercase_matchesCaseInsensitively) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  const std::string line = "7f0000500000-7f0000600000 r-xp 00000000 fd:00 300  /data/app/XposedBridge.jar";
  const std::string path = write_maps(directory, line + "\n");
  ASSERT_FALSE(path.empty());

  EXPECT_EQ(observe_maps(path, rasp::util::read_file).at(0), maps_hits({line}));
}

TEST(Hooks, observeMaps_whenTheAppsPackageNameContainsFridays_doesNotReportTheAppsOwnMappings) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  const std::string maps =
      "7f0000000000-7f0000010000 r--p 00000000 fd:00 1  /data/app/~~Xk3R==/com.tgifridays.app-Yq9==/base.apk\n"
      "7f0000010000-7f0000020000 r-xp 00000000 fd:00 2  "
      "/data/app/~~Xk3R==/com.tgifridays.app-Yq9==/lib/arm64/librasp.so\n"
      "7f0000020000-7f0000030000 r--p 00000000 fd:00 3  "
      "/data/app/~~Xk3R==/com.tgifridays.app-Yq9==/oat/arm64/base.odex\n"
      "7f0000030000-7f0000040000 r--p 00000000 fd:00 4  /data/user/0/com.tgifridays.app/files/menu.db\n"
      "7f0000040000-7f0000050000 r--p 00000000 00:00 0  [anon:dalvik-classes.dex extracted in memory from "
      "/data/app/~~Xk3R==/com.tgifridays.app-Yq9==/base.apk]\n";
  const std::string path = write_maps(directory, maps);
  ASSERT_FALSE(path.empty());

  EXPECT_EQ(observe_maps(path, rasp::util::read_file).at(0), maps_hits({}));
}

TEST(Hooks, observeMaps_whenTheAppsPackageNameContainsGadget_doesNotReportTheAppsOwnMappings) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  const std::string maps =
      "7f0000000000-7f0000010000 r--p 00000000 fd:00 1  /data/app/~~Pq8w==/com.gadgetflow.shop-Tz4==/base.apk\n"
      "7f0000010000-7f0000020000 r-xp 00000000 fd:00 2  "
      "/data/app/~~Pq8w==/com.gadgetflow.shop-Tz4==/lib/arm64/librasp.so\n"
      "7f0000020000-7f0000030000 r--p 00000000 fd:00 3  /data/user/0/com.gadgetflow.shop/files/cart.db (deleted)\n";
  const std::string path = write_maps(directory, maps);
  ASSERT_FALSE(path.empty());

  EXPECT_EQ(observe_maps(path, rasp::util::read_file).at(0), maps_hits({}));
}

TEST(Hooks, observeMaps_whenARandomInstallFolderSpellsRiru_doesNotReportTheAppsOwnMappings) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  const std::string maps =
      "7f0000000000-7f0000010000 r--p 00000000 fd:00 1  /data/app/~~a7RiRu2b==/co.app-Hw0RIRUx==/base.apk\n"
      "7f0000010000-7f0000020000 r-xp 00000000 fd:00 2  "
      "/data/app/~~a7RiRu2b==/co.app-Hw0RIRUx==/lib/arm64/librasp.so\n";
  const std::string path = write_maps(directory, maps);
  ASSERT_FALSE(path.empty());

  EXPECT_EQ(observe_maps(path, rasp::util::read_file).at(0), maps_hits({}));
}

TEST(Hooks, observeMaps_whenAFileNameIsAFrameworksLibrary_reportsEachLineWhole) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  const std::vector<std::string> lines = {
      "7f0000500000-7f0000600000 r-xp 00000000 fd:00 300  /data/local/tmp/frida-agent-64.so",
      "7f0000600000-7f0000700000 r-xp 00000000 fd:00 301  /data/app/~~a==/co.app-1/lib/arm64/libgadget.so",
      "7f0000700000-7f0000800000 r--p 00000000 fd:00 302  /system/framework/XposedBridge.jar",
      "7f0000800000-7f0000900000 r-xp 00000000 fd:00 303  /data/local/tmp/frida-agent-64.so (deleted)",
      "7f0000900000-7f0000a00000 r-xp 00000000 00:01 304  /memfd:frida-agent-64.so (deleted)",
  };
  std::string maps(kCleanMaps);
  for (const std::string& line : lines) {
    maps += line + "\n";
  }
  const std::string path = write_maps(directory, maps);
  ASSERT_FALSE(path.empty());

  EXPECT_EQ(observe_maps(path, rasp::util::read_file).at(0), maps_hits(lines));
}

TEST(Hooks, observeMaps_whenARegionIsWritableExecutable_reportsItUnderRwxRegions) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  const std::string line = "7f0000700000-7f0000800000 rwxp 00000000 00:00 0 ";
  const std::string path = write_maps(directory, std::string(kCleanMaps) + line + "\n");
  ASSERT_FALSE(path.empty());

  const std::vector<Observation> observations = observe_maps(path, rasp::util::read_file);

  EXPECT_EQ(observations.at(1), rwx_regions({line}));
}

TEST(Hooks, observeMaps_whenARegionIsWritableButNotExecutable_doesNotReportIt) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  const std::string line = "7f0000700000-7f0000800000 rw-p 00000000 00:00 0  [anon:something]";
  const std::string path = write_maps(directory, line + "\n");
  ASSERT_FALSE(path.empty());

  EXPECT_EQ(observe_maps(path, rasp::util::read_file).at(1), rwx_regions({}));
}

TEST(Hooks, observeMaps_whenALibraryIsLoadedFromOutsideTheAppAndSystem_reportsItUnderForeignLibs) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  const std::string line =
      "7f0000500000-7f0000600000 r-xp 00000000 fd:00 300  /data/local/tmp/re.frida.server/frida-agent-64.so";
  const std::string path = write_maps(directory, std::string(kCleanMaps) + line + "\n");
  ASSERT_FALSE(path.empty());

  EXPECT_EQ(observe_maps(path, rasp::util::read_file).at(2), foreign_libs({line}));
}

TEST(Hooks, observeMaps_whenTheForeignLibrarysFileWasDeleted_reportsItUnderForeignLibs) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  const std::string line = "7f0000500000-7f0000600000 r-xp 00000000 fd:00 300  /data/local/tmp/libhook.so (deleted)";
  const std::string path = write_maps(directory, std::string(kCleanMaps) + line + "\n");
  ASSERT_FALSE(path.empty());

  EXPECT_EQ(observe_maps(path, rasp::util::read_file).at(2), foreign_libs({line}));
}

TEST(Hooks, observeMaps_whenLibrariesComeFromTheExpectedDirectories_doesNotReportThem) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  const std::string maps =
      "7f0000000000-7f0000010000 r-xp 00000000 fd:00 1  /system/lib64/libandroid_runtime.so\n"
      "7f0000010000-7f0000020000 r-xp 00000000 fd:00 2  /apex/com.android.art/lib64/libart.so\n"
      "7f0000020000-7f0000030000 r-xp 00000000 fd:00 3  /vendor/lib64/libgles.so\n"
      "7f0000030000-7f0000040000 r-xp 00000000 fd:00 4  /product/lib64/libextra.so\n"
      "7f0000040000-7f0000050000 r-xp 00000000 fd:00 5  /data/app/~~a==/co.app-1/lib/arm64/libapp.so\n"
      "7f0000050000-7f0000060000 r-xp 00000000 fd:00 6  /system/lib64/libold.so (deleted)\n";
  const std::string path = write_maps(directory, maps);
  ASSERT_FALSE(path.empty());

  EXPECT_EQ(observe_maps(path, rasp::util::read_file).at(2), foreign_libs({}));
}

TEST(Hooks, observeMaps_whenAForeignMappingIsNotALibrary_doesNotReportIt) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  const std::string maps =
      "7f0000000000-7f0000010000 r--p 00000000 fd:00 1  /data/local/tmp/notes.txt\n"
      "7f0000010000-7f0000020000 rw-p 00000000 00:00 0  [anon:dalvik-main space]\n";
  const std::string path = write_maps(directory, maps);
  ASSERT_FALSE(path.empty());

  EXPECT_EQ(observe_maps(path, rasp::util::read_file).at(2), foreign_libs({}));
}

TEST(Hooks, observeMaps_whenTheFileIsMissing_reportsAnErrorForEach) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());

  EXPECT_EQ(observe_maps(directory.path() + "/missing"),
            (std::vector<Observation>{unreadable("hook.maps_hits"), unreadable("hook.rwx_regions"),
                                      unreadable("hook.foreign_libs")}));
}

TEST(Hooks, hooks_whenOffAndroid_reportsEveryCheckAsUnsupported) {
  EXPECT_EQ(hooks(),
            (std::vector<Observation>{
                {.signal = "hook.maps_hits", .source = "proc_maps", .status = Status::kUnsupported, .value = {}},
                {.signal = "hook.rwx_regions", .source = "proc_maps", .status = Status::kUnsupported, .value = {}},
                {.signal = "hook.foreign_libs", .source = "proc_maps", .status = Status::kUnsupported, .value = {}},
                {.signal = "hook.threads", .source = "proc_task", .status = Status::kUnsupported, .value = {}},
            }));
}

TEST(Hooks, observeThreads_whenNoThreadHasAFrameworkName_reportsAnEmptyList) {
  const TemporaryDirectory task;
  ASSERT_FALSE(task.path().empty());
  ASSERT_TRUE(add_folder(task.path(), "100", "co.app\n"));
  ASSERT_TRUE(add_folder(task.path(), "101", "RenderThread\n"));

  EXPECT_EQ(observe_threads(task.path(), rasp::util::read_file), (std::vector<Observation>{threads({})}));
}

TEST(Hooks, observeThreads_whenAThreadHasAFridaName_reportsTheNameWithoutItsLineBreak) {
  const TemporaryDirectory task;
  ASSERT_FALSE(task.path().empty());
  ASSERT_TRUE(add_folder(task.path(), "100", "co.app\n"));
  ASSERT_TRUE(add_folder(task.path(), "102", "gum-js-loop\n"));

  EXPECT_EQ(observe_threads(task.path(), rasp::util::read_file), (std::vector<Observation>{threads({"gum-js-loop"})}));
}

TEST(Hooks, observeThreads_whenThreadsShareAFrameworkName_reportsEachNameOnceInOrder) {
  const TemporaryDirectory task;
  ASSERT_FALSE(task.path().empty());
  ASSERT_TRUE(add_folder(task.path(), "100", "gmain\n"));
  ASSERT_TRUE(add_folder(task.path(), "101", "gdbus\n"));
  ASSERT_TRUE(add_folder(task.path(), "102", "gmain\n"));

  EXPECT_EQ(observe_threads(task.path(), rasp::util::read_file),
            (std::vector<Observation>{threads({"gdbus", "gmain"})}));
}

TEST(Hooks, observeThreads_whenMoreThan16NamesMatch_reportsTheFirst16InOrder) {
  const TemporaryDirectory task;
  ASSERT_FALSE(task.path().empty());
  std::vector<std::string> expected;
  for (std::size_t index = 10; index < 30; ++index) {
    const std::string name = "pool-frida-" + std::to_string(index);
    ASSERT_TRUE(add_folder(task.path(), std::to_string(100 + index), name + "\n"));
    if (expected.size() < 16) {
      expected.push_back(name);
    }
  }

  EXPECT_EQ(observe_threads(task.path(), rasp::util::read_file), (std::vector<Observation>{threads(expected)}));
}

TEST(Hooks, observeThreads_whenTheListHoldsEntriesThatAreNotThreads_ignoresThem) {
  const TemporaryDirectory task;
  ASSERT_FALSE(task.path().empty());
  ASSERT_TRUE(add_folder(task.path(), "notes", "gmain\n"));
  ASSERT_TRUE(add_folder(task.path(), "100", "co.app\n"));

  EXPECT_EQ(observe_threads(task.path(), rasp::util::read_file), (std::vector<Observation>{threads({})}));
}

TEST(Hooks, observeThreads_whenTheListIsMissing_reportsAnError) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());

  EXPECT_EQ(observe_threads(directory.path() + "/missing"), (std::vector<Observation>{unreadable_threads()}));
}

TEST(Hooks, observeThreads_whenARunningThreadsNameCannotBeRead_reportsAnErrorRatherThanAPartialList) {
  const TemporaryDirectory task;
  ASSERT_FALSE(task.path().empty());
  ASSERT_TRUE(add_folder(task.path(), "100", "gmain\n"));
  std::error_code error;
  ASSERT_TRUE(std::filesystem::create_directory(task.path() + "/101", error));

  EXPECT_EQ(observe_threads(task.path(), rasp::util::read_file), (std::vector<Observation>{unreadable_threads()}));
}

TEST(Hooks, observeThreads_whenTheListHoldsMoreThan4096Threads_reportsAnErrorRatherThanAPartialList) {
  const TemporaryDirectory task;
  ASSERT_FALSE(task.path().empty());
  for (std::size_t id = 1; id <= 4097; ++id) {
    ASSERT_TRUE(add_folder(task.path(), std::to_string(id), "worker\n"));
  }

  EXPECT_EQ(observe_threads(task.path(), rasp::util::read_file), (std::vector<Observation>{unreadable_threads()}));
}

}  // namespace
}  // namespace rasp::android::checks
