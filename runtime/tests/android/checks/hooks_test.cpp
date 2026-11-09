/// Tests for the Android hooking checks: the memory-map probe that reports instrumentation-framework mappings and
/// writable-executable regions.

#include "checks/hooks.h"

#include <gtest/gtest.h>
#include <string>
#include <string_view>
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
