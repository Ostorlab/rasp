/// Tests for the Android hooking checks: the memory-map probe that reports instrumentation-framework mappings and
/// writable-executable regions, and the thread probe that reports Frida's threads.

#include "checks/hooks.h"

#include <array>
#include <cerrno>
#include <filesystem>
#include <gtest/gtest.h>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include "rasp/context.h"
#include "rasp/observation.h"
#include "rasp/plugin.h"
#include "rasp/plugins/registry.h"
#ifdef RASP_TEST_ANDROID_HOOKS
#include <pthread.h>
#endif
#include "support/files.h"
#include "support/syscall_files.h"

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

/// The hook.maps_hits observation through `source` that reports `lines`.
[[nodiscard]] Observation maps_hits(std::vector<std::string> lines, std::string_view source = "proc_maps") {
  return {.signal = "hook.maps_hits", .source = std::string(source), .status = Status::kOk, .value = std::move(lines)};
}

/// The hook.rwx_regions observation that reports `lines`.
[[nodiscard]] Observation rwx_regions(std::vector<std::string> lines) {
  return {.signal = "hook.rwx_regions", .source = "proc_maps", .status = Status::kOk, .value = std::move(lines)};
}

/// The observation through `source` of a memory map that couldn't be read, for `signal`.
[[nodiscard]] Observation unreadable(std::string_view signal, std::string_view source = "proc_maps") {
  return {.signal = std::string(signal), .source = std::string(source), .status = Status::kError, .value = {}};
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

/// Where a plugin captures the actual production observations it receives.
constexpr plugins::Key<std::vector<Observation>> kCapturedObservations{"hooks.captured"};

/// Records the callback's observations without interpreting their names, types or statuses.
void capture_observations(std::span<const Observation> observations, plugins::Context& context) {
  context.put(kCapturedObservations, std::vector<Observation>(observations.begin(), observations.end()));
}

/// Writes a thread folder named `thread_id` in `task_path`, whose `comm` file holds `name` and a line break.
///
/// @param task_path The folder of the threads.
/// @param thread_id The thread's id, the name of its folder.
/// @param name The thread's name.
/// @return `true` when the folder and the file were written.
[[nodiscard]] bool write_thread(const std::string& task_path, int thread_id, std::string_view name) {
  const std::filesystem::path folder = std::filesystem::path(task_path) / std::to_string(thread_id);
  std::error_code error;
  std::filesystem::create_directories(folder, error);
  return !error && write_file((folder / "comm").string(), std::string(name) + "\n");
}

TEST(Hooks, observeMaps_whenMapIsClean_reportsEmptyLists) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  const std::string path = write_maps(directory, kCleanMaps);
  ASSERT_FALSE(path.empty());

  EXPECT_EQ(observe_maps(path),
            (std::vector<Observation>{maps_hits({}), rwx_regions({}), maps_hits({}, "proc_maps_syscall")}));
}

TEST(Hooks, observeMaps_whenFridaAgentIsMapped_reportsItUnderMapsHitsThroughBothSources) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  const std::string line =
      "7f0000500000-7f0000600000 r-xp 00000000 fd:00 300  /data/local/tmp/re.frida.server/frida-agent-64.so";
  const std::string path = write_maps(directory, std::string(kCleanMaps) + line + "\n");
  ASSERT_FALSE(path.empty());

  const std::vector<Observation> observations = observe_maps(path);

  ASSERT_EQ(observations.size(), 3U);
  EXPECT_EQ(observations[0], maps_hits({line}));
  EXPECT_EQ(observations[2], maps_hits({line}, "proc_maps_syscall"));
}

TEST(Hooks, observeMaps_whenAMarkerIsUppercase_matchesCaseInsensitively) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  const std::string line = "7f0000500000-7f0000600000 r-xp 00000000 fd:00 300  /data/app/XposedBridge.jar";
  const std::string path = write_maps(directory, line + "\n");
  ASSERT_FALSE(path.empty());

  const std::vector<Observation> observations = observe_maps(path);

  ASSERT_EQ(observations.size(), 3U);
  EXPECT_EQ(observations[0], maps_hits({line}));
  EXPECT_EQ(observations[2], maps_hits({line}, "proc_maps_syscall"));
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

TEST(Hooks, observeMaps_whenTheFileIsMissing_reportsAnErrorForEveryObservation) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());

  EXPECT_EQ(observe_maps(directory.path() + "/missing"),
            (std::vector<Observation>{unreadable("hook.maps_hits"), unreadable("hook.rwx_regions"),
                                      unreadable("hook.maps_hits", "proc_maps_syscall")}));
}

TEST(Hooks, observeMaps_whenTheFileCantBeRead_reportsAnErrorForEveryObservation) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());

  EXPECT_EQ(observe_maps(directory.path()),
            (std::vector<Observation>{unreadable("hook.maps_hits"), unreadable("hook.rwx_regions"),
                                      unreadable("hook.maps_hits", "proc_maps_syscall")}));
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

TEST(Hooks, observeThreads_whenAThreadDisappears_reportsAnError) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  std::error_code error;
  std::filesystem::create_directories(std::filesystem::path(directory.path()) / "100", error);
  ASSERT_FALSE(error);
  ASSERT_TRUE(write_thread(directory.path(), 101, "gum-js-loop"));

  EXPECT_EQ(observe_threads(directory.path()), failed("hook.threads", "proc_task"));
}

TEST(Hooks, observeThreads_whenTheFolderIsMissing_reportsAnError) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());

  EXPECT_EQ(observe_threads(directory.path() + "/missing"),
            (Observation{.signal = "hook.threads", .source = "proc_task", .status = Status::kError, .value = {}}));
}

TEST(Hooks, observeThreads_whenNamesAreGenericOrRenamed_reportsAnEmptyList) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  ASSERT_TRUE(write_thread(directory.path(), 100, "gmain"));
  ASSERT_TRUE(write_thread(directory.path(), 101, "pool-worker"));
  ASSERT_TRUE(write_thread(directory.path(), 102, "renamed-agent"));
  EXPECT_EQ(observe_threads(directory.path()), threads({}));
}

TEST(Hooks, observeThreads_whenCommIsMalformed_reportsAnError) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  ASSERT_TRUE(write_thread(directory.path(), 100, "worker"));
  const std::array<std::string, 8> malformed = {
      "",
      "\n",
      "frida",
      "frida\nextra\n",
      std::string("frida\0x\n", 8),
      "frida\r\n",
      std::string(16, 'x') + "\n",
      std::string(1024, 'x') + "frida\n",
  };
  for (const std::string& content : malformed) {
    ASSERT_TRUE(write_file(directory.path() + "/100/comm", content));
    EXPECT_EQ(observe_threads(directory.path()), failed("hook.threads", "proc_task")) << content.size();
  }
}

TEST(Hooks, observeThreads_whenNameIsKernelTruncated_reportsOnlyVisibleBytes) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  ASSERT_TRUE(write_thread(directory.path(), 100, "123456789012345"));
  ASSERT_TRUE(write_thread(directory.path(), 101, "frida-123456789"));
  EXPECT_EQ(observe_threads(directory.path()), threads({"frida-123456789"}));
}

TEST(Hooks, observeThreads_whenCommReadFails_reportsAnError) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  std::error_code error;
  ASSERT_TRUE(std::filesystem::create_directories(directory.path() + "/100/comm", error));
  ASSERT_FALSE(error);
  EXPECT_EQ(observe_threads(directory.path()), failed("hook.threads", "proc_task"));
}

TEST(Hooks, observeThreads_whenCommReadIsDenied_reportsAnError) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  ASSERT_TRUE(write_thread(directory.path(), 100, "worker"));
  const std::string path = directory.path() + "/100/comm";
  std::error_code error;
  std::filesystem::permissions(path, std::filesystem::perms::none, error);
  ASSERT_FALSE(error);
  const Observation result = observe_threads(directory.path());
  std::filesystem::permissions(path, std::filesystem::perms::owner_read | std::filesystem::perms::owner_write, error);
  ASSERT_FALSE(error);
  EXPECT_EQ(result, failed("hook.threads", "proc_task"));
}

TEST(Hooks, observeThreads_whenTaskLimitIsExceeded_neverReportsClean) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  for (int thread_id = 1; thread_id <= 4096; ++thread_id) {
    ASSERT_TRUE(write_thread(directory.path(), thread_id, "worker"));
  }
  EXPECT_EQ(observe_threads(directory.path()), threads({}));
  ASSERT_TRUE(write_thread(directory.path(), 4097, "worker"));
  EXPECT_EQ(observe_threads(directory.path()), failed("hook.threads", "proc_task"));
}

TEST(Hooks, observeThreads_whenManyNamesMatch_reportsSmallest32AfterCompleteScan) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  std::vector<std::string> expected;
  for (int thread_id = 150; thread_id >= 100; --thread_id) {
    const std::string name = "frida-" + std::to_string(thread_id);
    ASSERT_TRUE(write_thread(directory.path(), thread_id, name));
    if (thread_id < 132) {
      expected.insert(expected.begin(), name);
    }
  }
  EXPECT_EQ(observe_threads(directory.path()), threads(expected));
  ASSERT_TRUE(write_file(directory.path() + "/100/comm", ""));
  EXPECT_EQ(observe_threads(directory.path()), failed("hook.threads", "proc_task"));
}

TEST(Hooks, observeThreads_whenErrorReachesPlugins_preservesTypedFailure) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  const std::vector<Observation> observations = {observe_threads(directory.path() + "/missing")};
  plugins::Context context;
  const plugins::Plugin plugin{.init = nullptr, .checks = {}, .on_observations = capture_observations};
  const std::array plugins{&plugin};
  EXPECT_EQ(plugins::run_plugins(plugins, observations, context),
            (std::vector<Observation>{failed("hook.threads", "proc_task")}));
  EXPECT_EQ(context.get(kCapturedObservations), observations);
}

#ifdef RASP_TEST_ANDROID_HOOKS
TEST(Hooks, hooks_whenAndroidBranchRuns_readsOwnThreadsAndPreservesPluginContract) {
  std::array<char, 16> original{};
  ASSERT_EQ(pthread_getname_np(pthread_self(), original.data(), original.size()), 0);
  ASSERT_EQ(pthread_setname_np(pthread_self(), "gum-js-loop"), 0);
  const std::vector<Observation> observations = hooks();
  const int renamed = pthread_setname_np(pthread_self(), "ordinary-worker");
  const std::vector<Observation> renamed_observations = hooks();
  ASSERT_EQ(pthread_setname_np(pthread_self(), original.data()), 0);
  ASSERT_EQ(renamed, 0);
  ASSERT_EQ(renamed_observations.size(), 4);
  EXPECT_EQ(renamed_observations[3], threads({}));
  ASSERT_EQ(observations.size(), 4);
  EXPECT_EQ(observations[0].signal, "hook.maps_hits");
  EXPECT_EQ(observations[1].signal, "hook.rwx_regions");
  EXPECT_EQ(observations[2].source, "proc_maps_syscall");
  EXPECT_EQ(observations[3], threads({"gum-js-loop"}));
  plugins::Context context;
  const plugins::Plugin plugin{.init = nullptr, .checks = {}, .on_observations = capture_observations};
  const std::array plugins{&plugin};
  EXPECT_EQ(plugins::run_plugins(plugins, observations, context), observations);
  EXPECT_EQ(context.get(kCapturedObservations), observations);
}
#else
TEST(Hooks, hooks_whenOffAndroid_reportsEveryCheckAsUnsupported) {
  EXPECT_EQ(
      hooks(),
      (std::vector<Observation>{
          {.signal = "hook.maps_hits", .source = "proc_maps", .status = Status::kUnsupported, .value = {}},
          {.signal = "hook.rwx_regions", .source = "proc_maps", .status = Status::kUnsupported, .value = {}},
          {.signal = "hook.maps_hits", .source = "proc_maps_syscall", .status = Status::kUnsupported, .value = {}},
          {.signal = "hook.threads", .source = "proc_task", .status = Status::kUnsupported, .value = {}},
      }));
}

#endif

TEST(Hooks, observeMaps_whenSourcesDiverge_preservesBothThroughPluginCallback) {
  const TemporaryDirectory directory;
  const std::string path = write_maps(directory, kCleanMaps);
  const std::string line = "1000-2000 r-xp 00000000 00:00 0 /frida.so";
  const std::string syscall_maps = line + "\n";
  test_support::SyscallFile fixture{.content = syscall_maps};
  test_support::SyscallFile::active = &fixture;
  const std::vector<Observation> observations = observe_maps(path, test_support::SyscallFile::invoke);
  EXPECT_EQ(observations,
            (std::vector<Observation>{maps_hits({}), rwx_regions({}), maps_hits({line}, "proc_maps_syscall")}));
  EXPECT_EQ(fixture.close_count, 1);
  plugins::Context context;
  const plugins::Plugin plugin{.init = nullptr, .checks = {}, .on_observations = capture_observations};
  const std::array plugins{&plugin};
  EXPECT_EQ(plugins::run_plugins(plugins, observations, context), observations);
  EXPECT_EQ(context.get(kCapturedObservations), observations);
}

TEST(Hooks, observeMaps_whenSyscallReadIsDenied_keepsPrimaryAndReportsError) {
  const TemporaryDirectory directory;
  const std::string path = write_maps(directory, kCleanMaps);
  test_support::SyscallFile fixture{.content = {}, .error = EACCES};
  test_support::SyscallFile::active = &fixture;
  EXPECT_EQ(
      observe_maps(path, test_support::SyscallFile::invoke),
      (std::vector<Observation>{maps_hits({}), rwx_regions({}), unreadable("hook.maps_hits", "proc_maps_syscall")}));
}

TEST(Hooks, observeMaps_whenInputIsMalformedOrTruncated_neverReportsClean) {
  const TemporaryDirectory directory;
  for (const std::string_view content :
       {"", "\n", "garbage\n", "1000-2000 rw", "1000-2000 rwxp 0 00:00 0\ninvalid\n"}) {
    const std::string path = write_maps(directory, content);
    EXPECT_EQ(observe_maps(path),
              (std::vector<Observation>{unreadable("hook.maps_hits"), unreadable("hook.rwx_regions"),
                                        unreadable("hook.maps_hits", "proc_maps_syscall")}));
  }
}

}  // namespace
}  // namespace rasp::android::checks
