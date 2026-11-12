/// Tests for the Android hooking checks: the memory-map probe that reports instrumentation-framework mappings and
/// writable-executable regions, the thread probe that reports Frida's threads, and the inline-hook probe that compares
/// functions' first bytes in memory with their library's file. The inline-hook tests read two small libraries built
/// from util/data/prologue.c, copy each into memory as its loaded image, and describe that copy in a memory map.

#include "checks/hooks.h"

#include <algorithm>
#include <array>
#include <bit>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <format>
#include <gtest/gtest.h>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include "rasp/context.h"
#include "rasp/decision.h"
#include "rasp/observation.h"
#include "rasp/plugin.h"
#include "rasp/plugins/registry.h"
#ifdef RASP_TEST_ANDROID_HOOKS
#include <dlfcn.h>
#include <pthread.h>
#endif
#include "support/decision.h"
#include "support/files.h"
#include "support/syscall_files.h"
#include "util/direct_syscall.h"
#include "util/elf.h"
#ifdef __linux__
#include <cstring>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>
#endif

namespace rasp::android::checks {
namespace {

using test_support::read_file;
using test_support::TemporaryDirectory;
using test_support::write_file;

/// The arm64 fixture library.
constexpr std::string_view kArm64Library = RASP_TEST_ELF_DATA "/libprologue-arm64.so";
/// The armeabi-v7a fixture library, built as Thumb code.
constexpr std::string_view kArmv7Library = RASP_TEST_ELF_DATA "/libprologue-armv7.so";
/// The file offset of `rasp_fixture_first` in the arm64 fixture.
constexpr std::uintptr_t kArm64First = 0x3AC;
/// The file offset of `rasp_fixture_second` in the arm64 fixture.
constexpr std::uintptr_t kArm64Second = 0x3D0;
/// The file offset of `rasp_fixture_indirect`, an IFUNC, in the arm64 fixture.
constexpr std::uintptr_t kArm64Indirect = 0x3DC;
/// The file offset of `rasp_fixture_first` in the armeabi-v7a fixture, a Thumb function.
constexpr std::uintptr_t kArmv7First = 0x224;

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

/// A fixture library as the inline-hook probe sees it: its file, and a copy of the file's bytes that stands for its
/// loaded image, mapped from the start of the file.
struct LoadedLibrary {
  /// The path of the library file.
  std::string path;
  /// The copy of the file's bytes, read by the probe as the library's memory.
  std::vector<std::uint8_t> memory;
};

/// The library file at `path`, loaded as a copy of its bytes. The copy is empty when the file can't be read.
[[nodiscard]] LoadedLibrary load(std::string_view path) {
  const std::optional<std::string> content = read_file(std::string(path));
  if (!content) {
    return {.path = std::string(path), .memory = {}};
  }
  return {.path = std::string(path), .memory = {content->begin(), content->end()}};
}

/// The address of the byte at `file_offset` in the loaded copy of `library`.
[[nodiscard]] std::uintptr_t address_of(const LoadedLibrary& library, std::uintptr_t file_offset) {
  return std::bit_cast<std::uintptr_t>(library.memory.data()) + file_offset;
}

/// How a memory-map line describes a loaded library: its permissions, the file offset it says the copy is mapped
/// from, and how many of the copy's bytes it spans, all of them when 0.
struct MapsLine {
  /// The permissions field.
  std::string_view perms = "r-xp";
  /// The offset field.
  std::uint64_t file_offset = 0;
  /// The number of bytes the line spans, or 0 for the whole copy.
  std::size_t length = 0;
};

/// Writes a memory map in `directory` that maps the loaded copy of `library` as `line` describes, and returns its path.
[[nodiscard]] std::string write_library_maps(const TemporaryDirectory& directory, const LoadedLibrary& library,
                                             const MapsLine& line = {}) {
  const std::uintptr_t start = address_of(library, 0);
  const std::size_t length = line.length == 0 ? library.memory.size() : line.length;
  const std::string maps = std::format("{:x}-{:x} {} {:08x} fd:00 100  {}\n", start, start + length, line.perms,
                                       line.file_offset, library.path);
  return write_maps(directory, std::string(kCleanMaps) + maps);
}

/// The hook.inline observation that reports `names`.
[[nodiscard]] Observation inline_hooks(std::vector<std::string> names) {
  return {.signal = "hook.inline", .source = "prologue", .status = Status::kOk, .value = std::move(names)};
}

/// The hook.inline observation of a probe that couldn't compare the functions.
[[nodiscard]] Observation inline_failed() {
  return {.signal = "hook.inline", .source = "prologue", .status = Status::kError, .value = {}};
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
  const auto snapshot = test_support::decide("android", observations);
  EXPECT_TRUE(std::ranges::any_of(snapshot->local_decisions.rows, [](const auto& decision) {
    return decision.rule_id == "native.android.hook.maps_hits.proc_maps" && decision.verdict == LocalVerdict::kThreat &&
           decision.confidence == LocalConfidence::kLimited;
  }));
  ASSERT_EQ(snapshot->local_decisions.relations.size(), 1U);
  EXPECT_EQ(snapshot->local_decisions.relations[0].state, LocalRelationState::kAgreePresent);
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

#ifdef __linux__
/// Exercises real RX file mappings without executing cross-ABI fixture instructions.
[[nodiscard]] bool check_executable_fixture(std::string_view filename) {
  const std::string path = std::string(RASP_TEST_ELF_DATA) + "/" + std::string(filename);
  const LoadedLibrary file = load(path);
  const auto headers = util::read_elf_headers(file.memory);
  if (!headers.has_value()) {
    return false;
  }
  const auto symbol = util::find_dynamic_symbol(file.memory, *headers, "rasp_fixture_first");
  if (!symbol.has_value()) {
    return false;
  }
  const bool thumb = headers->machine == util::kMachineArm && (symbol->value & 1U) != 0;
  const auto code = util::find_code(
      file.memory, *headers, {.address = symbol->value & ~(thumb ? std::uint64_t{1} : std::uint64_t{0}), .length = 16});
  if (!code.has_value()) {
    return false;
  }
  const auto opened = util::libc_syscall(
      SYS_openat,
      {static_cast<std::uintptr_t>(AT_FDCWD), std::bit_cast<std::uintptr_t>(path.c_str()), O_RDONLY | O_CLOEXEC, 0});
  if (opened.value < 0) {
    return false;
  }
  const int descriptor = static_cast<int>(opened.value);
  void* const memory = mmap(nullptr, file.memory.size(), PROT_READ | PROT_EXEC, MAP_PRIVATE, descriptor, 0);
  const bool closed = close(descriptor) == 0;
  if (memory == MAP_FAILED) {
    return false;
  }
  const auto base = std::bit_cast<std::uintptr_t>(memory);
  const auto functions = std::to_array<ResolvedFunction>({
      {.name = "rasp_fixture_first", .address = base + code->file_offset + (thumb ? 1U : 0U)},
  });
  const bool stock = observe_inline_hooks("/proc/self/maps", functions) == inline_hooks({});
  const bool writable = mprotect(memory, file.memory.size(), PROT_READ | PROT_WRITE) == 0;
  bool changed = false;
  if (writable) {
    const auto bytes = std::span(static_cast<std::uint8_t*>(memory), file.memory.size());
    bytes[static_cast<std::size_t>(code->file_offset)] ^= 0xFFU;
    if (mprotect(memory, file.memory.size(), PROT_READ | PROT_EXEC) == 0) {
      changed = observe_inline_hooks("/proc/self/maps", functions) == inline_hooks({"rasp_fixture_first"});
    }
  }
  const bool unmapped = munmap(memory, file.memory.size()) == 0;
  return closed && stock && writable && changed && unmapped;
}

TEST(Hooks, observeInlineHooks_whenRealExecutableFixturesArePatched_reportsChangedBytesAcrossAbis) {
  constexpr auto kNames = std::to_array<std::string_view>({
      "libprologue-arm64.so",
      "libprologue-armv7.so",
      "libprologue-arm.so",
      "libprologue-x86.so",
      "libprologue-x86_64.so",
  });
  for (const std::string_view filename : kNames) {
    EXPECT_TRUE(check_executable_fixture(filename)) << filename;
  }
}

TEST(Hooks, observeInlineHooks_whenMemoryBecameUnreadable_reportsAnErrorWithoutCrashing) {
  const TemporaryDirectory directory;
  LoadedLibrary library = load(kArm64Library);
  const long page_size = sysconf(_SC_PAGESIZE);
  ASSERT_GT(page_size, 0);
  void* const memory =
      mmap(nullptr, static_cast<std::size_t>(page_size), PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  ASSERT_NE(memory, MAP_FAILED);
  const auto base = std::bit_cast<std::uintptr_t>(memory);
  const std::string maps = write_maps(
      directory,
      std::format("{:x}-{:x} r-xp 0 00:00 1 {}\n", base, base + static_cast<std::uintptr_t>(page_size), library.path));
  const auto functions = std::to_array<ResolvedFunction>({
      {.name = "rasp_fixture_first", .address = base + kArm64First},
  });
  const Observation result = observe_inline_hooks(maps, functions);
  EXPECT_EQ(munmap(memory, static_cast<std::size_t>(page_size)), 0);
  EXPECT_EQ(result, inline_failed());
}
#endif

#ifdef __linux__
TEST(Hooks, observeInlineHooks_whenMemoryReadIsShort_reportsAnError) {
  const TemporaryDirectory directory;
  LoadedLibrary library = load(kArm64Library);
  const long page_size = sysconf(_SC_PAGESIZE);
  ASSERT_GT(page_size, 0);
  const auto size = static_cast<std::size_t>(page_size);
  void* const memory = mmap(nullptr, 2 * size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  ASSERT_NE(memory, MAP_FAILED);
  const auto base = std::bit_cast<std::uintptr_t>(memory);
  const auto address = base + size - 8;
  void* const second = std::bit_cast<void*>(base + size);
  ASSERT_EQ(mprotect(second, size, PROT_NONE), 0);
  const std::string maps = write_maps(
      directory, std::format("{:x}-{:x} r-xp {:x} 00:00 1 {}\n", address, address + 16, kArm64First, library.path));
  const auto functions = std::to_array<ResolvedFunction>({{.name = "rasp_fixture_first", .address = address}});
  const auto result = observe_inline_hooks(maps, functions);
  EXPECT_EQ(munmap(memory, 2 * size), 0);
  EXPECT_EQ(result, inline_failed());
}
#endif

TEST(Hooks, observeInlineHooks_whenFunctionExtentIsZero_reportsAnError) {
  const TemporaryDirectory directory;
  LoadedLibrary library = load(kArm64Library);
  const auto original = read_file(library.path);
  ASSERT_TRUE(original.has_value());
  std::string bytes = *original;
  const auto headers = util::read_elf_headers(library.memory);
  ASSERT_TRUE(headers.has_value());
  const auto symbols = util::find_section(library.memory, *headers, ".dynsym");
  ASSERT_TRUE(symbols.has_value());
  bytes.replace(static_cast<std::size_t>(symbols->file_offset) + 48 + 16, 8, 8, '\0');
  library.path = directory.path() + "/zero.so";
  ASSERT_TRUE(write_file(library.path, bytes));
  const auto functions = std::to_array<ResolvedFunction>({
      {.name = "rasp_fixture_first", .address = address_of(library, kArm64First)},
  });
  EXPECT_EQ(observe_inline_hooks(write_library_maps(directory, library), functions), inline_failed());
}

TEST(Hooks, observeInlineHooks_whenFunctionsAreDuplicateOrNamesUnbounded_reportsAnError) {
  const TemporaryDirectory directory;
  const LoadedLibrary library = load(kArm64Library);
  const auto functions = std::to_array<ResolvedFunction>({
      {.name = "rasp_fixture_first", .address = address_of(library, kArm64First)},
      {.name = "rasp_fixture_first", .address = address_of(library, kArm64First)},
  });
  const std::string path = write_library_maps(directory, library);
  EXPECT_EQ(observe_inline_hooks(path, functions), inline_failed());
  for (const std::string& name : {std::string(), std::string(129, 'x'), std::string("rasp\0suffix", 11)}) {
    const auto invalid = std::to_array<ResolvedFunction>({{.name = name, .address = functions[0].address}});
    EXPECT_EQ(observe_inline_hooks(path, invalid), inline_failed());
  }
}

TEST(Hooks, observeInlineHooks_whenLibraryArchitectureIsInvalid_reportsAnError) {
  const TemporaryDirectory directory;
  LoadedLibrary library = load(kArm64Library);
  const auto functions = std::to_array<ResolvedFunction>({
      {.name = "rasp_fixture_first", .address = address_of(library, kArm64First)},
  });
  const auto original = read_file(library.path);
  ASSERT_TRUE(original.has_value());
  library.path = directory.path() + "/library.so";
  for (const std::size_t offset : {std::size_t{4}, std::size_t{5}, std::size_t{18}}) {
    std::string invalid = *original;
    invalid[offset] = 0;
    ASSERT_TRUE(write_file(library.path, invalid));
    EXPECT_EQ(observe_inline_hooks(write_library_maps(directory, library), functions), inline_failed());
  }
}

TEST(Hooks, observeInlineHooks_whenNoFunctionsWereCompared_reportsAnError) {
  const TemporaryDirectory directory;
  EXPECT_EQ(observe_inline_hooks(write_maps(directory, kCleanMaps), {}), inline_failed());
}

TEST(Hooks, observeInlineHooks_whenMapsContainInvalidRecords_neverReportsClean) {
  const TemporaryDirectory directory;
  const LoadedLibrary library = load(kArm64Library);
  const auto functions = std::to_array<ResolvedFunction>({
      {.name = "rasp_fixture_first", .address = address_of(library, kArm64First)},
  });
  const std::string path = write_library_maps(directory, library);
  const auto maps = read_file(path);
  ASSERT_TRUE(maps.has_value());
  for (const std::string& invalid :
       {std::string("invalid\n"), std::string(8193, 'x') + "\n", std::string("1000-2000 r-xp 0 zz:00 0 /fake\n")}) {
    ASSERT_TRUE(write_file(path, *maps + invalid));
    EXPECT_EQ(observe_inline_hooks(path, functions), inline_failed());
  }
  ASSERT_TRUE(write_file(path, maps->substr(0, maps->size() - 1)));
  EXPECT_EQ(observe_inline_hooks(path, functions), inline_failed());
}

TEST(Hooks, observeInlineHooks_whenAnyMappingsOverlap_reportsWholeObservationError) {
  const TemporaryDirectory directory;
  LoadedLibrary library = load(kArm64Library);
  library.memory[kArm64First] ^= 0xFFU;
  const auto functions = std::to_array<ResolvedFunction>({
      {.name = "rasp_fixture_first", .address = address_of(library, kArm64First)},
      {.name = "rasp_fixture_second", .address = address_of(library, kArm64Second)},
  });
  const std::string path = write_library_maps(directory, library);
  const auto maps = read_file(path);
  ASSERT_TRUE(maps.has_value());
  for (const std::string_view overlap : {
           "1000-2000 r--p 0 00:00 0 /unrelated\n1000-2000 r--p 0 00:00 0 /duplicate\n",
           "1000-3000 r--p 0 00:00 0 /unrelated\n1800-2000 ---p 0 00:00 0 /nested\n",
           "1800-3000 r--p 0 00:00 0 /unrelated\n1000-2000 r--p 0 00:00 0 /partial\n",
       }) {
    ASSERT_TRUE(write_file(path, *maps + std::string(overlap)));
    EXPECT_EQ(observe_inline_hooks(path, functions), inline_failed());
  }
  const auto start = address_of(library, 0);
  ASSERT_TRUE(write_file(
      path, *maps + std::format("{:x}-{:x} r-xp 0 00:00 1 {}\n", start, start + library.memory.size(), library.path)));
  EXPECT_EQ(observe_inline_hooks(path, functions), inline_failed());
}

TEST(Hooks, observeInlineHooks_whenMappingsAreUnorderedAndAdjacent_comparesEveryFunctionEachTime) {
  const TemporaryDirectory directory;
  LoadedLibrary library = load(kArm64Library);
  const auto functions = std::to_array<ResolvedFunction>({
      {.name = "rasp_fixture_first", .address = address_of(library, kArm64First)},
      {.name = "rasp_fixture_second", .address = address_of(library, kArm64Second)},
  });
  const auto start = address_of(library, 0);
  const auto boundary = address_of(library, kArm64Second);
  const std::string path = write_maps(
      directory, std::format("{:x}-{:x} r-xp {:x} 00:00 1 {}\n{:x}-{:x} r-xp 0 00:00 1 {}\n", boundary,
                             start + library.memory.size(), kArm64Second, library.path, start, boundary, library.path));
  EXPECT_EQ(observe_inline_hooks(path, functions), inline_hooks({}));
  library.memory[kArm64Second] ^= 0xFFU;
  EXPECT_EQ(observe_inline_hooks(path, functions), inline_hooks({"rasp_fixture_second"}));
  const auto maps = read_file(path);
  ASSERT_TRUE(maps.has_value());
  ASSERT_TRUE(write_file(path, *maps + "malformed\n"));
  EXPECT_EQ(observe_inline_hooks(path, functions), inline_failed());
}

TEST(Hooks, observeInlineHooks_whenMapIsWritable_reportsAnError) {
  const TemporaryDirectory directory;
  const LoadedLibrary library = load(kArm64Library);
  const auto functions = std::to_array<ResolvedFunction>({
      {.name = "rasp_fixture_first", .address = address_of(library, kArm64First)},
  });
  EXPECT_EQ(observe_inline_hooks(write_library_maps(directory, library, {.perms = "rwxp"}), functions),
            inline_failed());
}

TEST(Hooks, observeInlineHooks_whenMapOffsetWouldOverflow_reportsAnError) {
  const TemporaryDirectory directory;
  const LoadedLibrary library = load(kArm64Library);
  const auto functions = std::to_array<ResolvedFunction>({
      {.name = "rasp_fixture_first", .address = address_of(library, kArm64First)},
  });
  EXPECT_EQ(observe_inline_hooks(write_library_maps(directory, library, {.file_offset = UINT64_MAX}), functions),
            inline_failed());
}

TEST(Hooks, observeInlineHooks_whenMemoryMatchesTheFile_reportsAnEmptyList) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  const LoadedLibrary library = load(kArm64Library);
  ASSERT_FALSE(library.memory.empty());
  const std::string maps = write_library_maps(directory, library);
  const auto functions = std::to_array<ResolvedFunction>({
      {.name = "rasp_fixture_first", .address = address_of(library, kArm64First)},
      {.name = "rasp_fixture_second", .address = address_of(library, kArm64Second)},
  });

  EXPECT_EQ(observe_inline_hooks(maps, functions), inline_hooks({}));
}

TEST(Hooks, observeInlineHooks_whenAPrologueWasRewritten_reportsThatFunction) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  LoadedLibrary library = load(kArm64Library);
  ASSERT_FALSE(library.memory.empty());
  library.memory[kArm64Second + 4] ^= 0xFFU;
  const std::string maps = write_library_maps(directory, library);
  const auto functions = std::to_array<ResolvedFunction>({
      {.name = "rasp_fixture_first", .address = address_of(library, kArm64First)},
      {.name = "rasp_fixture_second", .address = address_of(library, kArm64Second)},
  });

  EXPECT_EQ(observe_inline_hooks(maps, functions), inline_hooks({"rasp_fixture_second"}));
}

TEST(Hooks, observeInlineHooks_whenABytePastThePrologueChanged_reportsAnEmptyList) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  LoadedLibrary library = load(kArm64Library);
  ASSERT_FALSE(library.memory.empty());
  library.memory[kArm64First + 16] ^= 0xFFU;
  const std::string maps = write_library_maps(directory, library);
  const auto functions = std::to_array<ResolvedFunction>({
      {.name = "rasp_fixture_first", .address = address_of(library, kArm64First)},
  });

  EXPECT_EQ(observe_inline_hooks(maps, functions), inline_hooks({}));
}

TEST(Hooks, observeInlineHooks_whenTheMappingEndsInsideThePrologue_reportsAnError) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  LoadedLibrary library = load(kArm64Library);
  ASSERT_FALSE(library.memory.empty());
  library.memory[kArm64First + 8] ^= 0xFFU;
  const std::string maps = write_library_maps(directory, library, {.length = kArm64First + 8});
  const auto functions = std::to_array<ResolvedFunction>({
      {.name = "rasp_fixture_first", .address = address_of(library, kArm64First)},
  });

  EXPECT_EQ(observe_inline_hooks(maps, functions), inline_failed());
}

TEST(Hooks, observeInlineHooks_whenTheAddressIsTagged_comparesTheUntaggedAddress) {
  if constexpr (sizeof(std::uintptr_t) == sizeof(std::uint64_t)) {
    const TemporaryDirectory directory;
    ASSERT_FALSE(directory.path().empty());
    LoadedLibrary library = load(kArm64Library);
    ASSERT_FALSE(library.memory.empty());
    library.memory[kArm64First] ^= 0xFFU;
    const std::string maps = write_library_maps(directory, library);
    const std::uintptr_t tag = std::uintptr_t{0xB4} << 56U;
    const auto functions = std::to_array<ResolvedFunction>({
        {.name = "rasp_fixture_first", .address = address_of(library, kArm64First) | tag},
    });

    EXPECT_EQ(observe_inline_hooks(maps, functions), inline_hooks({"rasp_fixture_first"}));
  }
}

TEST(Hooks, observeInlineHooks_whenAThumbFunctionMatches_reportsAnEmptyList) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  const LoadedLibrary library = load(kArmv7Library);
  ASSERT_FALSE(library.memory.empty());
  const std::string maps = write_library_maps(directory, library);
  const auto functions = std::to_array<ResolvedFunction>({
      {.name = "rasp_fixture_first", .address = address_of(library, kArmv7First + 1)},
  });

  EXPECT_EQ(observe_inline_hooks(maps, functions), inline_hooks({}));
}

TEST(Hooks, observeInlineHooks_whenAThumbFunctionsFirstByteWasRewritten_reportsThatFunction) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  LoadedLibrary library = load(kArmv7Library);
  ASSERT_FALSE(library.memory.empty());
  library.memory[kArmv7First] ^= 0xFFU;
  const std::string maps = write_library_maps(directory, library);
  const auto functions = std::to_array<ResolvedFunction>({
      {.name = "rasp_fixture_first", .address = address_of(library, kArmv7First + 1)},
  });

  EXPECT_EQ(observe_inline_hooks(maps, functions), inline_hooks({"rasp_fixture_first"}));
}

TEST(Hooks, observeInlineHooks_whenTheMappedOffsetDisagreesWithTheSymbol_reportsAnError) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  const LoadedLibrary library = load(kArm64Library);
  ASSERT_FALSE(library.memory.empty());
  const std::string maps = write_library_maps(directory, library, {.file_offset = 0x1000});
  const auto functions = std::to_array<ResolvedFunction>({
      {.name = "rasp_fixture_first", .address = address_of(library, kArm64First)},
  });

  EXPECT_EQ(observe_inline_hooks(maps, functions), inline_failed());
}

TEST(Hooks, observeInlineHooks_whenTheAddressIsNotTheSymbols_reportsAnError) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  const LoadedLibrary library = load(kArm64Library);
  ASSERT_FALSE(library.memory.empty());
  const std::string maps = write_library_maps(directory, library);
  const auto functions = std::to_array<ResolvedFunction>({
      {.name = "rasp_fixture_first", .address = address_of(library, kArm64Second)},
  });

  EXPECT_EQ(observe_inline_hooks(maps, functions), inline_failed());
}

TEST(Hooks, observeInlineHooks_whenTheMappingIsNotExecutable_reportsAnError) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  const LoadedLibrary library = load(kArm64Library);
  ASSERT_FALSE(library.memory.empty());
  const std::string maps = write_library_maps(directory, library, {.perms = "rw-p"});
  const auto functions = std::to_array<ResolvedFunction>({
      {.name = "rasp_fixture_first", .address = address_of(library, kArm64First)},
  });

  EXPECT_EQ(observe_inline_hooks(maps, functions), inline_failed());
}

TEST(Hooks, observeInlineHooks_whenTheAddressIsNotMapped_reportsAnError) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  const LoadedLibrary library = load(kArm64Library);
  ASSERT_FALSE(library.memory.empty());
  const std::string maps = write_maps(directory, kCleanMaps);
  const auto functions = std::to_array<ResolvedFunction>({
      {.name = "rasp_fixture_first", .address = address_of(library, kArm64First)},
  });

  EXPECT_EQ(observe_inline_hooks(maps, functions), inline_failed());
}

TEST(Hooks, observeInlineHooks_whenTheSymbolIsMissing_reportsAnError) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  const LoadedLibrary library = load(kArm64Library);
  ASSERT_FALSE(library.memory.empty());
  const std::string maps = write_library_maps(directory, library);
  const auto functions = std::to_array<ResolvedFunction>({
      {.name = "rasp_fixture_first", .address = address_of(library, kArm64First)},
      {.name = "rasp_fixture_missing", .address = address_of(library, kArm64Second)},
  });

  EXPECT_EQ(observe_inline_hooks(maps, functions), inline_failed());
}

TEST(Hooks, observeInlineHooks_whenTheSymbolIsAnIndirectFunction_reportsAnError) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  const LoadedLibrary library = load(kArm64Library);
  ASSERT_FALSE(library.memory.empty());
  const std::string maps = write_library_maps(directory, library);
  const auto functions = std::to_array<ResolvedFunction>({
      {.name = "rasp_fixture_indirect", .address = address_of(library, kArm64Indirect)},
  });

  EXPECT_EQ(observe_inline_hooks(maps, functions), inline_failed());
}

TEST(Hooks, observeInlineHooks_whenTheLibraryFileIsMissing_reportsAnError) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  LoadedLibrary library = load(kArm64Library);
  ASSERT_FALSE(library.memory.empty());
  library.path = directory.path() + "/missing.so";
  const std::string maps = write_library_maps(directory, library);
  const auto functions = std::to_array<ResolvedFunction>({
      {.name = "rasp_fixture_first", .address = address_of(library, kArm64First)},
  });

  EXPECT_EQ(observe_inline_hooks(maps, functions), inline_failed());
}

TEST(Hooks, observeInlineHooks_whenTheMapIsMissing_reportsAnError) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());

  EXPECT_EQ(observe_inline_hooks(directory.path() + "/missing", {}), inline_failed());
}

TEST(Hooks, observeInlineHooks_whenGivenTooManyFunctions_reportsAnError) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  const LoadedLibrary library = load(kArm64Library);
  ASSERT_FALSE(library.memory.empty());
  const std::string maps = write_library_maps(directory, library);
  const std::vector<ResolvedFunction> functions(
      65, {.name = "rasp_fixture_first", .address = address_of(library, kArm64First)});

  EXPECT_EQ(observe_inline_hooks(maps, functions), inline_failed());
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

TEST(Hooks, observeThreads_whenEntriesAreNotThreadIds_skipsNamesAndUnreadableEntries) {
  const TemporaryDirectory directory;
  ASSERT_TRUE(write_thread(directory.path(), 123, "gum-js-loop"));
  for (const std::string_view name : {"frida", "123suffix", "+42", " 42", "42.0"}) {
    std::error_code error;
    ASSERT_TRUE(std::filesystem::create_directory(directory.path() + "/" + std::string(name), error));
    ASSERT_FALSE(error);
  }
  ASSERT_TRUE(write_file(directory.path() + "/frida/comm", "frida-fake\n"));
  EXPECT_EQ(observe_threads(directory.path()), threads({"gum-js-loop"}));
}

TEST(Hooks, observeThreads_whenNumericLimitHasStrayEntry_doesNotCountOrReadIt) {
  const TemporaryDirectory directory;
  ASSERT_FALSE(directory.path().empty());
  for (int thread_id = 1; thread_id <= 4096; ++thread_id) {
    ASSERT_TRUE(write_thread(directory.path(), thread_id, "worker"));
  }
  ASSERT_TRUE(write_file(directory.path() + "/not-a-tid", ""));
  EXPECT_EQ(observe_threads(directory.path()), threads({}));
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
TEST(Hooks, hooks_whenLoadedWatchedCodeChanges_reachesActualCollectorAndPlugins) {
  void* const libc = dlopen(RASP_TEST_WATCHED_LIBC, RTLD_NOW | RTLD_LOCAL);
  ASSERT_NE(libc, nullptr);
  void* const libdl = dlopen(RASP_TEST_WATCHED_LIBDL, RTLD_NOW | RTLD_LOCAL);
  ASSERT_NE(libdl, nullptr);
  const auto stock = hooks();
  ASSERT_EQ(stock.size(), 5);
  EXPECT_EQ(stock[4], inline_hooks({}));
  void* const address = dlsym(libc, "open");
  ASSERT_NE(address, nullptr);
  const long page_size = sysconf(_SC_PAGESIZE);
  ASSERT_GT(page_size, 0);
  const auto integer = std::bit_cast<std::uintptr_t>(address);
  void* const page = std::bit_cast<void*>(integer - (integer % static_cast<std::uintptr_t>(page_size)));
  std::uint8_t original = 0;
  std::memcpy(&original, address, 1);
  ASSERT_EQ(mprotect(page, static_cast<std::size_t>(page_size), PROT_READ | PROT_WRITE), 0);
  const std::uint8_t changed = original ^ 0xFFU;
  std::memcpy(address, &changed, 1);
  ASSERT_EQ(mprotect(page, static_cast<std::size_t>(page_size), PROT_READ | PROT_EXEC), 0);
  const auto patched = hooks();
  ASSERT_EQ(mprotect(page, static_cast<std::size_t>(page_size), PROT_READ | PROT_WRITE), 0);
  std::memcpy(address, &original, 1);
  ASSERT_EQ(mprotect(page, static_cast<std::size_t>(page_size), PROT_READ | PROT_EXEC), 0);
  const auto restored = hooks();
  EXPECT_EQ(dlclose(libdl), 0);
  EXPECT_EQ(dlclose(libc), 0);
  ASSERT_EQ(patched.size(), 5);
  EXPECT_EQ(patched[4], inline_hooks({"open"}));
  ASSERT_EQ(restored.size(), 5);
  EXPECT_EQ(restored[4], inline_hooks({}));
  plugins::Context context;
  const plugins::Plugin plugin{.init = nullptr, .checks = {}, .on_observations = capture_observations};
  const std::array plugins{&plugin};
  EXPECT_EQ(plugins::run_plugins(plugins, patched, context), patched);
  EXPECT_EQ(context.get(kCapturedObservations), patched);
}

TEST(Hooks, hooks_whenAndroidBranchRuns_readsOwnThreadsAndPreservesPluginContract) {
  std::array<char, 16> original{};
  ASSERT_EQ(pthread_getname_np(pthread_self(), original.data(), original.size()), 0);
  ASSERT_EQ(pthread_setname_np(pthread_self(), "gum-js-loop"), 0);
  const std::vector<Observation> observations = hooks();
  const int renamed = pthread_setname_np(pthread_self(), "ordinary-worker");
  const std::vector<Observation> renamed_observations = hooks();
  ASSERT_EQ(pthread_setname_np(pthread_self(), original.data()), 0);
  ASSERT_EQ(renamed, 0);
  ASSERT_EQ(renamed_observations.size(), 5);
  EXPECT_EQ(renamed_observations[3], threads({}));
  ASSERT_EQ(observations.size(), 5);
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
          {.signal = "hook.inline", .source = "prologue", .status = Status::kUnsupported, .value = {}},
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
