#include "checks/code_origin.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <bit>
#include <charconv>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <gtest/gtest.h>
#include <memory>
#include <optional>
#include <pthread.h>
#include <string>
#include <string_view>
#include <sys/mman.h>
#include <system_error>
#include <thread>
#include <unistd.h>
#include <utility>
#include <variant>
#include <vector>

#include "rasp/observation.h"
#include "rasp/util/read_file.h"
#include "support/files.h"
#include "util/memory_map.h"
#include "util/raw_file.h"

namespace rasp::android::checks {
namespace {

using test_support::TemporaryDirectory;
using test_support::write_file;
using Strings = std::vector<std::string>;

/// The app of the tests, with its runtime's image at a fixed address range.
constexpr OwnCode kOwn{.image_start = 0x40000000, .image_end = 0x40100000, .package = "co.app"};
/// No runtime image and no package, so only installed files and kernel code are expected.
constexpr OwnCode kNoOwnCode{.image_start = 0, .image_end = 0, .package = ""};
/// A system libc's code.
constexpr std::string_view kLibcLine = "10000000-10100000 r-xp 00000000 fd:00 200 /apex/com.android.runtime/libc.so";
/// The address of an instruction in kLibcLine.
constexpr std::uintptr_t kInLibc = 0x10000400;
/// Anonymous executable memory.
constexpr std::string_view kAnonymousLine = "20000000-20010000 r-xp 00000000 00:00 0";
/// The address of an instruction in kAnonymousLine.
constexpr std::uintptr_t kInAnonymous = 0x20000040;
/// The words of each crafted thread stack.
constexpr std::size_t kStackWords = 32;

/// An address range in memory.
struct Region {
  std::uintptr_t start = 0;
  std::size_t size = 0;
};

/// The range `bytes` occupies.
template <typename T, std::size_t N>
[[nodiscard]] Region region_of(const std::array<T, N>& bytes) {
  return {.start = std::bit_cast<std::uintptr_t>(bytes.data()), .size = sizeof(T) * N};
}

[[nodiscard]] std::string hex(std::uintptr_t value) {
  std::array<char, 2 * sizeof(value)> digits{};
  const auto [end, error] = std::to_chars(digits.data(), std::to_address(digits.end()), value, 16);
  return error == std::errc{} ? std::string(digits.data(), end) : std::string();
}

/// A map line over `region`, with `permissions`, `offset`, `inode` and `pathname`.
[[nodiscard]] std::string line_over(Region region, std::string_view permissions, std::uintptr_t offset,
                                    std::string_view inode, std::string_view pathname) {
  return hex(region.start) + "-" + hex(region.start + region.size) + " " + std::string(permissions) + " " +
         hex(offset) + " 00:01 " + std::string(inode) + " " + std::string(pathname);
}

/// The readers of the tests: regular files, and the process's real memory.
[[nodiscard]] rasp::util::ProcessAccess test_access() {
  return {
      .read = rasp::util::read_file,
      .read_memory = rasp::util::read_own_memory,
      .open = rasp::util::open_file,
  };
}

[[nodiscard]] Observation exec_origin(Strings lines) {
  return {.signal = "hook.exec_origin", .source = "proc_maps", .status = Status::kOk, .value = std::move(lines)};
}

[[nodiscard]] Observation code_origin_found(Strings findings) {
  return {.signal = "hook.code_origin", .source = "thread_stacks", .status = Status::kOk, .value = std::move(findings)};
}

/// A thread of a crafted process.
struct Thread {
  std::string_view id;
  std::string_view name;
};

/// A crafted process: a memory map, a thread list with names, and thread stacks in real memory.
class CodeOriginTest : public testing::Test {
 protected:
  void SetUp() override {
    ASSERT_FALSE(directory_.path().empty());
    task_ = directory_.path() + "/task";
    std::error_code error;
    ASSERT_TRUE(std::filesystem::create_directory(task_, error));
  }

  /// Names `thread` in the thread list.
  void add_thread(const Thread& thread) const {
    const std::string folder = task_ + "/" + std::string(thread.id);
    std::error_code error;
    ASSERT_TRUE(std::filesystem::create_directory(folder, error));
    ASSERT_TRUE(write_file(folder + "/comm", std::string(thread.name) + "\n"));
  }

  /// Names the main thread.
  void name_main_thread(std::string_view name) const {
    ASSERT_TRUE(write_file(directory_.path() + "/comm", std::string(name) + "\n"));
  }

  /// Puts `word` on the crafted stack `stack` at `index`.
  void keep_on_stack(std::size_t stack, std::size_t index, std::uintptr_t word) {
    stacks_.at((stack * kStackWords) + index) = word;
  }

  /// The map line of the crafted stack `stack`, named `pathname`.
  [[nodiscard]] std::string stack_line(std::size_t stack, std::string_view pathname) const {
    constexpr std::size_t kStackBytes = kStackWords * sizeof(std::uintptr_t);
    const Region region{.start = region_of(stacks_).start + (stack * kStackBytes), .size = kStackBytes};
    return line_over(region, "rw-p", 0, "0", pathname);
  }

  /// Runs the checks over the map made of `lines`, sorted into address order as the kernel writes it.
  [[nodiscard]] std::vector<Observation> observe(std::vector<std::string> lines) const {
    std::ranges::sort(lines, {}, [](const std::string& line) {
      const std::vector<util::Mapping> parsed = util::parse_memory_map(line);
      return parsed.empty() ? std::uintptr_t{0} : parsed.front().start;
    });
    std::string maps;
    for (const std::string& line : lines) {
      maps += line + "\n";
    }
    const std::string path = directory_.path() + "/maps";
    if (!write_file(path, maps)) {
      return {};
    }
    const std::string comm = directory_.path() + "/comm";
    return observe_code_origin({.maps = path, .task = task_, .comm = comm}, kOwn, test_access());
  }

  /// The test's folder.
  [[nodiscard]] const std::string& directory() const { return directory_.path(); }

 private:
  TemporaryDirectory directory_;
  std::string task_;
  std::array<std::uintptr_t, 3 * kStackWords> stacks_{};
};

TEST_F(CodeOriginTest, observeCodeOrigin_whenEveryMappingIsExpected_reportsNothing) {
  keep_on_stack(0, 5, kInLibc);
  add_thread({.id = "101", .name = "main"});

  EXPECT_EQ(observe({std::string(kLibcLine), stack_line(0, "[anon:stack_and_tls:101]")}),
            (std::vector{exec_origin({}), code_origin_found({})}));
}

TEST_F(CodeOriginTest, observeCodeOrigin_whenAThreadsStackHoldsAnAddressOfForeignCode_reportsTheThread) {
  keep_on_stack(0, 5, kInAnonymous);
  add_thread({.id = "101", .name = "qdmzZ"});

  EXPECT_EQ(observe({std::string(kLibcLine), std::string(kAnonymousLine), stack_line(0, "[anon:stack_and_tls:101]")}),
            (std::vector{exec_origin({std::string(kAnonymousLine)}), code_origin_found({"qdmzZ -> [anon]"})}));
}

TEST_F(CodeOriginTest, observeCodeOrigin_whenTheMainStackHoldsAnAddressOfForeignCode_reportsTheMainThread) {
  keep_on_stack(0, kStackWords - 1, kInAnonymous);
  name_main_thread("co.app");

  EXPECT_EQ(observe({std::string(kAnonymousLine), stack_line(0, "[stack]")}),
            (std::vector{exec_origin({std::string(kAnonymousLine)}), code_origin_found({"co.app -> [anon]"})}));
}

TEST_F(CodeOriginTest, observeCodeOrigin_whenTheStacksHoldOnlyExpectedAddresses_reportsOnlyTheMapping) {
  keep_on_stack(0, 5, kInLibc);
  add_thread({.id = "101", .name = "main"});

  EXPECT_EQ(observe({std::string(kLibcLine), std::string(kAnonymousLine), stack_line(0, "[anon:stack_and_tls:101]")}),
            (std::vector{exec_origin({std::string(kAnonymousLine)}), code_origin_found({})}));
}

TEST_F(CodeOriginTest, observeCodeOrigin_whenTheMappingIsNotAThreadStack_skipsIt) {
  keep_on_stack(0, 5, kInAnonymous);
  keep_on_stack(1, 5, kInAnonymous);

  EXPECT_EQ(observe({std::string(kAnonymousLine), stack_line(0, "[anon:stack_and_tls:abc]"),
                     stack_line(1, "[anon:libc_malloc]")}),
            (std::vector{exec_origin({std::string(kAnonymousLine)}), code_origin_found({})}));
}

TEST_F(CodeOriginTest, observeCodeOrigin_whenTheThreadNameCantBeRead_reportsTheThreadId) {
  keep_on_stack(0, 5, kInAnonymous);

  EXPECT_EQ(observe({std::string(kAnonymousLine), stack_line(0, "[anon:stack_and_tls:101]")}),
            (std::vector{exec_origin({std::string(kAnonymousLine)}), code_origin_found({"101 -> [anon]"})}));
}

TEST_F(CodeOriginTest, observeCodeOrigin_whenSeveralThreadsHoldAddresses_reportsEachOnceInOrder) {
  keep_on_stack(0, 1, kInAnonymous);
  keep_on_stack(1, 2, kInAnonymous);
  keep_on_stack(2, 3, kInAnonymous);
  add_thread({.id = "101", .name = "pool-2"});
  add_thread({.id = "102", .name = "gmain"});
  add_thread({.id = "103", .name = "gmain"});

  EXPECT_EQ(observe({std::string(kAnonymousLine), stack_line(0, "[anon:stack_and_tls:101]"),
                     stack_line(1, "[anon:stack_and_tls:102]"), stack_line(2, "[anon:stack_and_tls:103]")}),
            (std::vector{exec_origin({std::string(kAnonymousLine)}),
                         code_origin_found({"gmain -> [anon]", "pool-2 -> [anon]"})}));
}

TEST_F(CodeOriginTest, observeCodeOrigin_whenNoThreadStackCanBeRead_reportsAnErrorForTheThreads) {
  void* const page = mmap(nullptr, 4096, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  ASSERT_NE(page, MAP_FAILED);
  ASSERT_EQ(munmap(page, 4096), 0);
  const std::string unmapped_stack =
      line_over({.start = std::bit_cast<std::uintptr_t>(page), .size = 4096}, "rw-p", 0, "0", "[stack]");

  EXPECT_EQ(observe({std::string(kAnonymousLine), unmapped_stack}),
            (std::vector{exec_origin({std::string(kAnonymousLine)}), failed("hook.code_origin", "thread_stacks")}));
}

TEST_F(CodeOriginTest, observeCodeOrigin_whenTheMapCantBeRead_reportsErrors) {
  const std::string maps = directory() + "/no_maps";

  EXPECT_EQ(observe_code_origin({.maps = maps, .task = directory(), .comm = directory()}, kOwn, test_access()),
            (std::vector{failed("hook.exec_origin", "proc_maps"), failed("hook.code_origin", "thread_stacks")}));
}

TEST_F(CodeOriginTest, observeCodeOrigin_forInstalledAndKernelCode_reportsNothing) {
  const std::vector<std::string> lines = {
      "10000000-10001000 r-xp 00000000 fd:00 1 /system/lib64/libandroid_runtime.so",
      "10001000-10002000 r-xp 00000000 fd:00 1 /system_ext/lib64/libfoo.so",
      "10002000-10003000 r-xp 00000000 fd:00 1 /product/lib64/libfoo.so",
      "10003000-10004000 r-xp 00000000 fd:00 1 /vendor/lib64/libfoo.so",
      "10004000-10005000 r-xp 00000000 fd:00 1 /odm/lib64/libfoo.so",
      "10005000-10006000 r-xp 00000000 fd:00 1 /apex/com.android.art/lib64/libart.so",
      "10006000-10007000 r-xp 00000000 fd:00 1 /data/app/~~a==/co.app-1/base.apk",
      "10007000-10008000 r-xp 00000000 fd:00 1 /data/dalvik-cache/arm64/system@framework@boot.oat",
      "10008000-10009000 r-xp 00000000 fd:00 1 /data/misc/apexdata/com.android.art/dalvik-cache/arm64/boot.oat",
      "10009000-1000a000 r-xp 00000000 fd:00 1 /data/data/co.app/app_lib/libextracted.so",
      "1000a000-1000b000 r-xp 00000000 fd:00 1 /data/user/10/co.app/files/libextracted.so",
      "1000b000-1000c000 r-xp 00000000 fd:00 1 /data/user_de/0/co.app/lib/libextracted.so",
      "1000c000-1000d000 r-xp 00000000 fd:00 1 /data/user_de/0/com.google.android.gms/app_chimera/m/1/Cronet.apk",
      "1000d000-1000e000 r-xp 00000000 00:00 0 [vdso]",
      "1000e000-1000f000 r-xp 00000000 00:00 0 [vectors]",
      "1000f000-10010000 r-xp 00000000 00:00 0 [sigpage]",
      "10010000-10011000 r-xp 00000000 fd:00 1 /mnt/expand/0e4c5a2d-1b6f/app/~~a==/co.app-1/lib/arm64/libapp.so",
      "10011000-10012000 r-xp 00000000 fd:00 1 /mnt/expand/0e4c5a2d-1b6f/app/~~a==/co.app-1/oat/arm64/base.odex",
      "10012000-10013000 r-xp 00000000 fd:00 1 /mnt/expand/0e4c5a2d-1b6f/user/0/co.app/files/libextracted.so",
      "10013000-10014000 r-xp 00000000 fd:00 1 /mnt/expand/0e4c5a2d-1b6f/user_de/10/co.app/lib/libextracted.so",
      "40001000-40002000 r-xp 00000000 00:00 0",
      "ffffffffff600000-ffffffffff601000 --xp 00000000 00:00 0 [vsyscall]",
  };

  EXPECT_EQ(observe(lines), (std::vector{exec_origin({}), code_origin_found({})}));
}

TEST_F(CodeOriginTest, observeCodeOrigin_forCodeNoInstalledFileBacks_reportsEachMapping) {
  const std::vector<std::string> lines = {
      "10000000-10001000 r-xp 00000000 fd:00 1 /data/local/tmp/re.frida.server/frida-agent-64.so",
      "10001000-10002000 r-xp 00000000 fd:00 1 /data/data/com.other/lib/libother.so",
      "10002000-10003000 r-xp 00000000 fd:00 1 /data/user_de/0/com.google.android.gms/files/libplugin.so",
      "10003000-10004000 r-xp 00000000 fd:00 1 /data/user/abc/co.app/lib/libfoo.so",
      "10004000-10005000 r-xp 00000000 00:01 7 /memfd:frida-agent-64.so (deleted)",
      "10005000-10006000 r-xp 00000000 fd:00 1 /system/lib64/libinjected.so (deleted)",
      "10006000-10007000 r-xp 00000000 00:00 0 [uprobes]",
      "10007000-10008000 r-xp 00000000 00:00 0 [anon:gum-code]",
      "10008000-10009000 r-xp 00000000 00:00 0",
      "10009000-1000a000 r-xp 00000000 00:00 0 [anon:dalvik-jit-code-cache]",
      "1000a000-1000b000 r-xs 00000000 00:05 9 /dev/ashmem/dalvik-jit-code-cache (deleted)",
      "1000b000-1000c000 r-xp 00000000 fd:00 1 /mnt/expand/0e4c5a2d-1b6f/user/0/com.other/lib/libother.so",
      "1000c000-1000d000 r-xp 00000000 fd:00 1 /mnt/expand/0e4c5a2d-1b6f/media/0/libfoo.so",
      "1000d000-1000e000 r-xp 00000000 fd:00 1 /mnt/expand//app/co.app-1/lib/arm64/libapp.so",
  };

  EXPECT_EQ(observe(lines), (std::vector{exec_origin(lines), code_origin_found({})}));
}

TEST_F(CodeOriginTest, observeCodeOrigin_forMemoryThatIsNotExecutable_reportsNothing) {
  const std::vector<std::string> lines = {
      "10000000-10001000 rw-p 00000000 00:00 0",
      "10001000-10002000 r--p 00000000 fd:00 1 /data/local/tmp/frida-agent-64.so",
  };

  EXPECT_EQ(observe(lines), (std::vector{exec_origin({}), code_origin_found({})}));
}

TEST_F(CodeOriginTest, observeCodeOrigin_forTheArtJitMemfdWithAPlainStart_reportsNothing) {
  const std::array<char, 16> data_view{};
  const std::vector<std::string> lines = {
      line_over(region_of(data_view), "r--s", 0, "251", "/memfd:jit-cache (deleted)"),
      "20000000-20010000 r-xs 02000000 00:01 251 /memfd:jit-cache (deleted)",
  };

  EXPECT_EQ(observe(lines), (std::vector{exec_origin({}), code_origin_found({})}));
}

TEST_F(CodeOriginTest, observeCodeOrigin_forAnElfLibraryNamedLikeTheArtJit_reportsIt) {
  const std::array<char, 16> elf_header = {'\x7f', 'E', 'L', 'F', '\x02', '\x01', '\x01'};
  const std::string code = "20000000-20010000 r-xs 00001000 00:01 252 /memfd:jit-cache (deleted)";
  const std::vector<std::string> lines = {
      line_over(region_of(elf_header), "r--s", 0, "252", "/memfd:jit-cache (deleted)"),
      code,
  };

  EXPECT_EQ(observe(lines), (std::vector{exec_origin({code}), code_origin_found({})}));
}

TEST_F(CodeOriginTest, observeCodeOrigin_forAPrivateMappingNamedLikeTheArtJit_reportsIt) {
  const std::array<char, 16> data_view{};
  const std::string code = "20000000-20010000 r-xp 02000000 00:01 254 /memfd:jit-cache (deleted)";
  const std::vector<std::string> lines = {
      line_over(region_of(data_view), "r--p", 0, "254", "/memfd:jit-cache (deleted)"),
      code,
  };

  EXPECT_EQ(observe(lines), (std::vector{exec_origin({code}), code_origin_found({})}));
}

TEST_F(CodeOriginTest, observeCodeOrigin_forAnArtJitMemfdWithoutItsStart_reportsIt) {
  const std::string code = "20000000-20010000 r-xs 02000000 00:01 253 /memfd:jit-zygote-cache (deleted)";

  EXPECT_EQ(observe({code}), (std::vector{exec_origin({code}), code_origin_found({})}));
}

TEST(CodeOrigin, codeOrigin_offAndroid_isUnsupported) {
  EXPECT_EQ(code_origin(), (std::vector{unsupported("hook.exec_origin", "proc_maps"),
                                        unsupported("hook.code_origin", "thread_stacks")}));
}

/// What a probe thread shares with the test.
struct Probe {
  /// The foreign code the thread keeps an address of on its stack.
  std::uintptr_t foreign = 0;
  /// The read end of the pipe the thread waits on.
  int wait_fd = -1;
  /// The thread's id, once it runs.
  std::atomic<long> thread_id{0};
  /// An address in the thread's stack, once it runs.
  std::atomic<std::uintptr_t> stack_address{0};
};

/// Names itself, keeps an address of foreign code on its stack, and waits in read until the test writes.
[[clang::no_sanitize("address")]] void* run_probe(void* argument) {
  auto* const probe = static_cast<Probe*>(argument);
  static_cast<void>(pthread_setname_np(pthread_self(), "rasp-probe"));
  volatile std::uintptr_t foreign = probe->foreign;
  probe->stack_address.store(std::bit_cast<std::uintptr_t>(&foreign));
  probe->thread_id.store(static_cast<long>(gettid()));
  char byte = 0;
  static_cast<void>(read(probe->wait_fd, &byte, 1));
  static_cast<void>(foreign);
  return nullptr;
}

/// A real thread that keeps an address of anonymous executable memory on its stack and waits in read until the object
/// goes away.
class ProbeThread {
 public:
  ProbeThread()
      : page_(static_cast<std::size_t>(sysconf(_SC_PAGESIZE))),
        foreign_(mmap(nullptr, page_, PROT_READ | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)) {
    if (foreign_ == MAP_FAILED || pipe(pipe_fds_.data()) != 0) {
      return;
    }
    probe_.foreign = std::bit_cast<std::uintptr_t>(foreign_) + 16;
    probe_.wait_fd = pipe_fds_[0];
    running_ = pthread_create(&thread_, nullptr, run_probe, &probe_) == 0;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{5};
    while (running_ && probe_.thread_id.load() == 0 && std::chrono::steady_clock::now() < deadline) {
      std::this_thread::sleep_for(std::chrono::milliseconds{5});
    }
  }

  ProbeThread(const ProbeThread&) = delete;
  ProbeThread& operator=(const ProbeThread&) = delete;
  ProbeThread(ProbeThread&&) = delete;
  ProbeThread& operator=(ProbeThread&&) = delete;

  ~ProbeThread() {
    if (running_) {
      const char byte = 0;
      static_cast<void>(write(pipe_fds_[1], &byte, 1));
      static_cast<void>(pthread_join(thread_, nullptr));
    }
    for (const int fd : pipe_fds_) {
      if (fd >= 0) {
        static_cast<void>(close(fd));
      }
    }
    if (foreign_ != MAP_FAILED) {
      static_cast<void>(munmap(foreign_, page_));
    }
  }

  /// Whether the thread runs and has published its stack.
  [[nodiscard]] bool running() const { return running_ && probe_.thread_id.load() != 0; }

  /// The thread's id.
  [[nodiscard]] long thread_id() const { return probe_.thread_id.load(); }

  /// An address in the thread's stack.
  [[nodiscard]] std::uintptr_t stack_address() const { return probe_.stack_address.load(); }

  /// The first address of the anonymous executable memory.
  [[nodiscard]] std::uintptr_t foreign_start() const { return std::bit_cast<std::uintptr_t>(foreign_); }

 private:
  std::size_t page_;
  void* foreign_;
  std::array<int, 2> pipe_fds_ = {-1, -1};
  Probe probe_;
  pthread_t thread_{};
  bool running_ = false;
};

/// The process's real memory map with every file path moved under `/system/`, so only memory no file backs is foreign
/// to the checks, and with the probe's stack named as bionic names a thread's stack.
[[nodiscard]] std::string map_as_on_android(const ProbeThread& probe) {
  const std::optional<std::string> maps = rasp::util::read_file("/proc/self/maps", std::size_t{16} << 20U);
  if (!maps) {
    return {};
  }
  constexpr std::string_view kDeleted = " (deleted)";
  std::string rewritten;
  for (const util::Mapping& mapping : util::parse_memory_map(*maps)) {
    std::string line(mapping.line);
    const std::size_t named = mapping.pathname.size() + (mapping.deleted ? kDeleted.size() : 0);
    const std::string unnamed = line.substr(0, line.size() - named);
    if (mapping.start <= probe.stack_address() && probe.stack_address() < mapping.end) {
      line = unnamed + "[anon:stack_and_tls:" + std::to_string(probe.thread_id()) + "]";
    } else if (mapping.pathname.starts_with('/')) {
      line = unnamed + "/system/lib64/installed.so";
    }
    rewritten += line + "\n";
  }
  return rewritten;
}

/// Whether `observation` lists a value that starts with `prefix`.
[[nodiscard]] bool lists_value_starting_with(const Observation& observation, std::string_view prefix) {
  const auto* const values = std::get_if<Strings>(&observation.value);
  return values != nullptr &&
         std::ranges::any_of(*values, [prefix](const std::string& value) { return value.starts_with(prefix); });
}

TEST(CodeOrigin, observeCodeOrigin_whenARealThreadKeepsAnAddressOfAnonymousCode_reportsTheThread) {
  const ProbeThread probe;
  ASSERT_TRUE(probe.running());
  const TemporaryDirectory directory;
  const std::string maps = directory.path() + "/maps";
  ASSERT_TRUE(write_file(maps, map_as_on_android(probe)));

  const std::vector<Observation> observations = observe_code_origin(
      {.maps = maps, .task = "/proc/self/task", .comm = "/proc/self/comm"}, kNoOwnCode, test_access());

  ASSERT_EQ(observations.size(), 2U);
  EXPECT_TRUE(lists_value_starting_with(observations[0], hex(probe.foreign_start()) + "-"));
  EXPECT_TRUE(lists_value_starting_with(observations[1], "rasp-probe -> [anon]"));
}

}  // namespace
}  // namespace rasp::android::checks
