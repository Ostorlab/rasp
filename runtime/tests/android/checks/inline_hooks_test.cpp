#include "checks/inline_hooks.h"

#include <array>
#include <bit>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <gtest/gtest.h>
#include <memory>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include "rasp/observation.h"
#include "rasp/util/read_file.h"
#include "support/files.h"
#include "util/raw_file.h"

namespace rasp::android::checks {
namespace {

using test_support::TemporaryDirectory;
using test_support::write_file;

/// Where the function bytes start in the stand-in library file.
constexpr std::size_t kFileOffset = 0x100;

/// The hook.inline observation that reports `findings`.
[[nodiscard]] Observation inline_hooks_found(std::vector<std::string> findings) {
  return {.signal = "hook.inline", .source = "memory_file", .status = Status::kOk, .value = std::move(findings)};
}

[[nodiscard]] std::string hex(std::uintptr_t value) {
  std::array<char, 2 * sizeof(value)> digits{};
  const auto [end, error] = std::to_chars(digits.data(), std::to_address(digits.end()), value, 16);
  return error == std::errc{} ? std::string(digits.data(), end) : std::string();
}

/// The readers of a test: regular files for the map, and the process's real memory.
[[nodiscard]] rasp::util::ProcessAccess test_access() {
  return {
      .read = rasp::util::read_file,
      .read_memory = rasp::util::read_own_memory,
      .open = rasp::util::open_file,
  };
}

/// Accepts the stand-in libc of a test, whatever folder it is in.
[[nodiscard]] bool is_test_libc(std::string_view path) { return path.ends_with("/libc.so"); }

/// A function in memory, a stand-in libc file that holds the same bytes, and the map that ties them together.
class InlineHooksTest : public testing::Test {
 protected:
  void SetUp() override {
    ASSERT_FALSE(directory_.path().empty());
    for (std::size_t index = 0; index < code_.size(); ++index) {
      code_.at(index) = static_cast<char>(0x40 + index);
    }
    library_ = directory_.path() + "/libc.so";
    ASSERT_TRUE(write_file(library_, std::string(kFileOffset, '\0') + std::string(code_.begin(), code_.end())));
  }

  /// The address of the function's code.
  [[nodiscard]] std::uintptr_t code_start() const { return std::bit_cast<std::uintptr_t>(code_.data()); }

  /// A map line over the function's code, with `permissions` and `pathname`.
  [[nodiscard]] std::string code_line(std::string_view permissions, std::string_view pathname) const {
    return hex(code_start()) + "-" + hex(code_start() + code_.size()) + " " + std::string(permissions) + " " +
           hex(kFileOffset) + " fd:00 7 " + std::string(pathname) + "\n";
  }

  /// Runs the check over `maps` for one target at `address`.
  [[nodiscard]] std::vector<Observation> observe(std::string_view maps, std::uintptr_t address) const {
    const std::string path = directory_.path() + "/maps";
    if (!write_file(path, maps)) {
      return {};
    }
    const std::array<HookTarget, 1> targets = {{{.name = "openat", .address = address}}};
    return observe_inline_hooks(path, targets, is_test_libc, test_access());
  }

  /// Patches the function's code at `index` with `byte`.
  void patch(std::size_t index, char byte) { code_.at(index) = byte; }

  /// The number of bytes of the function's code.
  [[nodiscard]] std::size_t code_size() const { return code_.size(); }

  /// The stand-in libc file.
  [[nodiscard]] const std::string& library() const { return library_; }

  /// The test's folder.
  [[nodiscard]] const std::string& directory() const { return directory_.path(); }

 private:
  TemporaryDirectory directory_;
  std::array<char, 64> code_{};
  std::string library_;
};

TEST_F(InlineHooksTest, observeInlineHooks_whenTheFunctionStartsAsInItsFile_reportsNothing) {
  EXPECT_EQ(observe(code_line("r-xp", library()), code_start() + 8), std::vector{inline_hooks_found({})});
}

TEST_F(InlineHooksTest, observeInlineHooks_whenTheFunctionStartWasPatched_reportsTheFunction) {
  patch(10, '\x14');

  EXPECT_EQ(observe(code_line("r-xp", library()), code_start() + 8), std::vector{inline_hooks_found({"openat"})});
}

TEST_F(InlineHooksTest, observeInlineHooks_whenThePatchIsPastTheStart_reportsNothing) {
  patch(40, '\x14');

  EXPECT_EQ(observe(code_line("r-xp", library()), code_start() + 8), std::vector{inline_hooks_found({})});
}

TEST_F(InlineHooksTest, observeInlineHooks_whenTheFunctionEndsItsMapping_comparesWhatIsMapped) {
  EXPECT_EQ(observe(code_line("r-xp", library()), code_start() + code_size() - 4), std::vector{inline_hooks_found({})});
}

TEST_F(InlineHooksTest, observeInlineHooks_whenTheFunctionIsInAnotherLibrary_reportsWhereItIs) {
  EXPECT_EQ(observe(code_line("r-xp", "/data/local/tmp/libhook.so"), code_start() + 8),
            std::vector{inline_hooks_found({"openat -> /data/local/tmp/libhook.so"})});
}

TEST_F(InlineHooksTest, observeInlineHooks_whenTheFunctionIsInAnonymousMemory_reportsIt) {
  EXPECT_EQ(observe(code_line("r-xp", ""), code_start() + 8), std::vector{inline_hooks_found({"openat -> [anon]"})});
}

TEST_F(InlineHooksTest, observeInlineHooks_whenTheFunctionIsInNoMapping_reportsIt) {
  EXPECT_EQ(observe(code_line("r-xp", library()), code_start() + code_size()),
            std::vector{inline_hooks_found({"openat -> [unmapped]"})});
}

TEST_F(InlineHooksTest, observeInlineHooks_whenTheMappingIsNotExecutable_reportsIt) {
  EXPECT_EQ(observe(code_line("r--p", library()), code_start() + 8),
            std::vector{inline_hooks_found({"openat -> " + library()})});
}

TEST_F(InlineHooksTest, observeInlineHooks_whenTheLibraryWasDeleted_reportsIt) {
  EXPECT_EQ(observe(code_line("r-xp", library() + " (deleted)"), code_start() + 8),
            std::vector{inline_hooks_found({"openat -> " + library() + " (deleted)"})});
}

TEST_F(InlineHooksTest, observeInlineHooks_whenTheLibraryFileCantBeRead_reportsAnError) {
  const std::string missing = directory() + "/missing/libc.so";

  EXPECT_EQ(observe(code_line("r-xp", missing), code_start() + 8),
            std::vector<Observation>{failed("hook.inline", "memory_file")});
}

TEST_F(InlineHooksTest, observeInlineHooks_whenTheMapCantBeRead_reportsAnError) {
  const std::array<HookTarget, 1> targets = {{{.name = "openat", .address = code_start()}}};

  EXPECT_EQ(observe_inline_hooks(directory() + "/no_maps", targets, is_test_libc, test_access()),
            std::vector<Observation>{failed("hook.inline", "memory_file")});
}

TEST(InlineHooks, isSystemLibc_whenThePathIsThePlatformsLibcOrLibdl_acceptsIt) {
  EXPECT_TRUE(is_system_libc("/apex/com.android.runtime/lib64/bionic/libc.so"));
  EXPECT_TRUE(is_system_libc("/apex/com.android.runtime/lib64/bionic/libdl.so"));
  EXPECT_TRUE(is_system_libc("/system/lib64/arm64/libc.so"));
}

TEST(InlineHooks, isSystemLibc_whenThePathIsAnotherFile_refusesIt) {
  EXPECT_FALSE(is_system_libc("/data/local/tmp/libc.so"));
  EXPECT_FALSE(is_system_libc("/apex/com.android.runtime/lib64/bionic/libm.so"));
  EXPECT_FALSE(is_system_libc("/system/lib64/libc.so.bak"));
  EXPECT_FALSE(is_system_libc("libc.so"));
}

TEST(InlineHooks, inlineHooks_offAndroid_isUnsupported) {
  EXPECT_EQ(inline_hooks(), std::vector<Observation>{unsupported("hook.inline", "memory_file")});
}

}  // namespace
}  // namespace rasp::android::checks
