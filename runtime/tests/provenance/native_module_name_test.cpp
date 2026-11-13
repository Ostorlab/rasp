/// Actual mapped/guard-page availability regressions through the native loader adapter's memory-copy path.
#include <array>
#include <cstddef>
#include <cstring>
#include <elf.h>
#include <gtest/gtest.h>
#include <link.h>
#include <span>
#include <string>
#include <sys/mman.h>
#include <unistd.h>
#include <variant>

#include "checks/module_provenance.h"
#include "rasp/observation.h"

namespace {
/// Name pointer supplied only to the public iterator boundary in this dedicated test executable.
const char*& iterator_name() {
  static const char* name = nullptr;
  return name;
}
}  // namespace
/// Linker wrapper changes only native iterator metadata; process_vm_readv and real VM protection remain intact.
extern "C" int real_iterator(int (*callback)(dl_phdr_info*, std::size_t, void*),
                             void* context) asm("__real_dl_iterate_phdr");
extern "C" int wrapped_iterator(int (*callback)(dl_phdr_info*, std::size_t, void*),
                                void* context) asm("__wrap_dl_iterate_phdr");
extern "C" int wrapped_iterator(int (*callback)(dl_phdr_info*, std::size_t, void*), void* context) {
  if (iterator_name() == nullptr) {
    return real_iterator(callback, context);
  }
  ElfW(Phdr) header{};
  header.p_type = PT_LOAD;
  header.p_flags = PF_R | PF_X;
  header.p_vaddr = 0x1000;
  header.p_memsz = 0x1000;
  header.p_filesz = 0x1000;
  dl_phdr_info info{};
  info.dlpi_name = iterator_name();
  info.dlpi_phdr = &header;
  info.dlpi_phnum = 1;
  return callback(&info, sizeof(info), context);
}
namespace {
/// Owns actual readable and inaccessible neighboring pages, with no signal handler or fault recovery.
class NativeModuleNameTest : public testing::Test {
 protected:
  /// Allocates real pages and removes all access from the second page.
  void SetUp() override {
    const auto size = sysconf(_SC_PAGESIZE);
    ASSERT_GT(size, 0);
    size_ = static_cast<std::size_t>(size);
    void* allocation = mmap(nullptr, size_ * 2, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    ASSERT_NE(allocation, MAP_FAILED);
    memory_ = static_cast<char*>(allocation);
    ASSERT_EQ(mprotect(memory().subspan(size_).data(), size_, PROT_NONE), 0);
  }
  /// Restores no process-wide state; releases only owned fixture memory.
  void TearDown() override {
    iterator_name() = nullptr;
    if (memory_ != nullptr) {
      EXPECT_EQ(munmap(memory_, size_ * 2), 0);
    }
  }
  std::span<char> memory() { return {memory_, size_ * 2}; }
  [[nodiscard]] std::size_t page_size() const { return size_; }

 private:
  char* memory_ = nullptr;
  std::size_t size_ = 0;
};
TEST_F(NativeModuleNameTest, native_whenValidTerminatorPrecedesUnreadablePage_doesNotRejectName) {
  constexpr std::array kName{'/', 'v', 'a', 'l', 'i', 'd', '.', 's', 'o', '\0'};
  char* start = memory().subspan(page_size() - kName.size()).data();
  std::memcpy(start, kName.data(), kName.size());
  iterator_name() = start;
  const auto rows = rasp::android::checks::collect_module_provenance({});
  EXPECT_EQ(rows[2].status, rasp::Status::kOk) << rasp::describe(rows[3]);
}
TEST_F(NativeModuleNameTest, native_whenPointerIsInsideUnreadablePage_returnsErrorWithoutDereference) {
  iterator_name() = memory().subspan(page_size()).data();
  const auto rows = rasp::android::checks::collect_module_provenance({});
  EXPECT_EQ(rows[2].status, rasp::Status::kError);
  EXPECT_TRUE(std::holds_alternative<std::monostate>(rows[2].value));
}
TEST_F(NativeModuleNameTest, native_whenNameHasNoTerminatorWithinLimit_returnsErrorWithoutOverread) {
  ASSERT_GE(page_size(), 4096U);
  char* start = memory().subspan(page_size() - 4096).data();
  std::memset(start, 'a', 4096);
  iterator_name() = start;
  const auto rows = rasp::android::checks::collect_module_provenance({});
  EXPECT_EQ(rows[2].status, rasp::Status::kError);
  EXPECT_NE(rasp::describe(rows[3]).find("reason=input_limit"), std::string::npos);
}
}  // namespace
