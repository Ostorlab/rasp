/// The intended production VM validation with only typed kernel I/O replaced; portable cases are not SDK evidence.
#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <gtest/gtest.h>
#include <span>
#if defined(__APPLE__) || defined(__linux__)
#include <sys/mman.h>
#include <unistd.h>
#endif
#ifdef __linux__
#include <bits/types/struct_iovec.h>
#include <sys/uio.h>
#endif

#include "rasp/posix/provenance.h"
#include "util/provenance_vm.h"

namespace {
namespace vm = rasp::ios::util::provenance_vm;
using rasp::provenance::Budget;
using rasp::provenance::Error;
/// Captured raw kernel-call arguments, grouped so fixtures can verify exact forwarding.
struct CopyCall {
  std::uint32_t task = 0;
  std::uint64_t address = 0;
  std::uint64_t size = 0;
  std::uint64_t destination = 0;
};
/// In/out request values are retained before the external region boundary writes replies.
struct RegionCall {
  std::uint64_t address = 0;
  std::uint64_t size = 0;
  std::uint32_t count = 0;
  std::uint32_t object = 0;
};
/// Portable kernel return contract; the real binding uses public Mach types/constants, not this model.
struct KernelState {
  CopyCall copy;
  RegionCall region;
  int copy_result = 0;
  std::uint64_t copied = 4;
  int region_result = 0;
  std::uint64_t base = 0x1000;
  std::uint64_t size = 4096;
  std::uint32_t count = 1;
  int protection = 1;
  std::uint32_t object = 42;
  int release_result = 0;
  unsigned copies = 0;
  unsigned queries = 0;
  unsigned releases = 0;
  std::int64_t tick = 1;
  bool expire_during_query = false;
};
/// Each GoogleTest process owns its kernel-boundary state; the collector adds no global object.
KernelState& kernel() {
  static KernelState state;
  return state;
}
/// Explicit monotonic seam keeps kernel-return fixtures independent of scheduler latency.
std::int64_t clock() { return kernel().tick; }
/// Same operation/type contract as the native descriptor; this does not claim a Darwin ABI or header layout.
struct ProbeVm {
  using Address = std::uint64_t;
  using Size = std::uint64_t;
  struct RegionInfo {
    int protection = 0;
  };
  using InfoPointer = int*;
  static constexpr int kSuccess = 0;
  static constexpr int kDenied = 2;
  static constexpr std::uint32_t kNull = 0;
  static constexpr std::uint32_t kDead = UINT32_MAX;
  static constexpr int kRegionFlavor = 9;
  static constexpr std::uint32_t kRegionCount = 1;
  static constexpr int kReadProtection = 1;
  static std::uint32_t self() { return 7; }
  static constexpr auto kCopy = [](std::uint32_t task, Address address, Size size, Address destination, Size* copied) {
    kernel().copy = {.task = task, .address = address, .size = size, .destination = destination};
    EXPECT_EQ(task, self());
    EXPECT_NE(address, 0U);
    EXPECT_NE(destination, 0U);
    EXPECT_EQ(size, 4U);
    ++kernel().copies;
    *copied = kernel().copied;
    return kernel().copy_result;
  };
  static constexpr auto kRegion = [](std::uint32_t task, Address* address, Size* size, int flavor, InfoPointer info,
                                     std::uint32_t* count, std::uint32_t* object) {
    EXPECT_EQ(task, self());
    kernel().region = {.address = *address, .size = *size, .count = *count, .object = *object};
    EXPECT_EQ(flavor, kRegionFlavor);
    EXPECT_EQ(*count, kRegionCount);
    EXPECT_EQ(*object, kNull);
    ++kernel().queries;
    *address = kernel().base;
    *size = kernel().size;
    *count = kernel().count;
    *info = kernel().protection;
    *object = kernel().object;
    if (kernel().expire_during_query) {
      kernel().tick += 100000000;
    }
    return kernel().region_result;
  };
  static constexpr auto kDeallocate = [](std::uint32_t task, std::uint32_t object) {
    EXPECT_EQ(task, self());
    EXPECT_EQ(object, kernel().object);
    ++kernel().releases;
    return kernel().release_result;
  };
};
class IosVmContractTest : public testing::Test {
 protected:
  void SetUp() override { kernel() = {}; }
};
TEST_F(IosVmContractTest, copy_whenKernelReportsExactSuccess_usesOwnTaskAndCallerBuffer) {
  std::array<std::uint8_t, 4> bytes{};
  Budget budget(clock);
  EXPECT_TRUE(vm::copy<ProbeVm>(0x1000, bytes, budget).has_value());
  EXPECT_EQ(kernel().copies, 1U);
  EXPECT_EQ(kernel().copy.address, 0x1000U);
  EXPECT_EQ(kernel().copy.size, bytes.size());
  EXPECT_EQ(kernel().copy.destination, std::bit_cast<std::uintptr_t>(bytes.data()));
}
TEST_F(IosVmContractTest, copy_whenDeniedUnmappedUnknownShortOrOverlong_neverAcceptsPartialSuccess) {
  std::array<std::uint8_t, 4> bytes{};
  for (const auto result : {0, 1, 2, 999}) {
    for (const auto copied : {0U, 3U, 4U, 5U}) {
      kernel().copy_result = result;
      kernel().copied = copied;
      Budget budget(clock);
      const auto read = vm::copy<ProbeVm>(0x1000, bytes, budget);
      if (result == 0 && copied == bytes.size()) {
        EXPECT_TRUE(read.has_value());
      } else {
        ASSERT_FALSE(read.has_value());
        EXPECT_EQ(read.error(), result == 2 ? Error::kDenied : Error::kIo);
      }
    }
  }
}
TEST_F(IosVmContractTest, copy_whenSourceIsNullOrWraps_refusesBeforeKernelIO) {
  std::array<std::uint8_t, 4> bytes{};
  for (const auto address : {std::uintptr_t{0}, UINTPTR_MAX - 2}) {
    Budget budget(clock);
    const auto read = vm::copy<ProbeVm>(address, bytes, budget);
    ASSERT_FALSE(read.has_value());
    EXPECT_EQ(read.error(), Error::kMalformed);
  }
  EXPECT_EQ(kernel().copies, 0U);
}
TEST_F(IosVmContractTest, region_whenReadableAndCovering_clampsToChunkAndReleasesExactlyOnce) {
  for (const auto pointer : {std::uintptr_t{0x1000}, std::uintptr_t{0x1fff}}) {
    kernel().releases = 0;
    Budget budget(clock);
    const auto extent = vm::region_bytes<ProbeVm>(pointer, budget);
    ASSERT_TRUE(extent.has_value());
    EXPECT_EQ(*extent, pointer == 0x1000 ? 256U : 1U);
    EXPECT_EQ(kernel().region.address, pointer);
    EXPECT_EQ(kernel().region.size, 0U);
    EXPECT_EQ(kernel().releases, 1U);
  }
}
TEST_F(IosVmContractTest, region_whenQueryCountExtentProtectionOrCoverageInvalid_stillReleasesReturnedPort) {
  for (const auto mode : {0, 1, 2, 3, 4, 5, 6, 7, 8, 9}) {
    kernel() = {};
    auto pointer = std::uintptr_t{0x1000};
    if (mode == 0) {
      kernel().region_result = 1;
    }
    if (mode == 1) {
      kernel().region_result = 2;
    }
    if (mode == 2) {
      kernel().count = 0;
    }
    if (mode == 3) {
      kernel().size = 0;
    }
    if (mode == 4) {
      kernel().base = 0x2000;
    }
    if (mode == 5) {
      kernel().size = 1;
      pointer = 0x1001;
    }
    if (mode == 6) {
      kernel().base = UINT64_MAX - 4;
      kernel().size = 8;
      pointer = UINTPTR_MAX - 1;
    }
    if (mode == 7) {
      kernel().protection = 4;
    }
    if (mode == 8) {
      kernel().count = 2;
    }
    if (mode == 9) {
      kernel().region_result = 999;
    }
    Budget budget(clock);
    const auto extent = vm::region_bytes<ProbeVm>(pointer, budget);
    ASSERT_FALSE(extent.has_value());
    EXPECT_EQ(extent.error(), Error::kIo) << mode;
    EXPECT_EQ(kernel().releases, 1U) << mode;
  }
}
TEST_F(IosVmContractTest, region_whenPortNullOrDead_neverDeallocatesInvalidRights) {
  for (const auto port : {ProbeVm::kNull, ProbeVm::kDead}) {
    for (const auto query : {0, 1, 999}) {
      kernel().object = port;
      kernel().region_result = query;
      Budget budget(clock);
      EXPECT_EQ(vm::region_bytes<ProbeVm>(0x1000, budget).has_value(), query == 0);
      EXPECT_EQ(kernel().releases, 0U);
    }
  }
}
TEST_F(IosVmContractTest, region_whenPointerNull_refusesBeforeKernel) {
  Budget budget(clock);
  const auto result = vm::region_bytes<ProbeVm>(0, budget);
  ASSERT_FALSE(result.has_value());
  EXPECT_EQ(result.error(), Error::kMalformed);
  EXPECT_EQ(kernel().queries, 0U);
  EXPECT_EQ(kernel().releases, 0U);
}
TEST_F(IosVmContractTest, region_whenCleanupFailsEvenAfterQueryFailure_returnsCleanupWithoutRetry) {
  for (const auto query : {0, 1, 2, 999}) {
    kernel() = {};
    kernel().region_result = query;
    kernel().release_result = 1;
    Budget budget(clock);
    const auto extent = vm::region_bytes<ProbeVm>(0x1000, budget);
    ASSERT_FALSE(extent.has_value());
    EXPECT_EQ(extent.error(), Error::kCleanup);
    EXPECT_EQ(kernel().releases, 1U);
  }
}
TEST_F(IosVmContractTest, region_whenQueryRunsPastDeadline_releasesBeforeNextReadRefuses) {
  kernel().expire_during_query = true;
  Budget budget(clock);
  EXPECT_TRUE(vm::region_bytes<ProbeVm>(0x1000, budget).has_value());
  EXPECT_EQ(kernel().releases, 1U);
  std::array<std::uint8_t, 4> bytes{};
  const auto read = vm::copy<ProbeVm>(0x1000, bytes, budget);
  ASSERT_FALSE(read.has_value());
  EXPECT_EQ(read.error(), Error::kDeadline);
  EXPECT_EQ(kernel().copies, 0U);
}
TEST_F(IosVmContractTest, budget_whenUnavailableOrExhausted_neverCallsKernel) {
  for (const auto invalid : {-1, 100000001}) {
    kernel().tick = invalid < 0 ? -1 : 1;
    Budget budget(clock);
    kernel().tick = invalid;
    EXPECT_FALSE(vm::region_bytes<ProbeVm>(0x1000, budget).has_value());
    std::array<std::uint8_t, 4> bytes{};
    EXPECT_FALSE(vm::copy<ProbeVm>(0x1000, bytes, budget).has_value());
    EXPECT_EQ(kernel().copies, 0U);
    EXPECT_EQ(kernel().queries, 0U);
  }
}
#ifdef __linux__
/// Real own-process Linux kernel copies exercise the validation, without claiming a Mach ABI or SDK result.
struct KernelVm : ProbeVm {
  static constexpr auto kCopy = [](std::uint32_t task, Address address, Size size, Address destination, Size* copied) {
    const CopyCall request{.task = task, .address = address, .size = size, .destination = destination};
    EXPECT_EQ(request.task, self());
    const iovec from{.iov_base = std::bit_cast<void*>(request.address), .iov_len = request.size};
    const iovec into{.iov_base = std::bit_cast<void*>(request.destination), .iov_len = request.size};
    const auto result = process_vm_readv(getpid(), &into, 1, &from, 1, 0);
    *copied = result < 0 ? 0 : static_cast<Size>(result);
    return result < 0 ? 1 : kSuccess;
  };
};
#elifdef __APPLE__
using KernelVm = vm::Native;
#endif
#if defined(__APPLE__) || defined(__linux__)
/// Actual mapped/guarded pages; Linux and Apple use their own real kernel read APIs.
class IosVmKernelTest : public testing::Test {
 protected:
  void SetUp() override {
    const auto native_page = sysconf(_SC_PAGESIZE);
    ASSERT_GT(native_page, 0);
    page_ = static_cast<std::size_t>(native_page);
    memory_ = mmap(nullptr, page_ * 2, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    ASSERT_NE(memory_, MAP_FAILED);
    const std::span bytes{static_cast<std::uint8_t*>(memory_), page_ * 2};
    bytes[page_ - 1] = 0;
    ASSERT_EQ(mprotect(bytes.subspan(page_).data(), page_, PROT_NONE), 0);
  }
  void TearDown() override {
    if (memory_ != MAP_FAILED) {
      release();
    }
  }
  [[nodiscard]] std::uintptr_t address() const { return std::bit_cast<std::uintptr_t>(memory_); }
  [[nodiscard]] std::size_t page_size() const { return page_; }
  void release() {
    ASSERT_EQ(munmap(memory_, page_ * 2), 0);
    memory_ = MAP_FAILED;
  }

 private:
  void* memory_ = MAP_FAILED;
  std::size_t page_ = 0;
};
TEST_F(IosVmKernelTest, copy_whenNulEndsReadablePage_preservesExactInPageByte) {
  Budget budget(clock);
  std::array<std::uint8_t, 1> into{123};
  const auto pointer = address() + page_size() - 1;
#ifdef __APPLE__
  const auto extent = vm::region_bytes<KernelVm>(pointer, budget);
  ASSERT_TRUE(extent.has_value());
  EXPECT_EQ(*extent, 1U);
#endif
  ASSERT_TRUE(vm::copy<KernelVm>(pointer, into, budget).has_value());
  EXPECT_EQ(into[0], 0U);
}
TEST_F(IosVmKernelTest, copy_whenRangeCrossesGuardOrStartsInGuard_refusesPartialOrDenied) {
  for (const auto offset : {page_size() - 2, page_size()}) {
    Budget budget(clock);
    std::array<std::uint8_t, 4> into{};
    const auto result = vm::copy<KernelVm>(address() + offset, into, budget);
    ASSERT_FALSE(result.has_value());
    EXPECT_TRUE(result.error() == Error::kIo || result.error() == Error::kDenied);
  }
}
TEST_F(IosVmKernelTest, copy_whenMappingWasRemoved_refusesUnmappedStorage) {
  const auto removed = address();
  release();
  Budget budget(clock);
  std::array<std::uint8_t, 4> into{};
  EXPECT_FALSE(vm::copy<KernelVm>(removed, into, budget).has_value());
}
#ifdef __APPLE__
TEST_F(IosVmKernelTest, region_whenRealPageHasNoReadProtection_refusesInventory) {
  Budget budget(clock);
  EXPECT_FALSE(vm::region_bytes<vm::Native>(address() + page_size(), budget).has_value());
}
#endif
#endif
#ifdef __APPLE__
TEST(IosVmNative, publicMach_whenReadingOwnStorage_returnsExactBytesAndReadableRegion) {
  std::array<std::uint8_t, 4> source{1, 2, 3, 4};
  std::array<std::uint8_t, 4> into{};
  Budget budget(clock);
  const auto address = std::bit_cast<std::uintptr_t>(source.data());
  ASSERT_TRUE(vm::region_bytes<vm::Native>(address, budget).has_value());
  ASSERT_TRUE(vm::copy<vm::Native>(address, into, budget).has_value());
  EXPECT_EQ(source, into);
}
#endif
}  // namespace
