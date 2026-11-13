/// Exact own-task VM access validation, shared by the public Mach adapter and native I/O contract tests.
#pragma once

#include <algorithm>
#include <array>
#include <bit>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <limits>
#include <span>
#include <type_traits>

#include "rasp/posix/provenance.h"

#ifdef __APPLE__
#include <mach/kern_return.h>
#include <mach/mach_init.h>
#include <mach/mach_port.h>
#include <mach/message.h>
#include <mach/port.h>
#include <mach/vm_map.h>
#include <mach/vm_prot.h>
#include <mach/vm_region.h>
#include <mach/vm_types.h>
#endif

namespace rasp::ios::util::provenance_vm {
#ifdef __APPLE__
/// Public iOS Mach VM signatures/types; own-task authority is never supplied by observations or configuration.
struct Native {
  using Port = mach_port_t;
  using Address = vm_address_t;
  using Size = vm_size_t;
  using RegionInfo = vm_region_basic_info_data_64_t;
  using InfoPointer = vm_region_info_t;
  static constexpr auto kCopy = vm_read_overwrite;
  static constexpr auto kRegion = vm_region_64;
  static constexpr auto kDeallocate = mach_port_deallocate;
  static constexpr auto kSuccess = KERN_SUCCESS;
  static constexpr auto kDenied = KERN_PROTECTION_FAILURE;
  static constexpr Port kNull{MACH_PORT_NULL};
  static constexpr Port kDead{MACH_PORT_DEAD};
  static constexpr auto kRegionFlavor = VM_REGION_BASIC_INFO_64;
  static constexpr mach_msg_type_number_t kRegionCount{VM_REGION_BASIC_INFO_COUNT_64};
  static constexpr auto kReadProtection = VM_PROT_READ;
  /// Always selects this process's task; never an externally supplied target.
  static Port self() { return mach_task_self(); }
};
#endif

/// Copies into caller-owned storage through the supplied own-task kernel boundary, never direct dereferencing.
/// @param address Source address, checked for wrapping before entering the kernel.
/// @param bytes Owned destination span; exact copied length is required.
/// @param budget Existing cooperative source budget, including this native call.
/// @return Complete success or a concrete failure; callers discard all partial inventory on failure.
template <typename Vm>
[[nodiscard]] provenance::Result<void> copy(std::uintptr_t address, std::span<std::uint8_t> bytes,
                                            provenance::Budget& budget) {
  static_assert(sizeof(typename Vm::Address) == 8);
  static_assert(sizeof(std::uintptr_t) == 8);
  static_assert(sizeof(typename Vm::Size) == 8);
  static_assert(sizeof(std::size_t) == 8);
  static_assert(std::is_unsigned_v<typename Vm::Address> && std::is_unsigned_v<typename Vm::Size>);
  if (!budget.step()) {
    return std::unexpected(budget.error());
  }
  const auto destination = std::bit_cast<typename Vm::Address>(bytes.data());
  if (address == 0 || bytes.size() > std::numeric_limits<std::uintptr_t>::max() - address ||
      (destination == 0 && !bytes.empty()) ||
      bytes.size() > std::numeric_limits<typename Vm::Address>::max() - destination) {
    return std::unexpected(provenance::Error::kMalformed);
  }
  typename Vm::Size copied = 0;
  const auto size = static_cast<Vm::Size>(bytes.size());
  const auto result = Vm::kCopy(Vm::self(), static_cast<Vm::Address>(address), size, destination, &copied);
  if (result != Vm::kSuccess || copied != size) {
    return std::unexpected(result == Vm::kDenied ? provenance::Error::kDenied : provenance::Error::kIo);
  }
  return {};
}
/// Returns a readable chunk covering the pointer, releasing every valid returned object right exactly once.
/// @param pointer Address within the requested readable region.
/// @param budget Existing cooperative source budget; cleanup is mandatory even after kernel failure.
/// @return At most 256 readable bytes, or unknown/error without a partial name.
template <typename Vm>
[[nodiscard]] provenance::Result<std::size_t> region_bytes(std::uintptr_t pointer, provenance::Budget& budget) {
  static_assert(sizeof(typename Vm::Address) == 8);
  static_assert(sizeof(std::uintptr_t) == 8);
  static_assert(sizeof(typename Vm::Size) == 8);
  static_assert(sizeof(std::size_t) == 8);
  static_assert(std::is_unsigned_v<typename Vm::Address> && std::is_unsigned_v<typename Vm::Size>);
  if (!budget.step()) {
    return std::unexpected(budget.error());
  }
  if (pointer == 0) {
    return std::unexpected(provenance::Error::kMalformed);
  }
  using Port = Vm::Port;
  static_assert(std::is_unsigned_v<Port>);
  static_assert(std::is_same_v<decltype(Vm::self()), Port>);
  constexpr Port kNull{Vm::kNull};
  constexpr Port kDead{Vm::kDead};
  static_assert(kNull != kDead);
  const auto task = Vm::self();
  auto address = static_cast<Vm::Address>(pointer);
  typename Vm::Size size = 0;
  using Word = std::remove_pointer_t<typename Vm::InfoPointer>;
  std::array<Word, Vm::kRegionCount> words{};
  static_assert(sizeof(words) == sizeof(typename Vm::RegionInfo));
  auto count = Vm::kRegionCount;
  Port object = kNull;
  const auto result = Vm::kRegion(task, &address, &size, Vm::kRegionFlavor, words.data(), &count, &object);
  if (object != kNull && object != kDead && Vm::kDeallocate(task, object) != Vm::kSuccess) {
    return std::unexpected(provenance::Error::kCleanup);
  }
  if (result != Vm::kSuccess || count != Vm::kRegionCount || size == 0 || address > pointer ||
      size > std::numeric_limits<typename Vm::Address>::max() - address || pointer >= address + size) {
    return std::unexpected(provenance::Error::kIo);
  }
  const auto info = std::bit_cast<typename Vm::RegionInfo>(words);
  if ((static_cast<std::uint32_t>(info.protection) & static_cast<std::uint32_t>(Vm::kReadProtection)) == 0) {
    return std::unexpected(provenance::Error::kIo);
  }
  return static_cast<std::size_t>(std::min<typename Vm::Size>(256, address + size - pointer));
}
}  // namespace rasp::ios::util::provenance_vm
