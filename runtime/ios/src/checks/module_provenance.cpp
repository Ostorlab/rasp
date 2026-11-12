/// Inactive dyld provenance implementation; no dispatcher or constructor calls this source.
#include "checks/module_provenance.h"

#include <cstddef>
#include <cstdint>
#include <expected>
#include <limits>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include "rasp/posix/provenance.h"
#include "util/macho.h"
#ifdef __APPLE__
#include <TargetConditionals.h>
#include <algorithm>
#include <array>
#include <bit>
#include <mach-o/dyld.h>
#include <mach/kern_return.h>
#include <mach/mach_init.h>
#include <mach/mach_port.h>
#include <mach/mach_vm.h>
#include <mach/vm_region.h>

#include "util/provenance_bundle.h"
#endif

namespace rasp::ios::checks {
namespace {
using provenance::Budget;
using provenance::Error;
using provenance::Result;
/// Dyld observations cover declarations, not live VM protections or anonymous executable memory.
struct Declared {
  std::size_t segments = 0;
  std::uint32_t flags = 0;
};
/// Adds a signed slide without signed overflow, including INT64_MIN.
Result<std::uintptr_t> slid_address(std::uint64_t address, const ProvenanceImage& image) {
  const auto slide = image.slide;
  constexpr auto kMaximum = std::numeric_limits<std::uintptr_t>::max();
  if (slide >= 0) {
    const auto positive = static_cast<std::uint64_t>(slide);
    if (positive > kMaximum || address > kMaximum - positive) {
      return std::unexpected(Error::kMalformed);
    }
    return static_cast<std::uintptr_t>(address + positive);
  }
  const auto negative = static_cast<std::uint64_t>(-(slide + 1)) + 1;
  if (address < negative || address - negative > kMaximum) {
    return std::unexpected(Error::kMalformed);
  }
  return static_cast<std::uintptr_t>(address - negative);
}
/// Validates one bounded64-bit segment and its complete section table before reducing flags.
Result<Declared> segment(std::span<const std::uint8_t> command, const ProvenanceImage& image) {
  if (command.size() < 72) {
    return std::unexpected(Error::kMalformed);
  }
  const auto address = util::read_little_endian_64(command, 24);
  const auto size = util::read_little_endian_64(command, 32);
  const auto offset = util::read_little_endian_64(command, 40);
  const auto file_size = util::read_little_endian_64(command, 48);
  const auto flags = util::read_little_endian(command, 60);
  const auto sections = util::read_little_endian(command, 64);
  if (!address || !size || !offset || !file_size || !flags || !sections || *sections > (command.size() - 72) / 80 ||
      command.size() != 72 + (static_cast<std::size_t>(*sections) * 80) || *file_size > *size ||
      *file_size > UINT64_MAX - *offset) {
    return std::unexpected(Error::kMalformed);
  }
  const auto start = slid_address(*address, image);
  if (!start || *size > std::numeric_limits<std::uintptr_t>::max() - *start) {
    return std::unexpected(Error::kMalformed);
  }
  return Declared{
      .segments = (*flags & 4U) != 0 && *size != 0 ? std::size_t{1} : 0,
      .flags = (*flags & 4U) != 0 && *size != 0 ? *flags & 7U : 0,
  };
}
/// Parses all commands, even after the output sample is full; no unchecked native pointer reads.
Result<Declared> declared(const ProvenanceImage& image, Budget& budget) {
  const auto header = util::read_mach_header(image.bytes);
  if (!header) {
    return std::unexpected(Error::kMalformed);
  }
  if (header->commands_size > 65536 || header->command_count > 4096) {
    return std::unexpected(Error::kInputLimit);
  }
  if (image.bytes.size() != util::kMachHeaderSize + header->commands_size) {
    return std::unexpected(Error::kMalformed);
  }
  const auto commands = util::load_commands(image.bytes);
  if (!commands) {
    return std::unexpected(Error::kMalformed);
  }
  std::size_t total = 0;
  Declared result;
  for (const auto& command : *commands) {
    if (!budget.step()) {
      return std::unexpected(budget.error());
    }
    if (command.bytes.size() % 8 != 0) {
      return std::unexpected(Error::kMalformed);
    }
    total += command.bytes.size();
    if (command.command != 0x19) {
      continue;
    }
    const auto item = segment(command.bytes, image);
    if (!item) {
      return std::unexpected(item.error());
    }
    result.segments += item->segments;
    result.flags |= item->flags;
  }
  if (total != header->commands_size) {
    return std::unexpected(Error::kMalformed);
  }
  return result;
}
#ifdef __APPLE__
/// Copies only exact own-task bytes; VM errors are unknown/error, never benign.
Result<void> copy_memory(std::uintptr_t address, std::span<std::uint8_t> bytes, Budget& budget) {
  if (!budget.step()) return std::unexpected(budget.error());
  if (address == 0 || bytes.size() > std::numeric_limits<std::uintptr_t>::max() - address)
    return std::unexpected(Error::kMalformed);
  mach_vm_size_t copied = 0;
  const auto result = mach_vm_read_overwrite(mach_task_self(), address, bytes.size(),
                                             std::bit_cast<mach_vm_address_t>(bytes.data()), &copied);
  if (result != KERN_SUCCESS || copied != bytes.size())
    return std::unexpected(result == KERN_PROTECTION_FAILURE ? Error::kDenied : Error::kIo);
  return {};
}
/// Returns at most the current readable region extent, releasing every returned port right exactly once.
Result<std::size_t> region_bytes(std::uintptr_t pointer, Budget& budget) {
  if (!budget.step()) return std::unexpected(budget.error());
  mach_vm_address_t address = pointer;
  mach_vm_size_t size = 0;
  vm_region_basic_info_data_64_t info{};
  auto count = static_cast<mach_msg_type_number_t>(VM_REGION_BASIC_INFO_COUNT_64);
  mach_port_t object = MACH_PORT_NULL;
  const auto result = mach_vm_region(mach_task_self(), &address, &size, VM_REGION_BASIC_INFO_64,
                                     static_cast<vm_region_info_t>(static_cast<void*>(&info)), &count, &object);
  bool released = true;
  if (object != MACH_PORT_NULL && object != MACH_PORT_DEAD)
    released = mach_port_deallocate(mach_task_self(), object) == KERN_SUCCESS;
  if (!released) return std::unexpected(Error::kCleanup);
  if (result != KERN_SUCCESS || count != VM_REGION_BASIC_INFO_COUNT_64 || address > pointer ||
      size > UINT64_MAX - address || pointer >= address + size || (info.protection & VM_PROT_READ) == 0)
    return std::unexpected(Error::kIo);
  return static_cast<std::size_t>(std::min<std::uint64_t>(256, address + size - pointer));
}
/// Copies bounded dyld-owned C-string bytes without assuming a valid borrowed pointer or page boundary.
Result<std::string> copied_name(std::uintptr_t pointer, Budget& budget) {
  std::string result;
  std::array<std::uint8_t, 256> buffer{};
  while (result.size() < 4096) {
    if (pointer > std::numeric_limits<std::uintptr_t>::max() - result.size()) return std::unexpected(Error::kMalformed);
    const auto address = pointer + result.size();
    const auto extent = region_bytes(address, budget);
    if (!extent) return std::unexpected(extent.error());
    const auto length = std::min(*extent, 4096 - result.size());
    const auto copied = copy_memory(address, std::span(buffer).first(length), budget);
    if (!copied) return std::unexpected(copied.error());
    for (const auto byte : std::span(buffer).first(length)) {
      if (byte == 0) return result;
      if (byte < 32 || byte == 127) return std::unexpected(Error::kMalformed);
      result.push_back(static_cast<char>(byte));
    }
  }
  return std::unexpected(Error::kInputLimit);
}
/// Public count accessor; count/index enumeration is best effort, not atomic.
Result<std::uint32_t> native_count(void* /*context*/, Budget& budget) {
  if (!budget.step()) return std::unexpected(budget.error());
  return _dyld_image_count();
}
/// Reads a single copied image from public accessors and own-task memory APIs only.
Result<ProvenanceImage> native_image(void* /*context*/, std::uint32_t index, Budget& budget) {
  if (!budget.step()) return std::unexpected(budget.error());
  const auto* header = _dyld_get_image_header(index);
  if (!budget.step()) return std::unexpected(budget.error());
  const auto* name = _dyld_get_image_name(index);
  if (!budget.step()) return std::unexpected(budget.error());
  const auto slide = _dyld_get_image_vmaddr_slide(index);
  if (header == nullptr || name == nullptr) return std::unexpected(Error::kRace);
  auto copied = copied_name(std::bit_cast<std::uintptr_t>(name), budget);
  if (!copied) return std::unexpected(copied.error());
  ProvenanceImage result{.name = std::move(*copied),
                         .header_address = std::bit_cast<std::uintptr_t>(header),
                         .slide = slide,
                         .bytes = std::vector<std::uint8_t>(util::kMachHeaderSize)};
  auto read = copy_memory(result.header_address, result.bytes, budget);
  if (!read) return std::unexpected(read.error());
  const auto parsed = util::read_mach_header(result.bytes);
  if (!parsed) return std::unexpected(Error::kMalformed);
  if (parsed->commands_size > 65536 || parsed->command_count > 4096) return std::unexpected(Error::kInputLimit);
  const auto original = result.bytes;
  result.bytes.resize(util::kMachHeaderSize + parsed->commands_size);
  read = copy_memory(result.header_address, result.bytes, budget);
  if (!read) return std::unexpected(read.error());
  if (!std::ranges::equal(original, std::span(result.bytes).first(util::kMachHeaderSize)))
    return std::unexpected(Error::kRace);
  return result;
}
#endif
/// Pass storage is bounded to8MiB command/header and4MiB name bytes.
struct Pass {
  std::vector<ProvenanceImage> images;
  std::vector<Declared> declarations;
};
/// Validates and owns an entire pass before exposing any sample.
Result<Pass> read_pass(DyldCalls calls, Budget& budget) {
  if (calls.count == nullptr || calls.image == nullptr) {
    return std::unexpected(Error::kNativeUnavailable);
  }
  if (!budget.step()) {
    return std::unexpected(budget.error());
  }
  const auto count = calls.count(calls.context, budget);
  if (!count) {
    return std::unexpected(count.error());
  }
  if (*count > 4096) {
    return std::unexpected(Error::kInputLimit);
  }
  Pass result;
  std::size_t bytes = 0;
  std::size_t names = 0;
  for (std::uint32_t index = 0; index < *count; ++index) {
    if (!budget.step()) {
      return std::unexpected(budget.error());
    }
    auto image = calls.image(calls.context, index, budget);
    if (!image) {
      return std::unexpected(image.error());
    }
    if (image->header_address == 0 || image->name.empty()) {
      return std::unexpected(Error::kMalformed);
    }
    if (image->name.size() >= 4096 || image->name.size() > (std::size_t{4} * 1024U * 1024U) - names ||
        image->bytes.size() > (std::size_t{8} * 1024U * 1024U) - bytes) {
      return std::unexpected(Error::kInputLimit);
    }
    names += image->name.size();
    bytes += image->bytes.size();
    const auto item = declared(*image, budget);
    if (!item) {
      return std::unexpected(item.error());
    }
    result.declarations.push_back(*item);
    result.images.push_back(std::move(*image));
  }
  if (!budget.step()) {
    return std::unexpected(budget.error());
  }
  const auto final_count = calls.count(calls.context, budget);
  if (!final_count) {
    return std::unexpected(final_count.error());
  }
  if (*final_count != *count) {
    return std::unexpected(Error::kRace);
  }
  if (!budget.step()) {
    return std::unexpected(budget.error());
  }
  return result;
}
}  // namespace

DyldCalls native_dyld_calls() {
#ifdef __APPLE__
  return {.count = native_count, .image = native_image};
#else
  return {};
#endif
}
provenance::Pair collect_module_provenance(const provenance::Locations& locations, DyldCalls calls,
                                           provenance::Clock clock) {
  Budget budget(clock);
  const auto first = read_pass(calls, budget);
  if (!first) {
    return provenance::pair("hook.exec_modules", "dyld_v1", std::unexpected(first.error()));
  }
  const auto second = read_pass(calls, budget);
  if (!second) {
    return provenance::pair("hook.exec_modules", "dyld_v1", std::unexpected(second.error()));
  }
  if (first->images != second->images) {
    return provenance::pair("hook.exec_modules", "dyld_v1", std::unexpected(Error::kRace));
  }
  const auto roots = provenance::valid_locations(locations) ? locations : provenance::Locations{};
  provenance::Metadata metadata{
      .seen = first->images.size(),
      .scope_available = roots.available,
      .stability = "bracket_equal",
  };
  std::vector<std::string> rows;
  for (std::size_t index = 0; index < first->images.size(); ++index) {
    const auto& item = first->declarations[index];
    if (item.segments == 0) {
      continue;
    }
    ++metadata.eligible;
    if (rows.size() < 32) {
      rows.push_back("v=1;i=" + std::to_string(index) +
                     ";scope=" + std::string(provenance::scope(first->images[index].name, roots, true)) +
                     ";exec_segments=" + std::to_string(item.segments) +
                     ";declared_flags=" + std::to_string(item.flags));
    }
  }
  if (!budget.step()) {
    return provenance::pair("hook.exec_modules", "dyld_v1", std::unexpected(budget.error()));
  }
  return provenance::pair("hook.exec_modules", "dyld_v1", std::move(rows), metadata);
}
provenance::Pair module_provenance() {
#if defined(__APPLE__) && TARGET_OS_IOS && !TARGET_OS_SIMULATOR && defined(__aarch64__)
  return collect_module_provenance(util::provenance_bundle());
#else
  return provenance::pair("hook.exec_modules", "dyld_v1", std::unexpected(Error::kPlatform));
#endif
}
}  // namespace rasp::ios::checks
