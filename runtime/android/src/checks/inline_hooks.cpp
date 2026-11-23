/// The Android inline-hook check: the function-start comparison, and its unsupported result off Android.

#include "checks/inline_hooks.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "rasp/observation.h"
#include "rasp/util/obfuscation.h"
#include "util/memory_map.h"
#include "util/raw_file.h"

#ifdef __ANDROID__
#include <bit>

// The runtime's own references to the functions it verifies: each takes its address through the library's GOT, as
// a call does, so a GOT redirect shows as an address outside libc.
extern "C" {
void rasp_hook_target_access() __asm__("access");
void rasp_hook_target_stat() __asm__("stat");
void rasp_hook_target_lstat() __asm__("lstat");
void rasp_hook_target_open() __asm__("open");
void rasp_hook_target_openat() __asm__("openat");
void rasp_hook_target_read() __asm__("read");
void rasp_hook_target_fopen() __asm__("fopen");
void rasp_hook_target_fgets() __asm__("fgets");
void rasp_hook_target_opendir() __asm__("opendir");
void rasp_hook_target_readdir() __asm__("readdir");
void rasp_hook_target_readlink() __asm__("readlink");
void rasp_hook_target_strstr() __asm__("strstr");
void rasp_hook_target_strcmp() __asm__("strcmp");
void rasp_hook_target_memcmp() __asm__("memcmp");
void rasp_hook_target_property_find() __asm__("__system_property_find");
void rasp_hook_target_property_get() __asm__("__system_property_get");
void rasp_hook_target_property_read_callback() __asm__("__system_property_read_callback");
void rasp_hook_target_getifaddrs() __asm__("getifaddrs");
void rasp_hook_target_dl_iterate_phdr() __asm__("dl_iterate_phdr");
void rasp_hook_target_dladdr() __asm__("dladdr");
void rasp_hook_target_dlopen() __asm__("dlopen");
void rasp_hook_target_pthread_create() __asm__("pthread_create");
void rasp_hook_target_syscall() __asm__("syscall");
void rasp_hook_target_mmap() __asm__("mmap");
void rasp_hook_target_mprotect() __asm__("mprotect");
}
#endif

namespace rasp::android::checks {

namespace {

constexpr std::string_view kInlineSignal = "hook.inline";
constexpr std::string_view kInlineSource = "memory_file";
constexpr std::string_view kMapsPath = "/proc/self/maps";
constexpr std::size_t kMaxMapsSize = std::size_t{4} << 20U;
/// The bytes compared at the start of each function: enough to hold any hooking framework's jump.
constexpr std::size_t kStartSize = 16;
#ifdef __arm__
/// The bit a Thumb function's address carries, which isn't part of where its code starts.
constexpr std::uintptr_t kThumbBit = 1;
#else
constexpr std::uintptr_t kThumbBit = 0;
#endif

/// Where an address lies, for the report: the mapped file, `[anon]` for anonymous memory, or `[unmapped]`.
[[nodiscard]] std::string location_of(const util::Mapping* mapping) {
  if (mapping == nullptr) {
    return "[unmapped]";
  }
  if (mapping->pathname.empty()) {
    return "[anon]";
  }
  std::string location(mapping->pathname);
  if (mapping->deleted) {
    location += " (deleted)";
  }
  return location;
}

/// Whether the function at `address`, in `mapping`, starts with the bytes its file holds there; nothing when either
/// side can't be read whole.
[[nodiscard]] std::optional<bool> starts_as_in_file(const util::Mapping& mapping, std::uintptr_t address,
                                                    const rasp::util::ProcessAccess& access) {
  const std::size_t length = std::min<std::uintptr_t>(kStartSize, mapping.end - address);
  const std::uint64_t file_offset = mapping.offset + (address - mapping.start);
  const std::optional<std::string> memory = access.read_memory(address, length);
  const std::optional<std::string> file =
      rasp::util::read_file_range(mapping.pathname, file_offset, length, access.open);
  if (!memory || !file || memory->size() != length || file->size() != length) {
    return std::nullopt;
  }
  return *memory == *file;
}

#ifdef __ANDROID__

/// The address the runtime calls `function` at.
[[nodiscard]] std::uintptr_t address_of(void (*function)()) { return std::bit_cast<std::uintptr_t>(function); }

#endif

}  // namespace

bool is_system_libc(std::string_view path) {
  const std::string_view name = path.substr(path.rfind('/') + 1);
  return (path.starts_with("/apex/") || path.starts_with("/system/")) && (name == "libc.so" || name == "libdl.so");
}

std::vector<Observation> observe_inline_hooks(std::string_view maps_path, std::span<const HookTarget> targets,
                                              SystemLibraryPredicate is_system_library,
                                              const rasp::util::ProcessAccess& access) {
  const std::optional<std::string> maps = access.read(maps_path, kMaxMapsSize);
  if (!maps) {
    return {failed(kInlineSignal, kInlineSource)};
  }
  const std::vector<util::Mapping> mappings = util::parse_memory_map(*maps);
  std::vector<std::string> findings;
  for (const HookTarget& target : targets) {
    const std::uintptr_t address = target.address & ~kThumbBit;
    const util::Mapping* const mapping = util::find_mapping(mappings, address);
    if (mapping == nullptr || !mapping->executable || mapping->deleted || !is_system_library(mapping->pathname)) {
      findings.push_back(std::string(target.name) + " -> " + location_of(mapping));
      continue;
    }
    const std::optional<bool> intact = starts_as_in_file(*mapping, address, access);
    if (!intact) {
      return {failed(kInlineSignal, kInlineSource)};
    }
    if (!*intact) {
      findings.emplace_back(target.name);
    }
  }
  return {observed(kInlineSignal, kInlineSource, std::move(findings))};
}

std::vector<Observation> inline_hooks() {
  static constexpr std::array kObfuscatedLiterals = {kInlineSignal, kInlineSource, kMapsPath};
  rasp::util::anchor_literals(kObfuscatedLiterals);
#ifdef __ANDROID__
  const auto targets = std::to_array<HookTarget>({
      {.name = "access", .address = address_of(&rasp_hook_target_access)},
      {.name = "stat", .address = address_of(&rasp_hook_target_stat)},
      {.name = "lstat", .address = address_of(&rasp_hook_target_lstat)},
      {.name = "open", .address = address_of(&rasp_hook_target_open)},
      {.name = "openat", .address = address_of(&rasp_hook_target_openat)},
      {.name = "read", .address = address_of(&rasp_hook_target_read)},
      {.name = "fopen", .address = address_of(&rasp_hook_target_fopen)},
      {.name = "fgets", .address = address_of(&rasp_hook_target_fgets)},
      {.name = "opendir", .address = address_of(&rasp_hook_target_opendir)},
      {.name = "readdir", .address = address_of(&rasp_hook_target_readdir)},
      {.name = "readlink", .address = address_of(&rasp_hook_target_readlink)},
      {.name = "strstr", .address = address_of(&rasp_hook_target_strstr)},
      {.name = "strcmp", .address = address_of(&rasp_hook_target_strcmp)},
      {.name = "memcmp", .address = address_of(&rasp_hook_target_memcmp)},
      {.name = "__system_property_find", .address = address_of(&rasp_hook_target_property_find)},
      {.name = "__system_property_get", .address = address_of(&rasp_hook_target_property_get)},
      {.name = "__system_property_read_callback", .address = address_of(&rasp_hook_target_property_read_callback)},
      {.name = "getifaddrs", .address = address_of(&rasp_hook_target_getifaddrs)},
      {.name = "dl_iterate_phdr", .address = address_of(&rasp_hook_target_dl_iterate_phdr)},
      {.name = "dladdr", .address = address_of(&rasp_hook_target_dladdr)},
      {.name = "dlopen", .address = address_of(&rasp_hook_target_dlopen)},
      {.name = "pthread_create", .address = address_of(&rasp_hook_target_pthread_create)},
      {.name = "syscall", .address = address_of(&rasp_hook_target_syscall)},
      {.name = "mmap", .address = address_of(&rasp_hook_target_mmap)},
      {.name = "mprotect", .address = address_of(&rasp_hook_target_mprotect)},
  });
  return observe_inline_hooks(kMapsPath, targets);
#else
  return {unsupported(kInlineSignal, kInlineSource)};
#endif
}

}  // namespace rasp::android::checks
