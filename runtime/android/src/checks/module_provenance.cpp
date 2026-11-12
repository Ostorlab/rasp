/// Bounded own-process map/native-loader sampling, currently linked only by inactive tests.
#include "checks/module_provenance.h"

#include <algorithm>
#include <array>
#include <bit>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <limits>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unistd.h>
#include <utility>
#include <vector>

#include "checks/module_provenance_io.h"
#include "rasp/observation.h"
#include "rasp/posix/provenance.h"
#include "util/proc_text.h"
#ifdef __ANDROID__
#include "checks/loader_provenance.h"
#endif
#ifdef __linux__
#if __has_include(<bits/types/struct_iovec.h>)
#include <bits/types/struct_iovec.h>
#endif
#include <elf.h>
#include <link.h>
#include <sys/uio.h>
#endif

namespace rasp::android::checks {
namespace {
using provenance::Budget;
using provenance::Error;
using provenance::Result;
/// Input limits are independent of the32-row output sample.
constexpr std::size_t kMaxMaps = std::size_t{4} * 1024U * 1024U;
constexpr std::size_t kMaxNames = std::size_t{4} * 1024U * 1024U;
constexpr std::size_t kMaxHeaders = std::size_t{2} * 1024U * 1024U;
constexpr std::size_t kMaxRecords = 8192;
constexpr std::size_t kMaxImages = 4096;
constexpr std::size_t kMaxIntervals = 16384;
/// Complete private identity compared only within this invocation.
struct Mapping {
  std::uintptr_t start;
  std::uintptr_t end;
  std::uint64_t offset;
  std::uint64_t major;
  std::uint64_t minor;
  std::uint64_t inode;
  std::string permissions;
  std::string path;
  friend bool operator==(const Mapping&, const Mapping&) = default;
};
/// Opens only the fixed own-process path, returning a negative captured errno on failure.
int open_maps(void* /*context*/) { return rasp_module_open_maps(); }
/// Captures errno immediately; the caller owns retries and complete-source semantics.
MapRead read_maps(void* /*context*/, int descriptor, std::span<char> into) {
  const auto count = read(descriptor, into.data(), into.size());
  return {.size = count, .error = count < 0 ? errno : 0};
}
/// Never retries close on a potentially reused descriptor.
int close_maps(void* /*context*/, int descriptor) { return close(descriptor); }
/// Converts captured native refusal to an explicit source failure.
Error io_error(int error) { return error == EACCES || error == EPERM ? Error::kDenied : Error::kIo; }
/// Reads to proven EOF with finite byte, attempt and interrupted-read limits.
Result<std::string> read_maps_content(MapIo calls, int descriptor, Budget& budget) {
  std::string text;
  std::vector<char> buffer(4096);
  unsigned interrupted = 0;
  for (std::size_t attempt = 0; attempt < 2048; ++attempt) {
    if (!budget.step()) {
      return std::unexpected(budget.error());
    }
    const auto remaining = std::min(buffer.size(), kMaxMaps - text.size() + 1);
    const auto part = calls.read(calls.context, descriptor, std::span(buffer).first(remaining));
    if (part.size < 0) {
      if (part.error == EINTR && ++interrupted <= 8) {
        continue;
      }
      return std::unexpected(io_error(part.error));
    }
    interrupted = 0;
    if (std::cmp_greater(part.size, remaining)) {
      return std::unexpected(Error::kMalformed);
    }
    if (part.size == 0) {
      return text;
    }
    if (std::cmp_greater(part.size, kMaxMaps - text.size())) {
      return std::unexpected(Error::kInputLimit);
    }
    text.append(buffer.data(), static_cast<std::size_t>(part.size));
  }
  return std::unexpected(Error::kInputLimit);
}
/// Owns the descriptor and closes it exactly once after every complete or failed read.
Result<std::string> map_text(MapIo calls, Budget& budget) {
  if (calls.open == nullptr || calls.read == nullptr || calls.close == nullptr) {
    return std::unexpected(Error::kNativeUnavailable);
  }
  if (!budget.step()) {
    return std::unexpected(budget.error());
  }
  const int descriptor = calls.open(calls.context);
  if (descriptor < 0) {
    return std::unexpected(descriptor == std::numeric_limits<int>::min() ? Error::kIo : io_error(-descriptor));
  }
  auto result = read_maps_content(calls, descriptor, budget);
  if (calls.close(calls.context, descriptor) != 0) {
    return std::unexpected(Error::kCleanup);
  }
  if (!budget.step() && result) {
    return std::unexpected(budget.error());
  }
  return result;
}
/// Parses actual kernel fields; path characters cannot create permission bits.
Result<Mapping> map_line(std::string_view line) {
  auto rest = line;
  const auto range = util::take_proc_field(rest);
  const auto dash = range.find('-');
  if (dash == std::string_view::npos) {
    return std::unexpected(Error::kMalformed);
  }
  const auto start = util::proc_number(range.substr(0, dash), 16);
  const auto end = util::proc_number(range.substr(dash + 1), 16);
  const auto permissions = util::take_proc_field(rest);
  const auto offset = util::proc_number(util::take_proc_field(rest), 16);
  const auto device = util::take_proc_field(rest);
  const auto colon = device.find(':');
  if (colon == std::string_view::npos) {
    return std::unexpected(Error::kMalformed);
  }
  const auto major = util::proc_number(device.substr(0, colon), 16);
  const auto minor = util::proc_number(device.substr(colon + 1), 16);
  const auto inode = util::proc_number(util::take_proc_field(rest), 10);
  if (!start || !end || *start >= *end || *end > std::numeric_limits<std::uintptr_t>::max() || !offset || !major ||
      !minor || !inode || permissions.size() != 4 || (permissions[0] != 'r' && permissions[0] != '-') ||
      (permissions[1] != 'w' && permissions[1] != '-') || (permissions[2] != 'x' && permissions[2] != '-') ||
      (permissions[3] != 'p' && permissions[3] != 's')) {
    return std::unexpected(Error::kMalformed);
  }
  return Mapping{
      .start = static_cast<std::uintptr_t>(*start),
      .end = static_cast<std::uintptr_t>(*end),
      .offset = *offset,
      .major = *major,
      .minor = *minor,
      .inode = *inode,
      .permissions = std::string(permissions),
      .path = std::string(rest),
  };
}
/// Validates every complete bounded record, including those after sample saturation.
Result<std::vector<Mapping>> mappings(MapIo calls, Budget& budget) {
  const auto text = map_text(calls, budget);
  if (!text) {
    return std::unexpected(text.error());
  }
  std::vector<Mapping> result;
  Error error = Error::kMalformed;
  const bool valid = util::valid_proc_table(*text, [&](std::string_view line) {
    if (!budget.step()) {
      error = budget.error();
      return false;
    }
    if (result.size() == kMaxRecords) {
      error = Error::kInputLimit;
      return false;
    }
    auto record = map_line(line);
    if (!record || (!result.empty() && record->start < result.back().end)) {
      return false;
    }
    result.push_back(std::move(*record));
    return true;
  });
  if (!valid) {
    return std::unexpected(error);
  }
  return result;
}
#ifdef __linux__
/// Copies own-process bytes without dereferencing a supplied pointer; short reads are errors.
bool copy_memory(std::uintptr_t address, std::span<std::byte> bytes) {
  if (address == 0 || bytes.size() > std::numeric_limits<std::uintptr_t>::max() - address) {
    return false;
  }
  const iovec local{.iov_base = bytes.data(), .iov_len = bytes.size()};
  const iovec remote{.iov_base = std::bit_cast<void*>(address), .iov_len = bytes.size()};
  return process_vm_readv(getpid(), &local, 1, &remote, 1, 0) == static_cast<ssize_t>(bytes.size());
}
/// Native callback state owns every byte retained beyond the callback.
struct NativeImages {
  Budget* budget;
  std::vector<ExecutableImage> images;
  std::size_t headers = 0;
  std::size_t names = 0;
  std::size_t intervals = 0;
  Error error = Error::kNone;
};
/// Copies at most4096 name bytes through exact-length OS reads.
Result<std::string> image_name(std::uintptr_t address, Budget& budget) {
  if (address == 0) {
    return std::unexpected(Error::kMalformed);
  }
  if (!budget.step()) {
    return std::unexpected(budget.error());
  }
  const auto native_page_size = sysconf(_SC_PAGESIZE);
  if (native_page_size <= 0) {
    return std::unexpected(Error::kIo);
  }
  const auto page_size = static_cast<std::uintptr_t>(native_page_size);
  std::string result;
  std::array<char, 256> bytes{};
  std::size_t offset = 0;
  while (offset < 4096) {
    if (!budget.step()) {
      return std::unexpected(budget.error());
    }
    if (address > std::numeric_limits<std::uintptr_t>::max() - offset) {
      return std::unexpected(Error::kMalformed);
    }
    const auto next = address + offset;
    const auto page_remaining = page_size - (next % page_size);
    const auto length = std::min({bytes.size(), 4096 - offset, static_cast<std::size_t>(page_remaining)});
    if (!copy_memory(next, std::as_writable_bytes(std::span(bytes).first(length)))) {
      return std::unexpected(Error::kIo);
    }
    for (const auto byte : std::span(bytes).first(length)) {
      if (byte == 0) {
        return result;
      }
      if (static_cast<unsigned char>(byte) < 32 || byte == 127) {
        return std::unexpected(Error::kMalformed);
      }
      result.push_back(byte);
    }
    offset += length;
  }
  return std::unexpected(Error::kInputLimit);
}
/// Checks copied PT_LOAD extents before retaining executable address metadata.
Result<ExecutableInterval> load_interval(const ElfW(Phdr) & header, std::uintptr_t slide) {
  constexpr auto kMaximum = std::numeric_limits<std::uintptr_t>::max();
  if (header.p_filesz > header.p_memsz || header.p_vaddr > kMaximum - slide ||
      header.p_memsz > kMaximum - (slide + header.p_vaddr) || header.p_offset > kMaximum - header.p_filesz ||
      (header.p_flags & ~7U) != 0) {
    return std::unexpected(Error::kMalformed);
  }
  return ExecutableInterval{
      .start = slide + header.p_vaddr,
      .end = slide + header.p_vaddr + header.p_memsz,
      .flags = header.p_flags,
  };
}
/// Validates callback size and copies metadata while the public loader owns its storage.
Result<ExecutableImage> copy_image(dl_phdr_info* borrowed, std::size_t size, NativeImages& state) {
  if (!state.budget->step()) {
    return std::unexpected(state.budget->error());
  }
  constexpr std::size_t kPrefix = offsetof(dl_phdr_info, dlpi_phnum) + sizeof(dl_phdr_info::dlpi_phnum);
  dl_phdr_info info{};
  if (size < kPrefix || !copy_memory(std::bit_cast<std::uintptr_t>(borrowed),
                                     std::as_writable_bytes(std::span{&info, 1}).first(kPrefix))) {
    return std::unexpected(Error::kMalformed);
  }
  const auto name = image_name(std::bit_cast<std::uintptr_t>(info.dlpi_name), *state.budget);
  if (!name) {
    return std::unexpected(name.error());
  }
  if (name->size() > kMaxNames - state.names || info.dlpi_phnum == 0 || info.dlpi_phnum > 1024) {
    return std::unexpected(Error::kInputLimit);
  }
  state.names += name->size();
  const auto bytes = static_cast<std::size_t>(info.dlpi_phnum) * sizeof(ElfW(Phdr));
  if (bytes > kMaxHeaders - state.headers) {
    return std::unexpected(Error::kInputLimit);
  }
  state.headers += bytes;
  std::vector<ElfW(Phdr)> headers(info.dlpi_phnum);
  if (!state.budget->step()) {
    return std::unexpected(state.budget->error());
  }
  if (!copy_memory(std::bit_cast<std::uintptr_t>(info.dlpi_phdr), std::as_writable_bytes(std::span(headers)))) {
    return std::unexpected(Error::kIo);
  }
  ExecutableImage image{.name = *name, .intervals = {}};
  for (const auto& header : headers) {
    if (!state.budget->step()) {
      return std::unexpected(state.budget->error());
    }
    if (header.p_type != PT_LOAD) {
      continue;
    }
    auto interval = load_interval(header, info.dlpi_addr);
    if (!interval) {
      return std::unexpected(interval.error());
    }
    if (interval->start == interval->end || (header.p_flags & PF_X) == 0) {
      continue;
    }
    if (state.intervals == kMaxIntervals) {
      return std::unexpected(Error::kInputLimit);
    }
    ++state.intervals;
    image.intervals.push_back(*interval);
  }
  return image;
}
/// Stops the public loader walk on the first structural/native/work failure.
int image_callback(dl_phdr_info* info, std::size_t size, void* context) {
  auto& state = *static_cast<NativeImages*>(context);
  if (state.images.size() == kMaxImages) {
    state.error = Error::kInputLimit;
    return 1;
  }
  auto image = copy_image(info, size, state);
  if (!image) {
    state.error = image.error();
    return 1;
  }
  state.images.push_back(std::move(*image));
  return 0;
}
#endif
/// Uses only the public native iterator; this is not an inventory of ART/JIT or all linker namespaces.
Result<std::vector<ExecutableImage>> native_images(void* /*context*/, Budget& budget) {
#ifdef __linux__
  NativeImages state{.budget = &budget, .images = {}};
  const int result = dl_iterate_phdr(image_callback, &state);
  if (state.error != Error::kNone) {
    return std::unexpected(state.error);
  }
  if (result != 0) {
    return std::unexpected(Error::kIo);
  }
  return state.images;
#else
  static_cast<void>(budget);
  return std::unexpected(Error::kNativeUnavailable);
#endif
}
/// Validates owned image extents before correlation, including fixture/native inputs beyond the sample.
Result<std::vector<ExecutableInterval>> intervals(const std::vector<ExecutableImage>& images, Budget& budget) {
  if (images.size() > kMaxImages) {
    return std::unexpected(Error::kInputLimit);
  }
  std::vector<ExecutableInterval> result;
  std::size_t names = 0;
  for (const auto& image : images) {
    if (!budget.step()) {
      return std::unexpected(budget.error());
    }
    if (image.name.size() >= 4096 || image.name.size() > kMaxNames - names) {
      return std::unexpected(Error::kInputLimit);
    }
    names += image.name.size();
    for (const auto& interval : image.intervals) {
      if (!budget.step()) {
        return std::unexpected(budget.error());
      }
      if (result.size() == kMaxIntervals) {
        return std::unexpected(Error::kInputLimit);
      }
      if (interval.start >= interval.end || (interval.flags & 1U) == 0 || (interval.flags & ~7U) != 0) {
        return std::unexpected(Error::kMalformed);
      }
      result.push_back(interval);
    }
  }
  std::ranges::sort(result, {}, &ExecutableInterval::start);
  return result;
}
/// Reduces valid image metadata to a bounded location-only sample.
std::vector<std::string> image_rows(const std::vector<ExecutableImage>& images, const provenance::Locations& locations,
                                    provenance::Metadata& metadata) {
  std::vector<std::string> rows;
  metadata.seen = images.size();
  for (std::size_t index = 0; index < images.size(); ++index) {
    const auto& image = images[index];
    if (image.intervals.empty()) {
      continue;
    }
    ++metadata.eligible;
    std::uint32_t flags = 0;
    for (const auto& interval : image.intervals) {
      flags |= interval.flags;
    }
    if (rows.size() < 32) {
      rows.push_back(
          "v=1;i=" + std::to_string(index) + ";scope=" + std::string(provenance::scope(image.name, locations)) +
          ";exec_segments=" + std::to_string(image.intervals.size()) + ";declared_flags=" + std::to_string(flags));
    }
  }
  return rows;
}
/// Merges a sorted interval union once, avoiding quadratic matching on overlapping image ranges.
std::vector<ExecutableInterval> merged_intervals(const std::vector<ExecutableInterval>& ranges) {
  std::vector<ExecutableInterval> merged;
  for (const auto& range : ranges) {
    if (!merged.empty() && range.start <= merged.back().end) {
      merged.back().end = std::max(merged.back().end, range.end);
    } else {
      merged.push_back(range);
    }
  }
  return merged;
}
/// Monotonic sweep against the merged interval union, never a malware/ownership judgment.
std::string_view coverage(const Mapping& mapping, std::span<const ExecutableInterval> ranges, std::size_t& cursor) {
  while (cursor < ranges.size() && ranges[cursor].end <= mapping.start) {
    ++cursor;
  }
  if (cursor == ranges.size() || ranges[cursor].start >= mapping.end) {
    return "uncovered";
  }
  return ranges[cursor].start <= mapping.start && ranges[cursor].end >= mapping.end ? "covered" : "partial";
}
/// Classifies kernel labels without whitelisting content based on names.
std::string_view backing(std::string_view path) {
  if (path.empty()) {
    return "anonymous";
  }
  if (path.starts_with("/memfd:") || path.starts_with("memfd:")) {
    return "memfd_label";
  }
  if (path.starts_with("[anon:") || path.starts_with("[anon_shmem:")) {
    return "named_anon";
  }
  return path.starts_with('/') ? "file" : "special";
}
/// Reduces eligible maps without transmitting private identity fields.
std::vector<std::string> map_rows(const std::vector<Mapping>& maps, const provenance::Locations& locations,
                                  const std::optional<std::vector<ExecutableInterval>>& ranges,
                                  provenance::Metadata& metadata) {
  std::vector<std::string> rows;
  metadata.seen = maps.size();
  std::size_t cursor = 0;
  for (std::size_t index = 0; index < maps.size(); ++index) {
    const auto& mapping = maps[index];
    if (mapping.permissions[2] != 'x') {
      continue;
    }
    ++metadata.eligible;
    const auto relation = ranges ? coverage(mapping, *ranges, cursor) : "unknown";
    if (rows.size() == 32) {
      continue;
    }
    std::string_view path = mapping.path;
    const bool deleted = path.ends_with(" (deleted)");
    if (deleted) {
      path.remove_suffix(10);
    }
    rows.push_back("v=1;i=" + std::to_string(index) + ";scope=" + std::string(provenance::scope(path, locations)) +
                   ";backing=" + std::string(backing(path)) + ";perms=" + mapping.permissions +
                   ";loader=" + std::string(relation) + ";deleted_label=" + (deleted ? "1" : "0"));
  }
  return rows;
}
}  // namespace

ModuleCalls native_module_calls() {
  return {.maps = {.open = open_maps, .read = read_maps, .close = close_maps}, .images = native_images};
}

std::vector<Observation> collect_module_provenance(const provenance::Locations& locations, ModuleCalls calls,
                                                   provenance::Clock clock) {
  const provenance::Locations roots = provenance::valid_locations(locations) ? locations : provenance::Locations{};
  Budget map_budget(clock);
  auto first = mappings(calls.maps, map_budget);
  Budget native_budget(clock);
  auto images = calls.images == nullptr
                    ? Result<std::vector<ExecutableImage>>(std::unexpected(Error::kNativeUnavailable))
                    : calls.images(calls.context, native_budget);
  auto ranges = images ? intervals(*images, native_budget)
                       : Result<std::vector<ExecutableInterval>>(std::unexpected(images.error()));
  if (!native_budget.step()) {
    ranges = std::unexpected(native_budget.error());
  }
  if (!ranges) {
    images = std::unexpected(ranges.error());
  }
  provenance::Metadata native_meta{.scope_available = roots.available, .stability = "best_effort"};
  auto native_rows = images ? Result<std::vector<std::string>>(image_rows(*images, roots, native_meta))
                            : Result<std::vector<std::string>>(std::unexpected(images.error()));
  if (!native_budget.step()) {
    native_rows = std::unexpected(native_budget.error());
  }
  auto second = mappings(calls.maps, map_budget);
  provenance::Metadata maps_meta{.scope_available = roots.available};
  std::optional<std::vector<ExecutableInterval>> correlated;
  if (first && second && *first == *second) {
    maps_meta.stability = "bracket_equal";
    if (ranges) {
      correlated = merged_intervals(*ranges);
      maps_meta.correlation = "available";
    }
  } else {
    maps_meta.stability = second ? "changed" : "na";
    maps_meta.correlation = second ? "unstable" : "unavailable";
  }
  if (map_budget.error() != Error::kNone) {
    first = std::unexpected(map_budget.error());
  }
  auto map_values = first ? Result<std::vector<std::string>>(map_rows(*first, roots, correlated, maps_meta))
                          : Result<std::vector<std::string>>(std::unexpected(first.error()));
  if (!map_budget.step()) {
    map_values = std::unexpected(map_budget.error());
  }
  auto maps_pair = provenance::pair("hook.exec_modules", "proc_maps_v1", std::move(map_values), maps_meta);
  auto native_pair = provenance::pair("hook.exec_modules", "dl_iterate_phdr_v1", std::move(native_rows), native_meta);
  return {std::move(maps_pair[0]), std::move(maps_pair[1]), std::move(native_pair[0]), std::move(native_pair[1])};
}

std::vector<Observation> module_provenance() {
#ifdef __ANDROID__
  return collect_module_provenance(application_provenance_locations());
#else
  const auto maps = provenance::pair("hook.exec_modules", "proc_maps_v1", std::unexpected(Error::kPlatform));
  const auto native = provenance::pair("hook.exec_modules", "dl_iterate_phdr_v1", std::unexpected(Error::kPlatform));
  return {maps[0], maps[1], native[0], native[1]};
#endif
}
}  // namespace rasp::android::checks
