/// The Android hooking checks: the memory-map probe, the thread probe, the inline-hook probe, and their unsupported
/// results off Android. The list of instrumentation markers draws on the names Frida, Substrate and Xposed map their
/// code under, and the thread markers on the names of the threads Frida's agent starts. The inline-hook probe reads
/// library files through the shared ELF reader in util/elf.h.

#include "checks/hooks.h"

#include <algorithm>
#include <array>
#include <bit>
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <iterator>
#include <limits>
#include <optional>
#include <ranges>
#include <set>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include "rasp/observation.h"
#include "rasp/util/read_file.h"
#include "util/apk_file.h"
#include "util/elf.h"

#ifdef __linux__
#include <sys/uio.h>
#if __has_include(<bits/types/struct_iovec.h>)
#include <bits/types/struct_iovec.h>
#else
#include <linux/uio.h>
#endif
#include <unistd.h>
#elifdef __APPLE__
#include <mach/mach.h>
#include <mach/mach_vm.h>
#endif

#ifdef __ANDROID__
#include <dlfcn.h>
#endif
#include "util/direct_syscall.h"
#include "util/proc_text.h"

namespace rasp::android::checks {

namespace {

using rasp::util::read_file;
using util::CodeLocation;
using util::ElfHeaders;
using util::ElfSymbol;
using util::find_code;
using util::find_dynamic_symbol;
using util::read_elf_headers;
using util::read_library_file;

/// The signal of the probe that reports mappings of a known instrumentation framework.
constexpr std::string_view kMapsHitsSignal = "hook.maps_hits";
/// The signal of the probe that reports writable-executable mappings.
constexpr std::string_view kRwxRegionsSignal = "hook.rwx_regions";
/// The source of both memory-map probes.
constexpr std::string_view kMapsSource = "proc_maps";
/// The map source using the hookable libc syscall entry.
constexpr std::string_view kMapsDirectSource = "proc_maps_syscall";
/// The signal of the probe that reports the app's threads named like an instrumentation framework's.
constexpr std::string_view kThreadsSignal = "hook.threads";
/// The source of the thread probe.
constexpr std::string_view kTaskSource = "proc_task";
/// The signal of the probe that reports system library functions whose first bytes were rewritten in memory.
constexpr std::string_view kInlineSignal = "hook.inline";
/// The source of the inline-hook probe.
constexpr std::string_view kPrologueSource = "prologue";

/// The largest thread name read. The kernel keeps at most 15 characters and a line break.
constexpr std::size_t kMaxThreadNameSize = 16;
/// The most threads looked at. An app has a few hundred at most.
constexpr std::size_t kMaxThreads = 4096;
/// The largest memory map read. A real one is a few hundred KiB.
constexpr std::size_t kMaxMapsSize = std::size_t{4} << 20U;
/// The most lines reported in each list.
constexpr std::size_t kMaxLines = 32;
/// The number of a function's first bytes compared. Frida's Interceptor, Dobby and Substrate write a jump of at most
/// 16 bytes over a function's start.
constexpr std::size_t kPrologueSize = 16;
/// The largest system library file read. libc.so is about 1 MiB.
constexpr std::size_t kMaxLibrarySize = std::size_t{32} << 20U;
/// The most functions the inline-hook probe compares in one run.
constexpr std::size_t kMaxFunctions = 64;
/// Removes AArch64 top-byte tags. Other ELF machines reject addresses changed by this mask; a 32-bit address
/// retains every bit.
constexpr auto kAddressMask = static_cast<std::uintptr_t>(~std::uint64_t{0} >> 8U);
/// The largest accepted function-name length in bytes.
constexpr std::size_t kMaxFunctionName = 128;
/// The bit a 32-bit Arm function address sets when the function is Thumb code.
constexpr std::uint64_t kThumbBit = 1;

/// The text that marks a mapping made by a known instrumentation or hooking framework, matched anywhere in the line.
/// Frida maps its agent and gadget, Substrate and Xposed map their own libraries, and a gadget is often injected
/// through a `re.frida` or `libgadget` name. These are heuristic markers; renaming or hiding a framework can evade
/// them, and a matching name alone does not establish instrumentation.
constexpr auto kFrameworkMarkers = std::to_array<std::string_view>({
    "frida",
    "gadget",
    "gum-js-loop",
    "substrate",
    "xposed",
    "lsposed",
    "riru",
    "zygisk",
    "magisk",
});

/// The text that marks a thread started by Frida's agent, matched anywhere in the thread's name: its JavaScript thread,
/// `gum-js-loop`, and its worker pool, `pool-frida`. The kernel keeps only a thread's first 15 characters, which these
/// fit in.
constexpr auto kThreadMarkers = std::to_array<std::string_view>({
    "gum-js-loop",
    "frida",
});

/// Validated kernel map fields, borrowed only while parsing the caller's snapshot.
struct MapFields {
  /// The first address, before checking this process's address width.
  std::uint64_t start;
  /// The address past the mapping.
  std::uint64_t end;
  /// The mapping's file offset.
  std::uint64_t file_offset;
  /// The validated permissions field.
  std::string_view permissions;
  /// The path after the numeric fields.
  std::string_view path;
};

/// Parses the address range, permissions and numeric kernel fields of one maps record.
[[nodiscard]] std::optional<MapFields> parse_map_fields(std::string_view line) {
  std::string_view rest = line;
  const std::string_view range = util::take_proc_field(rest);
  const std::size_t dash = range.find('-');
  if (dash == std::string_view::npos) {
    return std::nullopt;
  }
  const auto start = util::proc_number(range.substr(0, dash), 16);
  const auto end = util::proc_number(range.substr(dash + 1), 16);
  const std::string_view perms = util::take_proc_field(rest);
  const auto offset = util::proc_number(util::take_proc_field(rest), 16);
  const std::string_view device = util::take_proc_field(rest);
  const std::size_t colon = device.find(':');
  if (colon == std::string_view::npos) {
    return std::nullopt;
  }
  const auto major = util::proc_number(device.substr(0, colon), 16);
  const auto minor = util::proc_number(device.substr(colon + 1), 16);
  const auto inode = util::proc_number(util::take_proc_field(rest), 10);
  const bool valid = start.has_value() && end.has_value() && *start < *end && perms.size() == 4 &&
                     (perms[0] == 'r' || perms[0] == '-') && (perms[1] == 'w' || perms[1] == '-') &&
                     (perms[2] == 'x' || perms[2] == '-') && (perms[3] == 'p' || perms[3] == 's') &&
                     offset.has_value() && major.has_value() && minor.has_value() && inode.has_value();
  if (!valid) {
    return std::nullopt;
  }
  return MapFields{.start = *start, .end = *end, .file_offset = *offset, .permissions = perms, .path = rest};
}

/// Whether a maps record has a valid address range, permissions and numeric kernel fields.
[[nodiscard]] bool valid_map_line(std::string_view line) { return parse_map_fields(line).has_value(); }

/// The permissions field of an already validated memory-map line.
[[nodiscard]] std::string_view permissions_of(std::string_view line) {
  static_cast<void>(util::take_proc_field(line));
  return util::take_proc_field(line);
}

/// Whether `text` contains one of `markers`, ignoring case.
///
/// @param text The text to look in.
/// @param markers The lowercase markers.
/// @return `true` when one of them is in `text`.
[[nodiscard]] bool contains_marker(std::string_view text, std::span<const std::string_view> markers) {
  std::string lowered(text);
  std::ranges::transform(lowered, lowered.begin(), [](char character) {
    return static_cast<char>(std::tolower(static_cast<unsigned char>(character)));
  });
  return std::ranges::any_of(markers, [&lowered](std::string_view marker) { return lowered.contains(marker); });
}

/// Whether `line` is a mapping that names a known instrumentation framework.
[[nodiscard]] bool names_framework(std::string_view line) { return contains_marker(line, kFrameworkMarkers); }

/// The validated visible kernel name, or nothing for unreadable, incomplete or malformed comm data.
///
/// @param thread_folder The thread's folder, such as `/proc/self/task/1234`.
/// @return One to fifteen non-control bytes, without the required final newline. Kernel truncation is not recoverable.
[[nodiscard]] std::optional<std::string> thread_name(const std::filesystem::path& thread_folder) {
  std::optional<std::string> name = read_file((thread_folder / "comm").string(), kMaxThreadNameSize);
  if (!name.has_value() || name->size() < 2 || !name->ends_with('\n')) {
    return std::nullopt;
  }
  name->pop_back();
  if (std::ranges::any_of(*name, [](unsigned char character) { return character < 32 || character == 127; })) {
    return std::nullopt;
  }
  return name;
}

/// Whether `line` maps memory that is both writable and executable.
[[nodiscard]] bool writable_executable(std::string_view line) {
  const std::string_view perms = permissions_of(line);
  return perms.size() >= 3 && perms[1] == 'w' && perms[2] == 'x';
}

/// The first kMaxLines lines of `maps` that `matches`, without their line breaks.
[[nodiscard]] std::vector<std::string> matching_lines(std::string_view maps, bool (*matches)(std::string_view line)) {
  std::vector<std::string> lines;
  for (const auto piece : std::views::split(maps, '\n')) {
    const std::string_view line(piece.begin(), piece.end());
    if (line.empty() || !matches(line)) {
      continue;
    }
    lines.emplace_back(line);
    if (lines.size() == kMaxLines) {
      break;
    }
  }
  return lines;
}

/// One line of a memory map, with the fields the inline-hook probe needs.
struct Mapping {
  /// The first address of the mapping.
  std::uintptr_t start = 0;
  /// The address just past the mapping.
  std::uintptr_t end = 0;
  /// The offset in the file of the mapping's first byte.
  std::uint64_t file_offset = 0;
  /// Whether the mapping is both readable and executable.
  bool readable_executable = false;
  /// The path of the mapped file, or a name such as `[stack]` or empty for memory not mapped from a file.
  std::string path;
};

/// Parses every bounded record once, owns its paths, and rejects all overlapping ranges before comparisons.
[[nodiscard]] std::optional<std::vector<Mapping>> parse_mappings(std::string_view maps) {
  std::vector<Mapping> mappings;
  const bool valid = util::valid_proc_table(maps, [&mappings](std::string_view line) {
    const auto fields = parse_map_fields(line);
    if (!fields.has_value() || !std::in_range<std::uintptr_t>(fields->end)) {
      return false;
    }
    mappings.push_back({
        .start = static_cast<std::uintptr_t>(fields->start),
        .end = static_cast<std::uintptr_t>(fields->end),
        .file_offset = fields->file_offset,
        .readable_executable = fields->permissions == "r-xp" || fields->permissions == "r-xs",
        .path = std::string(fields->path),
    });
    return true;
  });
  if (!valid) {
    return std::nullopt;
  }
  std::ranges::sort(mappings, {}, &Mapping::start);
  for (std::size_t index = 1; index < mappings.size(); ++index) {
    if (mappings[index].start < mappings[index - 1].end) {
      return std::nullopt;
    }
  }
  return mappings;
}

/// The mapping containing address in an already validated, sorted, nonoverlapping snapshot, or null if absent.
[[nodiscard]] const Mapping* mapping_holding(std::span<const Mapping> mappings, std::uintptr_t address) {
  const auto after = std::ranges::upper_bound(mappings, address, {}, &Mapping::start);
  if (after == mappings.begin()) {
    return nullptr;
  }
  const Mapping& mapping = *std::prev(after);
  return address < mapping.end ? &mapping : nullptr;
}

/// Reads exactly the requested own-process bytes through the OS; stale maps, denial and short reads fail safely.
[[nodiscard]] bool read_prologue(std::uintptr_t address, std::span<std::uint8_t> output) {
#ifdef __linux__
  const iovec local{.iov_base = output.data(), .iov_len = output.size()};
  const iovec remote{.iov_base = std::bit_cast<void*>(address), .iov_len = output.size()};
  return process_vm_readv(getpid(), &local, 1, &remote, 1, 0) == static_cast<ssize_t>(output.size());
#elifdef __APPLE__
  mach_vm_size_t count = 0;
  return mach_vm_read_overwrite(mach_task_self(), address, output.size(),
                                std::bit_cast<mach_vm_address_t>(output.data()), &count) == KERN_SUCCESS &&
         count == output.size();
#else
  static_cast<void>(address);
  static_cast<void>(output);
  return false;
#endif
}

/// A library file read whole, with its ELF headers.
struct LibraryFile {
  /// The path the file was read from, as the memory map names it.
  std::string path;
  /// The bytes of the file.
  std::vector<std::uint8_t> bytes;
  /// The file's ELF headers.
  ElfHeaders headers;
};

/// Reads the library file at `path` and its ELF headers, or nothing when it can't be read, is larger than
/// kMaxLibrarySize, or isn't an ELF file.
[[nodiscard]] std::optional<LibraryFile> read_library(std::string_view path) {
  std::optional<std::vector<std::uint8_t>> bytes = read_library_file(path, kMaxLibrarySize);
  if (!bytes) {
    return std::nullopt;
  }
  const std::optional<ElfHeaders> headers = read_elf_headers(*bytes);
  if (!headers.has_value() || (headers->elf64 ? (headers->machine != 183 && headers->machine != 62)
                                              : (headers->machine != util::kMachineArm && headers->machine != 3))) {
    return std::nullopt;
  }
  return LibraryFile{.path = std::string(path), .bytes = std::move(*bytes), .headers = *headers};
}

/// Whether the first bytes of `function` in memory differ from its bytes in `library`, the file `mapping` maps.
///
/// The symbol must be a function (STT_FUNC). An IFUNC symbol's value is its resolver, not the code the linker resolved
/// the name to, so it can't be compared and gives nothing. On 32-bit Arm, the Thumb bit is cleared from the address
/// and from the symbol's value, so both name the first instruction. The file offset of the address, read from the
/// mapping, must equal the file offset of the symbol, read from the program headers: that proves the bytes compared
/// are the function's own. The loader maps an executable segment unchanged, since Android refuses text relocations
/// from API 23, and a PC-relative call or jump to a PLT stub is the same in memory as in the file, so the bytes differ
/// when something rewrote them. Loader-declared text relocations make the baseline unavailable. A short function is
/// compared only within its nonzero symbol size; a partial mapping or OS read is an error.
///
/// @param library The library file, read whole.
/// @param mapping The mapping of the library that holds the function's address.
/// @param function The function, with its address untagged.
/// @return `true` when the bytes differ, `false` when they are equal, or nothing when they can't be compared.
[[nodiscard]] std::optional<bool> prologue_differs(const LibraryFile& library, const Mapping& mapping,
                                                   const ResolvedFunction& function) {
  const std::optional<ElfSymbol> symbol = find_dynamic_symbol(library.bytes, library.headers, function.name);
  if (!symbol.has_value() || symbol->type != util::kSymbolFunction || symbol->size == 0) {
    return std::nullopt;
  }
  const bool arm = library.headers.machine == util::kMachineArm;
  const std::uint64_t thumb_bit = arm ? kThumbBit : 0U;
  const std::uintptr_t address = function.address & ~static_cast<std::uintptr_t>(thumb_bit);
  const std::uint64_t symbol_address = symbol->value & ~thumb_bit;
  if (address < mapping.start) {
    return std::nullopt;
  }
  const auto length = static_cast<std::size_t>(std::min<std::uint64_t>(kPrologueSize, symbol->size));
  const std::optional<CodeLocation> code =
      find_code(library.bytes, library.headers, {.address = symbol_address, .length = symbol->size});
  const std::uint64_t mapped_delta = address - mapping.start;
  if (!code.has_value() || address >= mapping.end || length > mapping.end - address ||
      mapped_delta > std::numeric_limits<std::uint64_t>::max() - mapping.file_offset ||
      code->file_offset != mapping.file_offset + mapped_delta ||
      !util::immutable_code(library.bytes, library.headers)) {
    return std::nullopt;
  }
  std::array<std::uint8_t, kPrologueSize> bytes{};
  const std::span<std::uint8_t> memory = std::span(bytes).first(length);
  if (!read_prologue(address, memory)) {
    return std::nullopt;
  }
  const std::span<const std::uint8_t> file =
      std::span<const std::uint8_t>(library.bytes).subspan(static_cast<std::size_t>(code->file_offset), length);
  return !std::ranges::equal(memory, file);
}

/// Compares one resolved function, reusing the most recently read library without retaining caller-owned views.
[[nodiscard]] std::optional<bool> compare_function(std::span<const Mapping> mappings, const ResolvedFunction& function,
                                                   std::optional<LibraryFile>& library) {
  const ResolvedFunction untagged{.name = function.name, .address = function.address & kAddressMask};
  const Mapping* const mapping = mapping_holding(mappings, untagged.address);
  if (mapping == nullptr || !mapping->readable_executable || !mapping->path.starts_with('/')) {
    return std::nullopt;
  }
  if (!library || library->path != mapping->path) {
    library = read_library(mapping->path);
    if (!library) {
      return std::nullopt;
    }
  }
  if ((function.expected_machine != 0 && function.expected_machine != library->headers.machine) ||
      (function.address != untagged.address && library->headers.machine != 183)) {
    return std::nullopt;
  }
  return prologue_differs(*library, *mapping, untagged);
}

}  // namespace

std::vector<Observation> observe_maps(std::string_view maps_path, util::SystemCall invoke) {
  std::optional<std::string> maps = read_file(maps_path, kMaxMapsSize);
  std::optional<std::string> direct_maps = util::read_file_direct(maps_path, kMaxMapsSize, invoke);
  if (maps.has_value() && !util::valid_proc_table(*maps, valid_map_line)) {
    maps.reset();
  }
  if (direct_maps.has_value() && !util::valid_proc_table(*direct_maps, valid_map_line)) {
    direct_maps.reset();
  }
  return {
      maps ? observed(kMapsHitsSignal, kMapsSource, matching_lines(*maps, names_framework))
           : failed(kMapsHitsSignal, kMapsSource),
      maps ? observed(kRwxRegionsSignal, kMapsSource, matching_lines(*maps, writable_executable))
           : failed(kRwxRegionsSignal, kMapsSource),
      direct_maps ? observed(kMapsHitsSignal, kMapsDirectSource, matching_lines(*direct_maps, names_framework))
                  : failed(kMapsHitsSignal, kMapsDirectSource),
  };
}

Observation observe_threads(std::string_view task_path) {
  std::error_code error;
  std::filesystem::directory_iterator iterator(std::filesystem::path(task_path), error);
  if (error) {
    return failed(kThreadsSignal, kTaskSource);
  }
  const std::filesystem::directory_iterator end;
  std::set<std::string> names;
  std::size_t threads = 0;
  for (; iterator != end && !error; iterator.increment(error)) {
    if (!util::is_thread_id(iterator->path().filename().string())) {
      continue;
    }
    if (threads == kMaxThreads) {
      return failed(kThreadsSignal, kTaskSource);
    }
    ++threads;
    const std::optional<std::string> name = thread_name(iterator->path());
    if (!name.has_value()) {
      return failed(kThreadsSignal, kTaskSource);
    }
    if (contains_marker(*name, kThreadMarkers)) {
      names.insert(*name);
      if (names.size() > kMaxLines) {
        names.erase(std::prev(names.end()));
      }
    }
  }
  if (error) {
    return failed(kThreadsSignal, kTaskSource);
  }
  return observed(kThreadsSignal, kTaskSource, std::vector<std::string>{names.begin(), names.end()});
}

Observation observe_inline_hooks(std::string_view maps_path, std::span<const ResolvedFunction> functions) {
  if (functions.empty() || functions.size() > kMaxFunctions) {
    return failed(kInlineSignal, kPrologueSource);
  }
  const std::optional<std::string> maps = read_file(maps_path, kMaxMapsSize);
  if (!maps.has_value()) {
    return failed(kInlineSignal, kPrologueSource);
  }
  const auto mappings = parse_mappings(*maps);
  if (!mappings.has_value()) {
    return failed(kInlineSignal, kPrologueSource);
  }
  std::optional<LibraryFile> library;
  std::vector<std::string> hooked;
  std::set<std::string_view> names;
  for (const ResolvedFunction& function : functions) {
    if (function.name.empty() || function.name.size() > kMaxFunctionName || function.name.contains('\0') ||
        !names.insert(function.name).second) {
      return failed(kInlineSignal, kPrologueSource);
    }
    const std::optional<bool> differs = compare_function(*mappings, function, library);
    if (!differs) {
      return failed(kInlineSignal, kPrologueSource);
    }
    if (*differs) {
      hooked.emplace_back(function.name);
    }
  }
  return observed(kInlineSignal, kPrologueSource, std::move(hooked));
}

#ifdef __ANDROID__

namespace {

/// The ELF machine of the production process, with zero for an unsupported build target.
#ifdef __aarch64__
constexpr std::uint16_t kNativeMachine = 183;
#elifdef __arm__
constexpr std::uint16_t kNativeMachine = 40;
#elifdef __x86_64__
constexpr std::uint16_t kNativeMachine = 62;
#elifdef __i386__
constexpr std::uint16_t kNativeMachine = 3;
#else
constexpr std::uint16_t kNativeMachine = 0;
#endif

/// The app's memory map.
constexpr std::string_view kMapsPath = "/proc/self/maps";
/// The folder that holds one folder per thread of the app.
constexpr std::string_view kTaskPath = "/proc/self/task";

/// The libc functions whose first bytes the inline-hook probe compares: those the runtime's checks call, and those
/// root, debugger and Frida bypass scripts hook to hide files, processes and their own exit. The string functions,
/// which bypass scripts also hook, are left out, because bionic resolves them through IFUNC resolvers on some devices.
constexpr auto kLibcFunctions = std::to_array<std::string_view>({
    "open",
    "openat",
    "read",
    "fopen",
    "fread",
    "access",
    "faccessat",
    "stat",
    "lstat",
    "fstat",
    "fstatat",
    "readlink",
    "opendir",
    "readdir",
    "syscall",
    "ptrace",
    "fork",
    "kill",
    "exit",
    "_exit",
    "abort",
    "pthread_create",
    "mmap",
    "connect",
    "__system_property_get",
    "__system_property_find",
    "__system_property_read_callback",
});

/// The libdl functions whose first bytes the inline-hook probe compares: those the runtime calls to find its own
/// library, and those bypass scripts hook to hide or catch the libraries an app loads.
constexpr auto kLibdlFunctions = std::to_array<std::string_view>({
    "dlopen",
    "android_dlopen_ext",
    "dlsym",
    "dladdr",
    "dl_iterate_phdr",
});

/// A system library and the functions of it the inline-hook probe compares.
struct WatchedLibrary {
  /// The library's name, as dlopen takes it.
  std::string_view name;
  /// The functions of the library to compare.
  std::span<const std::string_view> functions;
};

/// The libraries whose functions the inline-hook probe compares, with those functions.
constexpr auto kWatchedLibraries = std::to_array<WatchedLibrary>({
    {.name = "libc.so", .functions = kLibcFunctions},
    {.name = "libdl.so", .functions = kLibdlFunctions},
});

/// Resolves the functions of `library` through the library's own handle, and appends them to `functions`.
///
/// The handle limits the lookup to the library itself, so the address is the library's own definition, even when
/// another library interposes the name, as ART's libsigchain does for the signal functions. The library is already
/// loaded in every app, so it is opened without loading it.
///
/// @param library The library and the names of its functions.
/// @param functions Where the resolved functions are appended.
/// @return `true` when the library is loaded and every function resolved.
[[nodiscard]] bool resolve_functions(const WatchedLibrary& library, std::vector<ResolvedFunction>& functions) {
  void* const handle = dlopen(std::string(library.name).c_str(), RTLD_NOW | RTLD_NOLOAD);
  if (handle == nullptr) {
    return false;
  }
  bool resolved = true;
  for (const std::string_view name : library.functions) {
    const void* const address = dlsym(handle, std::string(name).c_str());
    if (address == nullptr) {
      resolved = false;
      break;
    }
    functions.push_back(
        {.name = name, .address = std::bit_cast<std::uintptr_t>(address), .expected_machine = kNativeMachine});
  }
  return dlclose(handle) == 0 && resolved;
}

/// The hook.inline observation for the watched functions, resolved in this process.
[[nodiscard]] Observation observe_watched_functions() {
  if constexpr (kNativeMachine == 0) {
    return unsupported(kInlineSignal, kPrologueSource);
  }
  std::vector<ResolvedFunction> functions;
  functions.reserve(kLibcFunctions.size() + kLibdlFunctions.size());
  for (const WatchedLibrary& library : kWatchedLibraries) {
    if (!resolve_functions(library, functions)) {
      return failed(kInlineSignal, kPrologueSource);
    }
  }
  return observe_inline_hooks(kMapsPath, functions);
}

}  // namespace

std::vector<Observation> hooks() {
  std::vector<Observation> observations = observe_maps(kMapsPath);
  observations.push_back(observe_threads(kTaskPath));
  observations.push_back(observe_watched_functions());
  return observations;
}

#else

std::vector<Observation> hooks() {
  return {
      unsupported(kMapsHitsSignal, kMapsSource),       unsupported(kRwxRegionsSignal, kMapsSource),
      unsupported(kMapsHitsSignal, kMapsDirectSource), unsupported(kThreadsSignal, kTaskSource),
      unsupported(kInlineSignal, kPrologueSource),
  };
}

#endif

}  // namespace rasp::android::checks
