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

#ifdef __ANDROID__
#include <dlfcn.h>
#endif

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
/// The signal of the probe that reports the app's threads named like an instrumentation framework's.
constexpr std::string_view kThreadsSignal = "hook.threads";
/// The source of the thread probe.
constexpr std::string_view kTaskSource = "proc_task";
/// The signal of the probe that reports system library functions whose first bytes were rewritten in memory.
constexpr std::string_view kInlineSignal = "hook.inline";
/// The source of the inline-hook probe.
constexpr std::string_view kPrologueSource = "prologue";

/// The largest thread name read. The kernel keeps at most 15 characters and a line break.
constexpr std::size_t kMaxThreadNameSize = 64;
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
/// The bits of an address that hold the address itself. arm64 ignores an address's top byte, where a pointer tag may
/// sit, and on other 64-bit platforms a user-space address never sets it. A 32-bit address keeps all its bits.
constexpr auto kAddressMask = static_cast<std::uintptr_t>(~std::uint64_t{0} >> 8U);
/// The most hexadecimal digits a 64-bit number has.
constexpr std::size_t kMaxHexDigits = 16;
/// The bit a 32-bit Arm function address sets when the function is Thumb code.
constexpr std::uint64_t kThumbBit = 1;

/// The text that marks a mapping made by a known instrumentation or hooking framework, matched anywhere in the line.
/// Frida maps its agent and gadget, Substrate and Xposed map their own libraries, and a gadget is often injected
/// through a `re.frida` or `libgadget` name. These catch a framework that keeps its default names; one rebuilt to
/// rename itself is caught instead by the writable-executable and prologue probes.
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

/// The permissions field of a memory-map line, the second space-separated field, or empty when the line has none.
[[nodiscard]] std::string_view permissions_of(std::string_view line) {
  const std::size_t start = line.find(' ');
  if (start == std::string_view::npos) {
    return {};
  }
  const std::string_view rest = line.substr(start + 1);
  const std::size_t end = rest.find(' ');
  return rest.substr(0, std::min(end, rest.size()));
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

/// The name of the thread whose folder is `thread_folder`, without its line break.
///
/// @param thread_folder The thread's folder, such as `/proc/self/task/1234`.
/// @return The name. Nothing when it can't be read, such as when the thread ended after the folder was listed.
[[nodiscard]] std::optional<std::string> thread_name(const std::filesystem::path& thread_folder) {
  std::optional<std::string> name = read_file((thread_folder / "comm").string(), kMaxThreadNameSize);
  if (name && name->ends_with('\n')) {
    name->pop_back();
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

/// The next space-separated field of `rest`, which is advanced past it; empty when `rest` holds no more fields.
[[nodiscard]] std::string_view next_field(std::string_view& rest) {
  const std::size_t start = rest.find_first_not_of(' ');
  if (start == std::string_view::npos) {
    rest = {};
    return {};
  }
  rest.remove_prefix(start);
  const std::size_t end = std::min(rest.find(' '), rest.size());
  const std::string_view field = rest.substr(0, end);
  rest.remove_prefix(end);
  return field;
}

/// The value of the hexadecimal digit `digit`, or nothing when it isn't one.
[[nodiscard]] std::optional<std::uint64_t> hex_digit(char digit) {
  if (digit >= '0' && digit <= '9') {
    return static_cast<std::uint64_t>(digit - '0');
  }
  if (digit >= 'a' && digit <= 'f') {
    return static_cast<std::uint64_t>(digit - 'a' + 10);
  }
  if (digit >= 'A' && digit <= 'F') {
    return static_cast<std::uint64_t>(digit - 'A' + 10);
  }
  return std::nullopt;
}

/// The hexadecimal number that is the whole of `text`, or nothing when `text` is empty, holds anything but hex digits,
/// or has more digits than a 64-bit number holds.
[[nodiscard]] std::optional<std::uint64_t> parse_hex(std::string_view text) {
  if (text.empty() || text.size() > kMaxHexDigits) {
    return std::nullopt;
  }
  std::uint64_t value = 0;
  for (const char character : text) {
    const std::optional<std::uint64_t> digit = hex_digit(character);
    if (!digit) {
      return std::nullopt;
    }
    value = (value << 4U) | *digit;
  }
  return value;
}

/// The mapping a memory-map `line` describes, or nothing when the line doesn't have the map's format or its addresses
/// don't fit this process's addresses.
[[nodiscard]] std::optional<Mapping> parse_mapping(std::string_view line) {
  std::string_view rest = line;
  const std::string_view range = next_field(rest);
  const std::string_view perms = next_field(rest);
  const std::string_view offset = next_field(rest);
  const std::string_view device = next_field(rest);
  const std::string_view inode = next_field(rest);
  const std::size_t dash = range.find('-');
  if (dash == std::string_view::npos || perms.size() < 3 || device.empty() || inode.empty()) {
    return std::nullopt;
  }
  const std::optional<std::uint64_t> start = parse_hex(range.substr(0, dash));
  const std::optional<std::uint64_t> end = parse_hex(range.substr(dash + 1));
  const std::optional<std::uint64_t> file_offset = parse_hex(offset);
  if (!start || !end || !file_offset || *start >= *end || !std::in_range<std::uintptr_t>(*end)) {
    return std::nullopt;
  }
  const std::size_t path_start = rest.find_first_not_of(' ');
  return Mapping{
      .start = static_cast<std::uintptr_t>(*start),
      .end = static_cast<std::uintptr_t>(*end),
      .file_offset = *file_offset,
      .readable_executable = perms[0] == 'r' && perms[2] == 'x',
      .path = path_start == std::string_view::npos ? std::string() : std::string(rest.substr(path_start)),
  };
}

/// Whether the address range at the start of a memory-map `line` holds `address`.
[[nodiscard]] bool line_holds(std::string_view line, std::uintptr_t address) {
  std::string_view rest = line;
  const std::string_view range = next_field(rest);
  const std::size_t dash = range.find('-');
  if (dash == std::string_view::npos) {
    return false;
  }
  const std::optional<std::uint64_t> start = parse_hex(range.substr(0, dash));
  const std::optional<std::uint64_t> end = parse_hex(range.substr(dash + 1));
  return start && end && *start <= address && address < *end;
}

/// The mapping of `maps` that holds `address`, or nothing when no line holds it or that line can't be parsed.
[[nodiscard]] std::optional<Mapping> mapping_holding(std::string_view maps, std::uintptr_t address) {
  for (const auto piece : std::views::split(maps, '\n')) {
    const std::string_view line(piece.begin(), piece.end());
    if (line_holds(line, address)) {
      return parse_mapping(line);
    }
  }
  return std::nullopt;
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
  if (!headers) {
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
/// only when something rewrote them. A function shorter than kPrologueSize is compared with the file bytes after it in
/// the same segment, which also match when nothing rewrote them.
///
/// @param library The library file, read whole.
/// @param mapping The mapping of the library that holds the function's address.
/// @param function The function, with its address untagged.
/// @return `true` when the bytes differ, `false` when they are equal, or nothing when they can't be compared.
[[nodiscard]] std::optional<bool> prologue_differs(const LibraryFile& library, const Mapping& mapping,
                                                   const ResolvedFunction& function) {
  const std::optional<ElfSymbol> symbol = find_dynamic_symbol(library.bytes, library.headers, function.name);
  if (!symbol || symbol->type != util::kSymbolFunction) {
    return std::nullopt;
  }
  const bool arm = library.headers.machine == util::kMachineArm;
  const std::uint64_t thumb_bit = arm ? kThumbBit : 0U;
  const std::uintptr_t address = function.address & ~static_cast<std::uintptr_t>(thumb_bit);
  const std::uint64_t symbol_address = symbol->value & ~thumb_bit;
  if (address < mapping.start) {
    return std::nullopt;
  }
  const std::optional<CodeLocation> code =
      find_code(library.bytes, library.headers, {.address = symbol_address, .length = 1});
  if (!code || code->file_offset != mapping.file_offset + (address - mapping.start)) {
    return std::nullopt;
  }
  const std::size_t length =
      static_cast<std::size_t>(std::min<std::uint64_t>({kPrologueSize, code->available, mapping.end - address}));
  const std::span<const std::uint8_t> memory(std::bit_cast<const std::uint8_t*>(address), length);
  const std::span<const std::uint8_t> file =
      std::span<const std::uint8_t>(library.bytes).subspan(static_cast<std::size_t>(code->file_offset), length);
  return !std::ranges::equal(memory, file);
}

}  // namespace

std::vector<Observation> observe_maps(std::string_view maps_path) {
  const std::optional<std::string> maps = read_file(maps_path, kMaxMapsSize);
  if (!maps) {
    return {failed(kMapsHitsSignal, kMapsSource), failed(kRwxRegionsSignal, kMapsSource)};
  }
  return {
      observed(kMapsHitsSignal, kMapsSource, matching_lines(*maps, names_framework)),
      observed(kRwxRegionsSignal, kMapsSource, matching_lines(*maps, writable_executable)),
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
  while (iterator != end && threads < kMaxThreads && names.size() < kMaxLines) {
    ++threads;
    const std::optional<std::string> name = thread_name(iterator->path());
    if (name && contains_marker(*name, kThreadMarkers)) {
      names.insert(*name);
    }
    iterator.increment(error);
    if (error) {
      return failed(kThreadsSignal, kTaskSource);
    }
  }
  return observed(kThreadsSignal, kTaskSource, std::vector<std::string>{names.begin(), names.end()});
}

Observation observe_inline_hooks(std::string_view maps_path, std::span<const ResolvedFunction> functions) {
  if (functions.size() > kMaxFunctions) {
    return failed(kInlineSignal, kPrologueSource);
  }
  const std::optional<std::string> maps = read_file(maps_path, kMaxMapsSize);
  if (!maps) {
    return failed(kInlineSignal, kPrologueSource);
  }
  std::optional<LibraryFile> library;
  std::vector<std::string> hooked;
  for (const ResolvedFunction& function : functions) {
    const ResolvedFunction untagged{.name = function.name, .address = function.address & kAddressMask};
    const std::optional<Mapping> mapping = mapping_holding(*maps, untagged.address);
    if (!mapping || !mapping->readable_executable || !mapping->path.starts_with('/')) {
      return failed(kInlineSignal, kPrologueSource);
    }
    if (!library || library->path != mapping->path) {
      library = read_library(mapping->path);
      if (!library) {
        return failed(kInlineSignal, kPrologueSource);
      }
    }
    const std::optional<bool> differs = prologue_differs(*library, *mapping, untagged);
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
    functions.push_back({.name = name, .address = std::bit_cast<std::uintptr_t>(address)});
  }
  return dlclose(handle) == 0 && resolved;
}

/// The hook.inline observation for the watched functions, resolved in this process.
[[nodiscard]] Observation observe_watched_functions() {
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
      unsupported(kMapsHitsSignal, kMapsSource),
      unsupported(kRwxRegionsSignal, kMapsSource),
      unsupported(kThreadsSignal, kTaskSource),
      unsupported(kInlineSignal, kPrologueSource),
  };
}

#endif

}  // namespace rasp::android::checks
