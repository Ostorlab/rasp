/// The Android code-origin checks, and their unsupported results off Android.

#include "checks/code_origin.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iterator>
#include <optional>
#include <ranges>
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
#include "util/app_storage.h"
#include "util/own_library.h"
#endif

namespace rasp::android::checks {

namespace {

constexpr std::string_view kExecOriginSignal = "hook.exec_origin";
constexpr std::string_view kCodeOriginSignal = "hook.code_origin";
constexpr std::string_view kMapsSource = "proc_maps";
constexpr std::string_view kStackSource = "thread_stacks";
constexpr std::string_view kMapsPath = "/proc/self/maps";
constexpr std::string_view kTaskPath = "/proc/self/task";
constexpr std::string_view kCommPath = "/proc/self/comm";
constexpr std::string_view kCmdlinePath = "/proc/self/cmdline";
constexpr std::size_t kMaxMapsSize = std::size_t{4} << 20U;
constexpr std::size_t kMaxNameSize = 512;
/// How much of a thread's stack is searched, from its top, where its record and its live frames are.
constexpr std::size_t kStackScanSize = std::size_t{64} << 10U;
constexpr std::size_t kMaxMappingsReported = 32;
constexpr std::size_t kMaxThreadsReported = 16;

/// An executable mapping the checks report.
struct ForeignCode {
  std::uintptr_t start = 0;
  std::uintptr_t end = 0;
  /// What a thread report calls it: the mapped file, or `[anon]`.
  std::string label;
  std::string_view line;
};

/// The rest of `text` after `prefix`, when `text` starts with it.
[[nodiscard]] std::optional<std::string_view> after(std::string_view text, std::string_view prefix) {
  if (!text.starts_with(prefix)) {
    return std::nullopt;
  }
  return text.substr(prefix.size());
}

/// The rest of `path` after `prefix` and the Android user number that follows it.
[[nodiscard]] std::optional<std::string_view> after_user_folder(std::string_view path, std::string_view prefix) {
  const std::optional<std::string_view> rest = after(path, prefix);
  if (!rest) {
    return std::nullopt;
  }
  const std::size_t slash = rest->find('/');
  if (slash == 0 || slash == std::string_view::npos || !std::ranges::all_of(rest->substr(0, slash), [](char character) {
        return character >= '0' && character <= '9';
      })) {
    return std::nullopt;
  }
  return rest->substr(slash + 1);
}

/// The rest of `path` after `/mnt/expand/` and the adopted storage volume that follows it.
[[nodiscard]] std::optional<std::string_view> on_adopted_volume(std::string_view path) {
  const std::optional<std::string_view> rest = after(path, "/mnt/expand/");
  if (!rest) {
    return std::nullopt;
  }
  const std::size_t slash = rest->find('/');
  if (slash == 0 || slash == std::string_view::npos) {
    return std::nullopt;
  }
  return rest->substr(slash + 1);
}

/// The rest of `path` after the user's data folder, on internal or adopted storage.
[[nodiscard]] std::optional<std::string_view> in_user_data(std::string_view path) {
  if (const std::optional<std::string_view> rest = after(path, "/data/data/")) {
    return rest;
  }
  if (const std::optional<std::string_view> rest = after_user_folder(path, "/data/user/")) {
    return rest;
  }
  if (const std::optional<std::string_view> rest = after_user_folder(path, "/data/user_de/")) {
    return rest;
  }
  const std::optional<std::string_view> volume = on_adopted_volume(path);
  if (!volume) {
    return std::nullopt;
  }
  if (const std::optional<std::string_view> rest = after_user_folder(*volume, "user/")) {
    return rest;
  }
  return after_user_folder(*volume, "user_de/");
}

/// Whether `path` is in the private storage of the app or holds a Google Play services module.
[[nodiscard]] bool is_app_data_code(std::string_view path, const OwnCode& own) {
  const std::optional<std::string_view> rest = in_user_data(path);
  if (!rest) {
    return false;
  }
  const std::size_t slash = rest->find('/');
  if (slash == std::string_view::npos) {
    return false;
  }
  const std::string_view owner = rest->substr(0, slash);
  const std::string_view inside = rest->substr(slash + 1);
  return (!own.package.empty() && owner == own.package) ||
         (owner == "com.google.android.gms" && inside.starts_with("app_chimera/"));
}

/// Whether `path` is an app installed on adopted storage.
[[nodiscard]] bool is_adopted_app_code(std::string_view path) {
  const std::optional<std::string_view> rest = on_adopted_volume(path);
  return rest && rest->starts_with("app/");
}

/// Whether `path` is an installed file the process is expected to run code from.
[[nodiscard]] bool is_installed_code(std::string_view path, const OwnCode& own) {
  return path.starts_with("/system/") || path.starts_with("/system_ext/") || path.starts_with("/product/") ||
         path.starts_with("/vendor/") || path.starts_with("/odm/") || path.starts_with("/apex/") ||
         path.starts_with("/data/app/") || path.starts_with("/data/dalvik-cache/") ||
         path.starts_with("/data/misc/apexdata/com.android.art/dalvik-cache/") || is_adopted_app_code(path) ||
         is_app_data_code(path, own);
}

/// Whether `name` is a code region the kernel maps into every process.
[[nodiscard]] bool is_kernel_code(std::string_view name) {
  return name == "[vdso]" || name == "[vectors]" || name == "[sigpage]" || name == "[vsyscall]";
}

/// Whether `name` is the name of the memfd ART keeps its JIT code cache in.
[[nodiscard]] bool is_art_jit_memfd(std::string_view name) { return name == "jit-cache" || name == "jit-zygote-cache"; }

/// Whether the start of the memfd behind `mapping` is mapped somewhere and doesn't hold an ELF header, which a library
/// loaded from a memfd carries.
[[nodiscard]] bool has_plain_memfd_start(const util::Mapping& mapping, std::span<const util::Mapping> mappings,
                                         rasp::util::MemoryReader read_memory) {
  const auto view = std::ranges::find_if(mappings, [&mapping](const util::Mapping& other) {
    return other.offset == 0 && other.inode == mapping.inode && other.device == mapping.device &&
           other.pathname == mapping.pathname;
  });
  if (view == mappings.end()) {
    return false;
  }
  const std::optional<std::string> head = read_memory(view->start, 4);
  if (!head || head->size() < 4) {
    return true;
  }
  const std::string& bytes = *head;
  return bytes[0] != '\x7f' || bytes[1] != 'E' || bytes[2] != 'L' || bytes[3] != 'F';
}

/// Whether the executable `mapping` is code the process is expected to run.
[[nodiscard]] bool is_expected_code(const util::Mapping& mapping, std::span<const util::Mapping> mappings,
                                    const OwnCode& own, rasp::util::MemoryReader read_memory) {
  if (own.image_start < own.image_end && mapping.start >= own.image_start && mapping.end <= own.image_end) {
    return true;
  }
  const std::string_view path = mapping.pathname;
  if (path.empty()) {
    return false;
  }
  if (path.starts_with('[')) {
    return is_kernel_code(path);
  }
  if (const std::optional<std::string_view> name = after(path, "/memfd:")) {
    return mapping.shared && is_art_jit_memfd(*name) && has_plain_memfd_start(mapping, mappings, read_memory);
  }
  return !mapping.deleted && is_installed_code(path, own);
}

/// What a thread report calls `mapping`.
[[nodiscard]] std::string label_of(const util::Mapping& mapping) {
  if (mapping.pathname.empty()) {
    return "[anon]";
  }
  std::string label(mapping.pathname);
  if (mapping.deleted) {
    label += " (deleted)";
  }
  return label;
}

/// The executable mappings of `mappings` that aren't code the process is expected to run, in address order.
[[nodiscard]] std::vector<ForeignCode> find_foreign_code(std::span<const util::Mapping> mappings, const OwnCode& own,
                                                         rasp::util::MemoryReader read_memory) {
  std::vector<ForeignCode> foreign;
  for (const util::Mapping& mapping : mappings) {
    if (mapping.executable && !is_expected_code(mapping, mappings, own, read_memory)) {
      foreign.push_back({.start = mapping.start, .end = mapping.end, .label = label_of(mapping), .line = mapping.line});
    }
  }
  return foreign;
}

/// The foreign code that holds `address`, or null.
[[nodiscard]] const ForeignCode* foreign_at(std::span<const ForeignCode> foreign, std::uintptr_t address) {
  const auto after_address = std::ranges::upper_bound(foreign, address, {}, &ForeignCode::start);
  if (after_address == foreign.begin()) {
    return nullptr;
  }
  const ForeignCode& candidate = *std::prev(after_address);
  return address < candidate.end ? &candidate : nullptr;
}

/// Whether `name` is a thread id: all digits.
[[nodiscard]] bool is_thread_id(std::string_view name) {
  return !name.empty() &&
         std::ranges::all_of(name, [](char character) { return character >= '0' && character <= '9'; });
}

/// The id of the thread whose stack `mapping` is: empty for the main thread, nothing when it isn't a thread's stack.
[[nodiscard]] std::optional<std::string_view> stack_owner(const util::Mapping& mapping) {
  if (!mapping.readable || mapping.executable) {
    return std::nullopt;
  }
  if (mapping.pathname == "[stack]") {
    return std::string_view();
  }
  const std::optional<std::string_view> rest = after(mapping.pathname, "[anon:stack_and_tls:");
  if (!rest || !rest->ends_with(']')) {
    return std::nullopt;
  }
  const std::string_view id = rest->substr(0, rest->size() - 1);
  if (!is_thread_id(id)) {
    return std::nullopt;
  }
  return id;
}

/// The first foreign code that `words` holds an address of, or null.
[[nodiscard]] const ForeignCode* first_foreign_address(std::string_view words, std::span<const ForeignCode> foreign) {
  for (std::size_t at = 0; at + sizeof(std::uintptr_t) <= words.size(); at += sizeof(std::uintptr_t)) {
    std::uintptr_t word = 0;
    std::memcpy(&word, words.substr(at, sizeof(word)).data(), sizeof(word));
    if (const ForeignCode* const code = foreign_at(foreign, word)) {
      return code;
    }
  }
  return nullptr;
}

/// The name of the thread that owns a stack, read from `comm`, or `fallback` when it can't be read.
[[nodiscard]] std::string thread_name(const std::string& comm, std::string_view fallback, rasp::util::ProcReader read) {
  const std::optional<std::string> name = read(comm, kMaxNameSize);
  if (!name) {
    return std::string(fallback);
  }
  std::string_view trimmed(*name);
  while (trimmed.ends_with('\n')) {
    trimmed.remove_suffix(1);
  }
  return std::string(trimmed);
}

/// The `<thread name> -> <where>` findings of the thread stacks that hold an address of foreign code; nothing when no
/// thread stack could be read.
[[nodiscard]] std::optional<std::vector<std::string>> scan_stacks(const ProcessPaths& paths,
                                                                  std::span<const util::Mapping> mappings,
                                                                  std::span<const ForeignCode> foreign,
                                                                  const rasp::util::ProcessAccess& access) {
  std::vector<std::string> findings;
  std::size_t stacks = 0;
  std::size_t unread = 0;
  for (const util::Mapping& mapping : mappings) {
    const std::optional<std::string_view> owner = stack_owner(mapping);
    if (!owner) {
      continue;
    }
    ++stacks;
    const std::size_t size = std::min<std::uintptr_t>(kStackScanSize, mapping.end - mapping.start);
    const std::optional<std::string> words = access.read_memory(mapping.end - size, size);
    if (!words) {
      ++unread;
      continue;
    }
    const ForeignCode* const code = first_foreign_address(*words, foreign);
    if (code == nullptr) {
      continue;
    }
    const std::string comm =
        owner->empty() ? std::string(paths.comm) : std::string(paths.task) + "/" + std::string(*owner) + "/comm";
    findings.push_back(thread_name(comm, owner->empty() ? "main" : *owner, access.read) + " -> " + code->label);
  }
  if (stacks > 0 && unread == stacks) {
    return std::nullopt;
  }
  return findings;
}

/// The hook.code_origin observation: the threads whose stack holds an address of foreign code.
[[nodiscard]] Observation observe_thread_origin(const ProcessPaths& paths, std::span<const util::Mapping> mappings,
                                                std::span<const ForeignCode> foreign,
                                                const rasp::util::ProcessAccess& access) {
  if (foreign.empty()) {
    return observed(kCodeOriginSignal, kStackSource, std::vector<std::string>());
  }
  std::optional<std::vector<std::string>> findings = scan_stacks(paths, mappings, foreign, access);
  if (!findings) {
    return failed(kCodeOriginSignal, kStackSource);
  }
  std::ranges::sort(*findings);
  const auto [removed_begin, removed_end] = std::ranges::unique(*findings);
  findings->erase(removed_begin, removed_end);
  if (findings->size() > kMaxThreadsReported) {
    findings->resize(kMaxThreadsReported);
  }
  return observed(kCodeOriginSignal, kStackSource, std::move(*findings));
}

}  // namespace

std::vector<Observation> observe_code_origin(const ProcessPaths& paths, const OwnCode& own,
                                             const rasp::util::ProcessAccess& access) {
  const std::optional<std::string> maps = access.read(paths.maps, kMaxMapsSize);
  if (!maps) {
    return {failed(kExecOriginSignal, kMapsSource), failed(kCodeOriginSignal, kStackSource)};
  }
  const std::vector<util::Mapping> mappings = util::parse_memory_map(*maps);
  const std::vector<ForeignCode> foreign = find_foreign_code(mappings, own, access.read_memory);
  std::vector<std::string> lines;
  for (const ForeignCode& code : foreign | std::views::take(kMaxMappingsReported)) {
    lines.emplace_back(code.line);
  }
  std::vector<Observation> observations;
  observations.push_back(observed(kExecOriginSignal, kMapsSource, std::move(lines)));
  observations.push_back(observe_thread_origin(paths, mappings, foreign, access));
  return observations;
}

std::vector<Observation> code_origin() {
  static constexpr std::array kObfuscatedLiterals = {
      kExecOriginSignal, kCodeOriginSignal, kMapsSource, kStackSource, kMapsPath, kTaskPath, kCommPath, kCmdlinePath,
  };
  rasp::util::anchor_literals(kObfuscatedLiterals);
#ifdef __ANDROID__
  constexpr std::size_t kMaxCmdlineSize = 4096;
  const std::optional<util::LoadedLibrary> library = util::find_own_library();
  const std::optional<std::string> cmdline = rasp::util::read_proc_file(kCmdlinePath, kMaxCmdlineSize);
  const OwnCode own{
      .image_start = library ? library->load_bias : 0,
      .image_end = library ? library->load_bias + static_cast<std::uintptr_t>(library->image_size) : 0,
      .package = cmdline ? util::package_name(*cmdline) : std::string_view(),
  };
  return observe_code_origin({.maps = kMapsPath, .task = kTaskPath, .comm = kCommPath}, own);
#else
  return {unsupported(kExecOriginSignal, kMapsSource), unsupported(kCodeOriginSignal, kStackSource)};
#endif
}

}  // namespace rasp::android::checks
