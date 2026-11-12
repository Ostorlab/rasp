/// Strict bounded own-process mountinfo and namespace reads; stock overlays and namespaces are context.
#include "checks/root_namespace.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstddef>
#include <fcntl.h>
#ifdef __BIONIC__
#include <asm-generic/fcntl.h>
#if defined(__aarch64__) || defined(__arm__)
#include <asm/fcntl.h>
#endif
#include <linux/stat.h>
#endif
#include <optional>
#include <ranges>
#include <span>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <unistd.h>
#include <utility>
#include <vector>

#include "rasp/observation.h"
#include "util/proc_text.h"

namespace rasp::android::checks {
namespace {
/// Fixed bounds apply before copying input or accepting a partial summary.
constexpr std::size_t kMaxBytes = 1048576;
/// Fixed identity of the aggregate output.
constexpr std::string_view kMountSignal = "root.mountinfo_context_v1";
/// Fixed identity of the aggregate source.
constexpr std::string_view kMountSource = "proc_self_mountinfo";
/// Fixed identity of the namespace output.
constexpr std::string_view kNamespaceSignal = "root.mount_namespace_v1";
/// Fixed identity of the namespace source.
constexpr std::string_view kNamespaceSource = "proc_self_ns_mnt";

/// Decodes kernel mount escaping, rejecting malformed escapes and raw control bytes.
[[nodiscard]] std::optional<std::string> unescape(std::string_view field) {
  if (field.empty()) {
    return std::nullopt;
  }
  std::string result;
  for (std::size_t index = 0; index < field.size(); ++index) {
    const auto character = static_cast<unsigned char>(field[index]);
    if (character < 33 || character == 127) {
      return std::nullopt;
    }
    if (character != '\\') {
      result += static_cast<char>(character);
      continue;
    }
    if (field.size() - index < 4) {
      return std::nullopt;
    }
    const auto escape = field.substr(index, 4);
    if (escape == "\\040") {
      result += ' ';
    } else if (escape == "\\011") {
      result += '\t';
    } else if (escape == "\\012") {
      result += '\n';
    } else if (escape == "\\134") {
      result += '\\';
    } else {
      return std::nullopt;
    }
    index += 3;
  }
  return result;
}
/// Requires an entire decimal field, with nonzero mount and propagation identifiers.
[[nodiscard]] bool number(std::string_view field, bool nonzero = false) {
  const auto value = util::proc_number(field, 10);
  return value.has_value() && (!nonzero || *value != 0);
}
/// Accepts a nonempty comma list with exactly one read-only/read-write flag.
[[nodiscard]] std::optional<bool> writable(std::string_view options) {
  bool seen = false;
  bool result = false;
  for (const auto piece : std::views::split(options, ',')) {
    const std::string_view option(piece.begin(), piece.end());
    if (option.empty()) {
      return std::nullopt;
    }
    if (option == "rw" || option == "ro") {
      if (seen) {
        return std::nullopt;
      }
      seen = true;
      result = option == "rw";
    }
  }
  return seen ? std::optional(result) : std::nullopt;
}
/// Aggregate counts deliberately omit paths, sources, options and other users' identities.
struct MountCounts {
  std::size_t mounts = 0;
  std::size_t overlay = 0;
  std::size_t shared = 0;
  std::size_t master = 0;
  bool root_seen = false;
  bool root_rw = false;
};
/// Per-record propagation flags are validated before summary counts change.
struct Propagation {
  bool shared = false;
  bool master = false;
};
/// Parses known propagation tags and ignores bounded forward-compatible optional tags.
[[nodiscard]] std::optional<Propagation> propagation(std::span<const std::string_view> tags) {
  Propagation result;
  bool propagated = false;
  bool unbindable = false;
  for (const auto tag : tags) {
    if (tag.starts_with("shared:")) {
      if (result.shared || !number(tag.substr(7), true)) {
        return std::nullopt;
      }
      result.shared = true;
    } else if (tag.starts_with("master:")) {
      if (result.master || !number(tag.substr(7), true)) {
        return std::nullopt;
      }
      result.master = true;
    } else if (tag.starts_with("propagate_from:")) {
      if (propagated || !number(tag.substr(15), true)) {
        return std::nullopt;
      }
      propagated = true;
    } else if (tag == "unbindable") {
      if (unbindable) {
        return std::nullopt;
      }
      unbindable = true;
    } else if (!unescape(tag).has_value()) {
      return std::nullopt;
    }
  }
  return propagated && !result.master ? std::nullopt : std::optional(result);
}
/// Accepts ordinary absolute roots and the kernel nsfs synthetic dentry names.
[[nodiscard]] bool valid_root(std::string_view root, std::string_view type) {
  if (root.starts_with('/')) {
    return true;
  }
  const auto bracket = root.find(":[");
  const std::string_view kind = root.substr(0, bracket);
  constexpr std::array kNamespaceKinds{
      "mnt", "net", "pid", "pid_for_children", "user", "uts", "ipc", "cgroup", "time", "time_for_children",
  };
  return type == "nsfs" && bracket != std::string_view::npos && root.ends_with(']') &&
         std::ranges::contains(kNamespaceKinds, kind) &&
         number(root.substr(bracket + 2, root.size() - bracket - 3), true);
}
/// Splits bounded fields without accepting incomplete records or unbounded optional fields.
[[nodiscard]] std::optional<std::vector<std::string_view>> mount_fields(std::string_view line) {
  if (line.empty() || line.size() > 8192) {
    return std::nullopt;
  }
  std::vector<std::string_view> fields;
  while (!line.empty()) {
    if (fields.size() >= 128) {
      return std::nullopt;
    }
    fields.push_back(util::take_proc_field(line));
  }
  return fields.size() < 10 ? std::nullopt : std::optional(std::move(fields));
}
/// Requires the mandatory numeric mount identity and major:minor device fields.
[[nodiscard]] bool valid_mount_numbers(std::span<const std::string_view> fields) {
  const std::size_t colon = fields[2].find(':');
  return number(fields[0], true) && number(fields[1], true) && colon != std::string_view::npos &&
         number(fields[2].substr(0, colon)) && number(fields[2].substr(colon + 1));
}
/// Validates and incorporates one complete kernel record with no partial-summary return.
[[nodiscard]] bool add_mount(std::string_view line, MountCounts& counts) {
  const auto parsed = mount_fields(line);
  if (!parsed.has_value() || !valid_mount_numbers(*parsed)) {
    return false;
  }
  const auto& fields = *parsed;
  const auto separator = std::ranges::find(fields | std::views::drop(6), "-");
  if (separator == fields.end() || fields.end() - separator != 4) {
    return false;
  }
  const auto offset = static_cast<std::size_t>(separator - fields.begin());
  const auto flags = propagation(std::span(fields).subspan(6, offset - 6));
  const auto root = unescape(fields[3]);
  const auto point = unescape(fields[4]);
  const auto options = unescape(fields[5]);
  const auto type = unescape(fields[offset + 1]);
  const auto source = unescape(fields[offset + 2]);
  const auto super = unescape(fields[offset + 3]);
  if (!flags.has_value() || !root.has_value() || !point.has_value() || !options.has_value() || !type.has_value() ||
      !source.has_value() || !super.has_value()) {
    return false;
  }
  const auto rw = writable(*options);
  if (!point->starts_with('/') || !valid_root(*root, *type) || !rw.has_value() || !writable(*super).has_value()) {
    return false;
  }
  ++counts.mounts;
  counts.overlay += *type == "overlay" ? 1U : 0U;
  counts.shared += flags->shared ? 1U : 0U;
  counts.master += flags->master ? 1U : 0U;
  if (*point == "/") {
    counts.root_seen = true;
    counts.root_rw = counts.root_rw || *rw;
  }
  return counts.mounts <= 4096;
}
/// Reads EOF with bounded interruptions, a nonblocking descriptor and no final symlink traversal.
[[nodiscard]] std::optional<std::string> read_table(std::string_view path) {
  if (path.empty() || path.contains('\0') || path.size() > 4096) {
    return std::nullopt;
  }
  const std::string name(path);
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg): POSIX open is the bounded descriptor boundary.
  const int descriptor = open(name.c_str(), O_RDONLY | O_CLOEXEC | O_NONBLOCK | O_NOFOLLOW);
  if (descriptor < 0) {
    return std::nullopt;
  }
  struct stat before{};
  struct stat after{};
  bool valid = fstat(descriptor, &before) == 0 && S_ISREG(before.st_mode) && before.st_size >= 0 &&
               std::cmp_less_equal(before.st_size, kMaxBytes);
  std::string content;
  std::array<char, 1024> chunk{};
  std::size_t interrupts = 0;
  while (valid) {
    const ssize_t count = read(descriptor, chunk.data(), std::min(chunk.size(), kMaxBytes - content.size() + 1));
    if (count < 0 && errno == EINTR && interrupts < 8) {
      ++interrupts;
      continue;
    }
    if (count < 0 || std::cmp_greater(count, kMaxBytes - content.size())) {
      valid = false;
      break;
    }
    if (count == 0) {
      break;
    }
    content.append(chunk.data(), static_cast<std::size_t>(count));
  }
  valid = valid && fstat(descriptor, &after) == 0 && before.st_dev == after.st_dev && before.st_ino == after.st_ino &&
          before.st_size == after.st_size && before.st_mtime == after.st_mtime && before.st_ctime == after.st_ctime;
#ifdef __APPLE__
  valid = valid && before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec &&
          before.st_ctimespec.tv_nsec == after.st_ctimespec.tv_nsec;
#else
  valid = valid && before.st_mtim.tv_nsec == after.st_mtim.tv_nsec && before.st_ctim.tv_nsec == after.st_ctim.tv_nsec;
#endif
  const bool closed = close(descriptor) == 0;
  return valid && closed ? std::optional(std::move(content)) : std::nullopt;
}
}  // namespace

Observation observe_mountinfo(std::string_view table) {
  if (table.size() > kMaxBytes || table.empty() || !table.ends_with('\n')) {
    return failed(kMountSignal, kMountSource);
  }
  table.remove_suffix(1);
  MountCounts counts;
  for (const auto piece : std::views::split(table, '\n')) {
    if (!add_mount(std::string_view(piece.begin(), piece.end()), counts)) {
      return failed(kMountSignal, kMountSource);
    }
  }
  if (!counts.root_seen) {
    return failed(kMountSignal, kMountSource);
  }
  return observed(kMountSignal, kMountSource,
                  std::vector<std::string>{
                      "mounts=" + std::to_string(counts.mounts),
                      "overlay=" + std::to_string(counts.overlay),
                      "shared=" + std::to_string(counts.shared),
                      "master=" + std::to_string(counts.master),
                      std::string("root_rw=") + (counts.root_rw ? "true" : "false"),
                  });
}
Observation observe_mountinfo_file(std::string_view path) {
  const auto text = read_table(path);
  return text.has_value() ? observe_mountinfo(*text) : failed(kMountSignal, kMountSource);
}
Observation observe_mount_namespace(std::string_view path) {
  if (path.empty() || path.size() > 4096 || path.contains('\0')) {
    return failed(kNamespaceSignal, kNamespaceSource);
  }
  const std::string name(path);
  std::array<char, 65> target{};
  const ssize_t count = readlink(name.c_str(), target.data(), target.size());
  if (count <= 0 || std::cmp_greater_equal(count, target.size())) {
    return failed(kNamespaceSignal, kNamespaceSource);
  }
  const std::string_view link(target.data(), static_cast<std::size_t>(count));
  if (!link.starts_with("mnt:[") || !link.ends_with(']') || !number(link.substr(5, link.size() - 6), true)) {
    return failed(kNamespaceSignal, kNamespaceSource);
  }
  return observed(kNamespaceSignal, kNamespaceSource, std::string(link));
}
std::vector<Observation> root_context() {
#ifdef __ANDROID__
  return {observe_mountinfo_file("/proc/self/mountinfo"), observe_mount_namespace("/proc/self/ns/mnt")};
#else
  return {unsupported(kMountSignal, kMountSource), unsupported(kNamespaceSignal, kNamespaceSource)};
#endif
}
}  // namespace rasp::android::checks
