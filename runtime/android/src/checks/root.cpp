/// The Android root checks: independent access/stat/libc syscall path and mount-table reads, the SELinux and
/// build-property probes, and their unsupported results off Android. The lists of su folders and writable system
/// folders draw on RootBeer (Apache 2.0).

#include "checks/root.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstddef>
#include <iterator>
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
#include "rasp/util/read_file.h"
#include "util/direct_syscall.h"
#include "util/proc_text.h"
#include "util/system_property.h"

namespace rasp::android::checks {

namespace {

using rasp::util::read_file;

/// The signal of the root-file probe.
constexpr std::string_view kPathsSignal = "root.fs_paths";
/// The signal of the mount-table probe that reports the mounts a root tool made.
constexpr std::string_view kMountsSignal = "root.mounts";
/// The signal of the mount-table probe that reports the system folders mounted writable.
constexpr std::string_view kRwMountsSignal = "root.rw_mounts";
/// The source of the mount-table probe that reads the table through the libc file functions.
constexpr std::string_view kMountsSource = "proc_mounts";
/// The source of the mount-table probe that reads the table through libc's hookable syscall entry.
constexpr std::string_view kMountsDirectSource = "proc_mounts_syscall";
/// The signal of the SELinux probe.
constexpr std::string_view kSelinuxSignal = "root.selinux_enforcing";
/// The source of the SELinux probe.
constexpr std::string_view kSelinuxSource = "selinuxfs";
/// The signal of the build-property probe.
constexpr std::string_view kPropsSignal = "root.build_props";
/// The source of the build-property probe.
constexpr std::string_view kPropsSource = "system_property";

/// The app's mount table.
constexpr std::string_view kMountsPath = "/proc/self/mounts";
/// The file that tells whether SELinux enforces its policy.
constexpr std::string_view kEnforcePath = "/sys/fs/selinux/enforce";

/// The largest mount table read. A real one is a few tens of KiB.
constexpr std::size_t kMaxMountsSize = std::size_t{1} << 20U;
/// The most mount lines reported in each list.
constexpr std::size_t kMaxMountLines = 32;
/// The largest SELinux enforce file read. A real one holds one digit.
constexpr std::size_t kMaxEnforceSize = 16;

/// The filesystem paths that rooting commonly leaves behind: `su` in each system directory of an app's `PATH` and in
/// the older install locations, the SuperSU files, and the binaries and folders of Magisk, KernelSU and APatch.
constexpr auto kArtifactPaths = std::to_array<std::string_view>({
    "/system/bin/su",
    "/system/xbin/su",
    "/system/sbin/su",
    "/system/bin/failsafe/su",
    "/system/bin/.ext/su",
    "/system/usr/we-need-root/su",
    "/system/sd/xbin/su",
    "/system_ext/bin/su",
    "/product/bin/su",
    "/vendor/bin/su",
    "/vendor/xbin/su",
    "/odm/bin/su",
    "/sbin/su",
    "/su/bin/su",
    "/data/local/su",
    "/data/local/bin/su",
    "/data/local/xbin/su",
    "/cache/su",
    "/data/su",
    "/dev/su",
    "/system/app/Superuser.apk",
    "/system/app/SuperSU.apk",
    "/system/xbin/daemonsu",
    "/system/xbin/supolicy",
    "/system/etc/init.d/99SuperSUDaemon",
    "/system/bin/magisk",
    "/system/xbin/magisk",
    "/sbin/magisk",
    "/debug_ramdisk/magisk",
    "/sbin/.magisk",
    "/debug_ramdisk/.magisk",
    "/cache/.disable_magisk",
    "/data/adb/magisk",
    "/data/adb/magisk.db",
    "/data/adb/modules",
    "/data/adb/ksu",
    "/data/adb/ksud",
    "/data/adb/ap",
    "/data/adb/apd",
});

/// The text that marks a mount made by Magisk, anywhere in its line: Magisk names its mounts and folders after itself,
/// and modules of every root tool live under `/data/adb`.
constexpr auto kMountMarkers = std::to_array<std::string_view>({
    "magisk",
    "zygisk",
    "core/mirror",
    "/debug_ramdisk",
    "/data/adb",
});

/// The sources KernelSU and APatch give their mounts. They are matched as the whole source only, since text such as
/// `KSU` can appear by chance in the random names other mounts carry.
constexpr auto kRootToolSources = std::to_array<std::string_view>({
    "KSU",
    "APatch",
});

/// The system folders that a stock device mounts read-only.
constexpr auto kSystemMountPoints = std::to_array<std::string_view>({
    "/",
    "/system",
    "/system/bin",
    "/system/sbin",
    "/system/xbin",
    "/vendor",
    "/vendor/bin",
    "/sbin",
    "/etc",
});

/// The build properties root.build_props reports, in the order it reports them.
constexpr auto kBuildProperties = std::to_array<std::string_view>({
    "ro.debuggable",
    "ro.secure",
    "ro.build.type",
    "ro.build.tags",
    "ro.boot.verifiedbootstate",
    "ro.boot.vbmeta.device_state",
    "ro.boot.flash.locked",
});

#ifdef __ANDROID__
/// Whether this build runs on Android, the only place the probes mean anything.
constexpr bool kOnAndroid = true;
#else
/// Whether this build runs on Android, the only place the probes mean anything.
constexpr bool kOnAndroid = false;
#endif

/// Whether access finds a file at `path`.
[[nodiscard]] std::optional<bool> found_by_access(const std::string& path, [[maybe_unused]] util::SystemCall invoke) {
  if (path.empty() || path.contains('\0')) {
    return std::nullopt;
  }
  if (access(path.c_str(), F_OK) == 0) {
    return true;
  }
  if (errno == ENOENT || errno == ENOTDIR) {
    return false;
  }
  return std::nullopt;
}

/// Whether stat finds a file at `path`.
[[nodiscard]] std::optional<bool> found_by_stat(const std::string& path, [[maybe_unused]] util::SystemCall invoke) {
  if (path.empty() || path.contains('\0')) {
    return std::nullopt;
  }
  struct stat info{};
  if (stat(path.c_str(), &info) == 0) {
    return true;
  }
  if (errno == ENOENT || errno == ENOTDIR) {
    return false;
  }
  return std::nullopt;
}

/// Whether libc's hookable faccessat syscall entry finds a file at `path`, or cannot determine existence.
[[nodiscard]] std::optional<bool> found_by_faccessat(const std::string& path, util::SystemCall invoke) {
  return util::exists_direct(path, invoke);
}

/// One way of asking whether a file exists at a path.
struct PathSource {
  /// The observation's source, such as access or stat.
  std::string_view name;
  /// Whether this source finds a file at the path.
  std::optional<bool> (*exists)(const std::string& path, util::SystemCall invoke);
};

/// The sources root.fs_paths reads each path through, in the order their observations are reported.
constexpr std::array kPathSources = {
    PathSource{.name = "access", .exists = found_by_access},
    PathSource{.name = "stat", .exists = found_by_stat},
    PathSource{.name = "faccessat_syscall", .exists = found_by_faccessat},
};

/// The fields of a mount table line that the probes read.
struct MountLine {
  /// What is mounted, such as a block device, or the name a root tool gives its mount.
  std::string_view source;
  /// The folder it is mounted on.
  std::string_view point;
  /// The mount options, separated by commas.
  std::string_view options;
};

/// Whether a mount record holds all six kernel fields, with numeric dump and fsck values.
[[nodiscard]] bool valid_mount_line(std::string_view line) {
  std::string_view rest = line;
  for (int field = 0; field < 4; ++field) {
    if (util::take_proc_field(rest).empty()) {
      return false;
    }
  }
  const auto dump = util::proc_number(util::take_proc_field(rest), 10);
  const auto pass = util::proc_number(util::take_proc_field(rest), 10);
  return dump.has_value() && pass.has_value() && rest.empty();
}

/// The source, mount point and options of `line`. A field the line doesn't have is empty.
[[nodiscard]] MountLine parse_mount_line(std::string_view line) {
  std::string_view rest = line;
  const std::string_view source = util::take_proc_field(rest);
  const std::string_view point = util::take_proc_field(rest);
  static_cast<void>(util::take_proc_field(rest));
  const std::string_view options = util::take_proc_field(rest);
  return MountLine{.source = source, .point = point, .options = options};
}

/// Whether `options`, separated by commas, include `option` exactly.
[[nodiscard]] bool has_option(std::string_view options, std::string_view option) {
  return std::ranges::any_of(std::views::split(options, ','), [option](const auto piece) {
    return std::string_view(piece.begin(), piece.end()) == option;
  });
}

/// Whether `line` is a mount a root tool made.
[[nodiscard]] bool made_by_root_tool(std::string_view line) {
  return std::ranges::contains(kRootToolSources, parse_mount_line(line).source) ||
         std::ranges::any_of(kMountMarkers, [line](std::string_view marker) { return line.contains(marker); });
}

/// Whether `line` mounts a system folder writable.
[[nodiscard]] bool system_folder_writable(std::string_view line) {
  const MountLine mount = parse_mount_line(line);
  return std::ranges::contains(kSystemMountPoints, mount.point) && has_option(mount.options, "rw");
}

/// The first kMaxMountLines lines of `table` that `matches`, without their line breaks.
[[nodiscard]] std::vector<std::string> matching_lines(std::string_view table, bool (*matches)(std::string_view line)) {
  std::vector<std::string> lines;
  for (const auto piece : std::views::split(table, '\n')) {
    const std::string_view line(piece.begin(), piece.end());
    if (!matches(line)) {
      continue;
    }
    lines.emplace_back(line);
    if (lines.size() == kMaxMountLines) {
      break;
    }
  }
  return lines;
}

/// The root.mounts and root.rw_mounts observations through `source` of `table`, the mount table as that source read
/// it, or nothing when it couldn't read it.
[[nodiscard]] std::vector<Observation> mounts_from(const std::optional<std::string>& table, std::string_view source) {
  if (!table.has_value() || !util::valid_proc_table(*table, valid_mount_line)) {
    return {failed(kMountsSignal, source), failed(kRwMountsSignal, source)};
  }
  return {
      observed(kMountsSignal, source, matching_lines(*table, made_by_root_tool)),
      observed(kRwMountsSignal, source, matching_lines(*table, system_folder_writable)),
  };
}

}  // namespace

std::vector<Observation> observe_paths(std::span<const std::string_view> paths, util::SystemCall invoke) {
  const std::vector<std::string> candidates(paths.begin(), paths.end());
  std::vector<Observation> observations;
  observations.reserve(kPathSources.size());
  for (const PathSource& source : kPathSources) {
    std::vector<std::string> found;
    bool complete = true;
    for (const std::string& path : candidates) {
      const std::optional<bool> exists = source.exists(path, invoke);
      if (!exists.has_value()) {
        complete = false;
        break;
      }
      if (*exists) {
        found.push_back(path);
      }
    }
    observations.push_back(complete ? observed(kPathsSignal, source.name, std::move(found))
                                    : failed(kPathsSignal, source.name));
  }
  return observations;
}

std::vector<Observation> observe_mounts(std::string_view mounts_path, util::SystemCall invoke) {
  std::vector<Observation> observations = mounts_from(read_file(mounts_path, kMaxMountsSize), kMountsSource);
  std::ranges::move(mounts_from(util::read_file_direct(mounts_path, kMaxMountsSize, invoke), kMountsDirectSource),
                    std::back_inserter(observations));
  return observations;
}

Observation observe_selinux(std::string_view enforce_path) {
  const std::optional<std::string> content = read_file(enforce_path, kMaxEnforceSize);
  if (content == "1" || content == "1\n") {
    return observed(kSelinuxSignal, kSelinuxSource, true);
  }
  if (content == "0" || content == "0\n") {
    return observed(kSelinuxSignal, kSelinuxSource, false);
  }
  return failed(kSelinuxSignal, kSelinuxSource);
}

Observation observe_build_props(util::PropertyReader read_property) {
  std::vector<std::string> properties;
  for (const std::string_view name : kBuildProperties) {
    const std::optional<std::string> value = read_property(name);
    if (value) {
      properties.push_back(std::string(name) + "=" + *value);
    }
  }
  return observed(kPropsSignal, kPropsSource, std::move(properties));
}

std::vector<Observation> root() {
  if (!kOnAndroid) {
    // Off Android the files, mounts and properties are not Android ones: report every probe as unsupported.
    std::vector<Observation> observations;
    observations.reserve(kPathSources.size() + 6);
    for (const PathSource& source : kPathSources) {
      observations.push_back(unsupported(kPathsSignal, source.name));
    }
    observations.push_back(unsupported(kMountsSignal, kMountsSource));
    observations.push_back(unsupported(kRwMountsSignal, kMountsSource));
    observations.push_back(unsupported(kMountsSignal, kMountsDirectSource));
    observations.push_back(unsupported(kRwMountsSignal, kMountsDirectSource));
    observations.push_back(unsupported(kSelinuxSignal, kSelinuxSource));
    observations.push_back(unsupported(kPropsSignal, kPropsSource));
    return observations;
  }
  std::vector<Observation> observations = observe_paths(kArtifactPaths);
  std::ranges::move(observe_mounts(kMountsPath), std::back_inserter(observations));
  observations.push_back(observe_selinux(kEnforcePath));
  observations.push_back(observe_build_props(util::read_system_property));
  return observations;
}

}  // namespace rasp::android::checks
