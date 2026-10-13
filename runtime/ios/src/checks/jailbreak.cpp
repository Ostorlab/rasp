/// The iOS jailbreak checks: the filesystem, sandbox-write and fork probes, and their unsupported results off a
/// physical device.

#include "checks/jailbreak.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <fcntl.h>
#include <iterator>
#include <span>
#include <string>
#include <string_view>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <utility>
#include <vector>

#include "rasp/observation.h"

#ifdef __APPLE__
#include <TargetConditionals.h>
#endif

namespace rasp::ios::checks {

namespace {

#if defined(__APPLE__) && TARGET_OS_IOS && !TARGET_OS_SIMULATOR
/// Whether this build runs on a physical iOS device, the only place the probes mean anything.
constexpr bool kPhysicalDevice = true;
#else
/// Whether this build runs on a physical iOS device, the only place the probes mean anything.
constexpr bool kPhysicalDevice = false;
#endif

/// The signal of the filesystem-path probe.
constexpr std::string_view kPathsSignal = "jb.fs_paths";
/// The signal of the sandbox-write probe.
constexpr std::string_view kSandboxSignal = "jb.sandbox_escape";
/// The signal of the fork probe.
constexpr std::string_view kForkSignal = "jb.fork_ok";
/// The path the sandbox-write probe tries to create, outside the app's sandbox.
constexpr std::string_view kSandboxProbe = "/private/.rasp_sandbox_probe";

/// The filesystem paths a jailbreak commonly leaves behind.
constexpr std::array<std::string_view, 21> kArtifactPaths = {
    "/Applications/Cydia.app",
    "/Applications/Sileo.app",
    "/Applications/Zebra.app",
    "/Library/MobileSubstrate/MobileSubstrate.dylib",
    "/usr/lib/libhooker.dylib",
    "/usr/lib/libsubstitute.dylib",
    "/usr/lib/substrate",
    "/usr/lib/TweakInject",
    "/usr/sbin/sshd",
    "/usr/bin/ssh",
    "/bin/bash",
    "/bin/sh",
    "/etc/apt",
    "/private/var/lib/apt",
    "/private/var/lib/cydia",
    "/private/var/stash",
    "/var/jb",
    "/var/jb/usr/bin/sshd",
    "/var/jb/Library/MobileSubstrate/MobileSubstrate.dylib",
    "/var/checkra1n.dmg",
    "/jb",
};

/// Whether access finds a file at `path`.
[[nodiscard]] bool found_by_access(const std::string& path) { return access(path.c_str(), F_OK) == 0; }

/// Whether stat finds a file at `path`.
[[nodiscard]] bool found_by_stat(const std::string& path) {
  struct stat info{};
  return stat(path.c_str(), &info) == 0;
}

/// One way of asking whether a file exists at a path.
struct PathSource {
  /// The observation's source, such as access or stat.
  std::string_view name;
  /// Whether this source finds a file at the path.
  bool (*exists)(const std::string& path);
};

/// The sources jb.fs_paths reads each path through, in the order their observations are reported.
constexpr std::array kPathSources = {
    PathSource{.name = "access", .exists = found_by_access},
    PathSource{.name = "stat", .exists = found_by_stat},
};

}  // namespace

std::vector<Observation> observe_paths(std::span<const std::string_view> paths) {
  const std::vector<std::string> candidates(paths.begin(), paths.end());
  std::vector<Observation> observations;
  observations.reserve(kPathSources.size());
  for (const PathSource& source : kPathSources) {
    std::vector<std::string> found;
    std::ranges::copy_if(candidates, std::back_inserter(found), source.exists);
    observations.push_back(observed(kPathsSignal, source.name, std::move(found)));
  }
  return observations;
}

Observation observe_sandbox_write(std::string_view probe_path) {
  const std::string path(probe_path);
  const int descriptor = creat(path.c_str(), S_IRUSR | S_IWUSR);
  if (descriptor >= 0) {
    close(descriptor);
    unlink(path.c_str());
    return observed(kSandboxSignal, "open", true);
  }
  switch (errno) {
    case EPERM:
    case EACCES:
    case EROFS:
    case ENOENT:
      return observed(kSandboxSignal, "open", false);
    default:
      return failed(kSandboxSignal, "open");
  }
}

Observation observe_fork() {
  const pid_t child = fork();
  if (child == 0) {
    _exit(0);
  }
  if (child < 0) {
    return observed(kForkSignal, "fork", false);
  }
  int status = 0;
  while (waitpid(child, &status, 0) < 0 && errno == EINTR) {
  }
  return observed(kForkSignal, "fork", true);
}

std::vector<Observation> jailbreak() {
  if (!kPhysicalDevice) {
    // Off a device there is no app sandbox, so every probe would look jailbroken: report them as unsupported.
    std::vector<Observation> observations;
    observations.reserve(kPathSources.size() + 2);
    for (const PathSource& source : kPathSources) {
      observations.push_back(unsupported(kPathsSignal, source.name));
    }
    observations.push_back(unsupported(kSandboxSignal, "open"));
    observations.push_back(unsupported(kForkSignal, "fork"));
    return observations;
  }
  std::vector<Observation> observations = observe_paths(kArtifactPaths);
  observations.push_back(observe_sandbox_write(kSandboxProbe));
  observations.push_back(observe_fork());
  return observations;
}

}  // namespace rasp::ios::checks
