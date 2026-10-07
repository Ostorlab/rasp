#include "rasp/checks/ios/jailbreak.h"

#include <array>
#include <cerrno>
#include <fcntl.h>
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

namespace rasp::checks::ios {

namespace {

#if defined(__APPLE__) && TARGET_OS_IOS && !TARGET_OS_SIMULATOR
constexpr bool kPhysicalDevice = true;
#else
constexpr bool kPhysicalDevice = false;
#endif

constexpr std::string_view kPathsSignal = "jb.fs_paths";
constexpr std::string_view kSandboxSignal = "jb.sandbox_escape";
constexpr std::string_view kForkSignal = "jb.fork_ok";
constexpr std::string_view kSandboxProbe = "/private/.rasp_sandbox_probe";

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

[[nodiscard]] Observation unsupported(std::string_view signal, std::string_view source) {
  return Observation{
      .signal = std::string(signal),
      .source = std::string(source),
      .status = Status::kUnsupported,
      .value = {},
  };
}

[[nodiscard]] bool found_by_access(const std::string& path) { return access(path.c_str(), F_OK) == 0; }

[[nodiscard]] bool found_by_stat(const std::string& path) {
  struct stat info{};
  return stat(path.c_str(), &info) == 0;
}

}  // namespace

std::vector<Observation> observe_paths(std::span<const std::string_view> paths) {
  std::vector<std::string> by_access;
  std::vector<std::string> by_stat;
  for (const std::string_view candidate : paths) {
    const std::string path(candidate);
    if (found_by_access(path)) {
      by_access.push_back(path);
    }
    if (found_by_stat(path)) {
      by_stat.push_back(path);
    }
  }
  return {
      Observation{
          .signal = std::string(kPathsSignal),
          .source = "access",
          .status = Status::kOk,
          .value = std::move(by_access),
      },
      Observation{
          .signal = std::string(kPathsSignal),
          .source = "stat",
          .status = Status::kOk,
          .value = std::move(by_stat),
      },
  };
}

Observation observe_sandbox_write(std::string_view probe_path) {
  const std::string path(probe_path);
  const int descriptor = creat(path.c_str(), S_IRUSR | S_IWUSR);
  if (descriptor >= 0) {
    close(descriptor);
    unlink(path.c_str());
    return Observation{.signal = std::string(kSandboxSignal), .source = "open", .status = Status::kOk, .value = true};
  }
  switch (errno) {
    case EPERM:
    case EACCES:
    case EROFS:
    case ENOENT:
      return Observation{
          .signal = std::string(kSandboxSignal),
          .source = "open",
          .status = Status::kOk,
          .value = false,
      };
    default:
      return Observation{
          .signal = std::string(kSandboxSignal),
          .source = "open",
          .status = Status::kError,
          .value = {},
      };
  }
}

Observation observe_fork() {
  const pid_t child = fork();
  if (child == 0) {
    _exit(0);
  }
  if (child < 0) {
    return Observation{.signal = std::string(kForkSignal), .source = "fork", .status = Status::kOk, .value = false};
  }
  int status = 0;
  while (waitpid(child, &status, 0) < 0 && errno == EINTR) {
  }
  return Observation{.signal = std::string(kForkSignal), .source = "fork", .status = Status::kOk, .value = true};
}

std::vector<Observation> jailbreak() {
  if (!kPhysicalDevice) {
    return {
        unsupported(kPathsSignal, "access"),
        unsupported(kPathsSignal, "stat"),
        unsupported(kSandboxSignal, "open"),
        unsupported(kForkSignal, "fork"),
    };
  }
  std::vector<Observation> observations = observe_paths(kArtifactPaths);
  observations.push_back(observe_sandbox_write(kSandboxProbe));
  observations.push_back(observe_fork());
  return observations;
}

}  // namespace rasp::checks::ios
