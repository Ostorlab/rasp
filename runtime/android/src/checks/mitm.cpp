/// The Android network-interception checks: the tunnel probe over the process's own network interfaces, the
/// user-authority probe, and their unsupported results off Android.

#include "checks/mitm.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <filesystem>
#include <ifaddrs.h>
#include <iterator>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

#include "rasp/observation.h"

namespace rasp::android::checks {

namespace {

#ifdef __ANDROID__
/// Whether this build runs on Android, the only place the probes mean anything.
constexpr bool kOnAndroid = true;
#else
/// Whether this build runs on Android, the only place the probes mean anything.
constexpr bool kOnAndroid = false;
#endif

/// The signal of the tunnel probe.
constexpr std::string_view kTunnelsSignal = "mitm.tunnels";
/// The source of the tunnel probe: the process's own network interfaces, read through getifaddrs.
constexpr std::string_view kTunnelsSource = "getifaddrs";

/// The signal of the user-authority probe.
constexpr std::string_view kUserCasSignal = "mitm.user_cas";
/// The source of the user-authority probe.
constexpr std::string_view kUserCasSource = "user_cacerts";

/// The most interface names or file names one observation reports, so a host with very many interfaces or a crafted
/// trust store can't grow it without bound.
constexpr std::size_t kMaxEntries = 100;

/// The interface-name prefixes of a tunnel, the kind a capturing proxy routes traffic through: `tun` for the layer-3
/// interface a VPN app opens through the kernel's TUN/TAP driver, and `tap` for its layer-2 interface. These are the
/// tunnels an on-device interception proxy opens; physical interfaces (`wlan`, `rmnet`, `eth`) and the loopback never
/// match.
constexpr auto kTunnelPrefixes = std::to_array<std::string_view>({"tun", "tap"});

/// Whether the interface `name` is a tunnel: its name starts with a tunnel prefix.
[[nodiscard]] bool is_tunnel(std::string_view name) {
  return std::ranges::any_of(kTunnelPrefixes, [name](std::string_view prefix) { return name.starts_with(prefix); });
}

/// The tunnel interface names in `names`, the kMaxEntries smallest of them, without duplicates. getifaddrs lists an
/// interface once per address, so a tunnel with several addresses would otherwise appear more than once.
[[nodiscard]] std::vector<std::string> tunnel_names(const std::vector<std::string>& names) {
  std::set<std::string> tunnels;
  for (const std::string& name : names) {
    if (!is_tunnel(name)) {
      continue;
    }
    tunnels.insert(name);
    if (tunnels.size() > kMaxEntries) {
      tunnels.erase(std::prev(tunnels.end()));
    }
  }
  return std::vector<std::string>(tunnels.begin(), tunnels.end());
}

/// The names of this process's network interfaces, read through getifaddrs, or nothing when getifaddrs fails. An
/// interface appears once per address it holds; the caller removes the duplicates. getifaddrs reads the interfaces over
/// a netlink socket, which an untrusted app process can open, unlike `/proc/net/route`, which Android denies it.
[[nodiscard]] std::optional<std::vector<std::string>> interface_names() {
  ifaddrs* list = nullptr;
  if (getifaddrs(&list) != 0) {
    return std::nullopt;
  }
  std::vector<std::string> names;
  for (const ifaddrs* entry = list; entry != nullptr; entry = entry->ifa_next) {
    if (entry->ifa_name != nullptr) {
      names.emplace_back(entry->ifa_name);
    }
  }
  freeifaddrs(list);
  return names;
}

/// The names of the regular files directly in `directory`, the kMaxEntries smallest of them, sorted, or nothing when
/// the directory can't be listed or an entry can't be read. Each user authority is one such file, named after the hash
/// of its subject. The iterator is advanced with `increment`, not a range-for, because its `operator++` throws on
/// failure and the library is built with -fno-exceptions; the kept set is bounded as it is built, so the directory size
/// doesn't bound memory.
[[nodiscard]] std::optional<std::vector<std::string>> regular_file_names(std::string_view directory) {
  std::error_code error;
  std::filesystem::directory_iterator iterator(std::filesystem::path(directory), error);
  if (error) {
    return std::nullopt;
  }
  const std::filesystem::directory_iterator end;
  std::set<std::string> names;
  while (iterator != end) {
    const bool regular = iterator->is_regular_file(error);
    if (error) {
      return std::nullopt;
    }
    if (regular) {
      names.insert(iterator->path().filename().string());
      if (names.size() > kMaxEntries) {
        names.erase(std::prev(names.end()));
      }
    }
    iterator.increment(error);
    if (error) {
      return std::nullopt;
    }
  }
  return std::vector<std::string>(names.begin(), names.end());
}

}  // namespace

Observation observe_tunnels(const std::vector<std::string>& interface_names) {
  return observed(kTunnelsSignal, kTunnelsSource, tunnel_names(interface_names));
}

Observation observe_user_cas(std::string_view cacerts_dir) {
  std::optional<std::vector<std::string>> names = regular_file_names(cacerts_dir);
  if (!names) {
    return failed(kUserCasSignal, kUserCasSource);
  }
  return observed(kUserCasSignal, kUserCasSource, std::move(*names));
}

std::vector<Observation> mitm() {
  if (!kOnAndroid) {
    return {unsupported(kTunnelsSignal, kTunnelsSource), unsupported(kUserCasSignal, kUserCasSource)};
  }
  const std::optional<std::vector<std::string>> names = interface_names();
  const Observation tunnels = names ? observe_tunnels(*names) : failed(kTunnelsSignal, kTunnelsSource);
  // The user trust store (`/data/misc/user/<id>/cacerts-added`) is labeled system_data_file under SELinux and there is
  // no public SDK API that exposes user-installed CAs, so an untrusted app process can't enumerate them: report
  // unsupported rather than a perpetual error.
  return {tunnels, unsupported(kUserCasSignal, kUserCasSource)};
}

}  // namespace rasp::android::checks
