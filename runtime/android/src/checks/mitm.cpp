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

/// The most tunnel interface names the tunnels observation reports, so a host with very many interfaces or addresses
/// can't grow it without bound. The user-authority probe is not capped: the user decides which certificates to trust,
/// so every one is reported.
constexpr std::size_t kMaxEntries = 100;

/// The interface-name prefixes of a tunnel, the kind a capturing proxy routes traffic through: `tun` for the layer-3
/// interface a VPN app opens through the kernel's TUN/TAP driver, and `tap` for its layer-2 interface. These are the
/// tunnels an on-device interception proxy opens; physical interfaces (`wlan`, `rmnet`, `eth`) and the loopback never
/// match.
constexpr auto kTunnelPrefixes = std::to_array<std::string_view>({"tun", "tap"});

/// Whether the interface `name` is a TUN/TAP device: a tunnel prefix followed by a run of digits and nothing else, as
/// the kernel names them (`tun0`, `tap3`). Requiring the digits keeps a differently-named interface that merely starts
/// with the prefix, such as the IPIP tunnel `tunl0`, from matching.
[[nodiscard]] bool is_tunnel(std::string_view name) {
  const auto matches_prefix = [name](std::string_view prefix) {
    if (!name.starts_with(prefix)) {
      return false;
    }
    const std::string_view rest = name.substr(prefix.size());
    return !rest.empty() &&
           std::ranges::all_of(rest, [](char character) { return character >= '0' && character <= '9'; });
  };
  return std::ranges::any_of(kTunnelPrefixes, matches_prefix);
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
  return {tunnels.begin(), tunnels.end()};
}

/// The tunnel interface names among this process's network interfaces, read through getifaddrs, the kMaxEntries
/// smallest of them without duplicates, or nothing when getifaddrs fails. The names are filtered and bounded while the
/// list is walked, so a device with very many interfaces or addresses doesn't grow an intermediate buffer without
/// bound. getifaddrs reads the interfaces over a netlink socket, which an untrusted app process can open, unlike
/// `/proc/net/route`, which Android denies it.
[[nodiscard]] std::optional<std::vector<std::string>> tunnel_interface_names() {
  ifaddrs* list = nullptr;
  if (getifaddrs(&list) != 0) {
    return std::nullopt;
  }
  std::set<std::string> tunnels;
  for (const ifaddrs* entry = list; entry != nullptr; entry = entry->ifa_next) {
    if (entry->ifa_name == nullptr || !is_tunnel(entry->ifa_name)) {
      continue;
    }
    tunnels.insert(entry->ifa_name);
    if (tunnels.size() > kMaxEntries) {
      tunnels.erase(std::prev(tunnels.end()));
    }
  }
  freeifaddrs(list);
  return std::vector<std::string>{tunnels.begin(), tunnels.end()};
}

/// The names of all the regular files directly in `directory`, sorted and without duplicates, or nothing when the
/// directory can't be listed or an entry can't be read. Each user authority is one such file, named after the hash of
/// its subject, and the user decides which to trust, so the probe reports every one rather than a bounded subset. The
/// iterator is advanced with `increment`, not a range-for, because its `operator++` throws on failure and the library
/// is built with -fno-exceptions.
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
    }
    iterator.increment(error);
    if (error) {
      return std::nullopt;
    }
  }
  return std::vector<std::string>{names.begin(), names.end()};
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
  const std::optional<std::vector<std::string>> names = tunnel_interface_names();
  Observation tunnels = names ? observe_tunnels(*names) : failed(kTunnelsSignal, kTunnelsSource);
  // The user trust store (`/data/misc/user/<id>/cacerts-added`) is labeled system_data_file under SELinux and there is
  // no public SDK API that exposes user-installed CAs, so an untrusted app process can't enumerate them: report
  // unsupported rather than a perpetual error.
  std::vector<Observation> observations;
  observations.reserve(2);
  observations.push_back(std::move(tunnels));
  observations.push_back(unsupported(kUserCasSignal, kUserCasSource));
  return observations;
}

}  // namespace rasp::android::checks
