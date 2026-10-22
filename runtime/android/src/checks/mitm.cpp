/// The Android network-interception checks: the tunnel probe, the user-authority probe, and their unsupported results
/// off Android.

#include "checks/mitm.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <filesystem>
#include <iterator>
#include <optional>
#include <ranges>
#include <set>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#include "rasp/observation.h"
#include "util/read_file.h"

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
/// The source of the tunnel probe.
constexpr std::string_view kTunnelsSource = "proc_net_route";

/// The signal of the user-authority probe.
constexpr std::string_view kUserCasSignal = "mitm.user_cas";
/// The source of the user-authority probe.
constexpr std::string_view kUserCasSource = "user_cacerts";

/// The route table, which names the interface of every route.
constexpr std::string_view kRoutePath = "/proc/net/route";
/// The largest route table read. A real one is a few KiB.
constexpr std::size_t kMaxRouteSize = std::size_t{256} << 10U;

/// The user trust store, where a certificate the user installs lands, apart from the system authorities.
constexpr std::string_view kUserCacertsDir = "/data/misc/user/0/cacerts-added";

/// The most lines or file names one observation reports, so a crafted route table or trust store can't grow it without
/// bound.
constexpr std::size_t kMaxEntries = 32;

/// The interface-name prefixes of a tunnel, the kind a capturing proxy routes traffic through: `tun` for a VPN app's
/// interface, `tap` for an ethernet-level tunnel, and `ppp` for a point-to-point tunnel.
constexpr auto kTunnelPrefixes = std::to_array<std::string_view>({"tun", "tap", "ppp"});

/// Whether the route `line` names a tunnel interface in its first field. A route table line is tab-separated and starts
/// with the interface name, so the name is the run of characters before the first tab.
[[nodiscard]] bool routes_through_tunnel(std::string_view line) {
  const std::size_t tab = line.find('\t');
  const std::string_view interface = line.substr(0, std::min(tab, line.size()));
  return std::ranges::any_of(kTunnelPrefixes,
                             [interface](std::string_view prefix) { return interface.starts_with(prefix); });
}

/// The route lines of `routes` that name a tunnel interface, at most kMaxEntries. The header line names no interface,
/// so it never matches.
[[nodiscard]] std::vector<std::string> tunnel_routes(std::string_view routes) {
  std::vector<std::string> lines;
  for (const auto piece : std::views::split(routes, '\n')) {
    const std::string_view line(piece.begin(), piece.end());
    if (line.empty() || !routes_through_tunnel(line)) {
      continue;
    }
    lines.emplace_back(line);
    if (lines.size() == kMaxEntries) {
      break;
    }
  }
  return lines;
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

Observation observe_tunnels(std::string_view route_path) {
  const std::optional<std::string> routes = util::read_file(route_path, kMaxRouteSize);
  if (!routes) {
    return failed(kTunnelsSignal, kTunnelsSource);
  }
  return observed(kTunnelsSignal, kTunnelsSource, tunnel_routes(*routes));
}

Observation observe_user_cas(std::string_view cacerts_dir) {
  const std::optional<std::vector<std::string>> names = regular_file_names(cacerts_dir);
  if (!names) {
    return failed(kUserCasSignal, kUserCasSource);
  }
  return observed(kUserCasSignal, kUserCasSource, *names);
}

std::vector<Observation> mitm() {
  if (!kOnAndroid) {
    return {unsupported(kTunnelsSignal, kTunnelsSource), unsupported(kUserCasSignal, kUserCasSource)};
  }
  return {observe_tunnels(kRoutePath), observe_user_cas(kUserCacertsDir)};
}

}  // namespace rasp::android::checks
