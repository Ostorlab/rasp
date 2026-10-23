/// The iOS network-interception checks: the tunnel probe over the process's own network interfaces, and its
/// unsupported result off a physical device.

#include "checks/mitm.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <ifaddrs.h>
#include <iterator>
#include <set>
#include <span>
#include <string>
#include <string_view>
#include <sys/socket.h>
#include <vector>

#include "rasp/observation.h"

#ifdef __APPLE__
#include <TargetConditionals.h>
#include <net/if.h>
#endif

namespace rasp::ios::checks {

namespace {

#if defined(__APPLE__) && TARGET_OS_IOS && !TARGET_OS_SIMULATOR
/// Whether this build runs on a physical iOS device, the only place the probe means anything.
constexpr bool kPhysicalDevice = true;
#else
/// Whether this build runs on a physical iOS device, the only place the probe means anything.
constexpr bool kPhysicalDevice = false;
#endif

/// The signal of the tunnel probe.
constexpr std::string_view kTunnelsSignal = "mitm.tunnels";
/// The source of the tunnel probe: the process's own network interfaces, read through getifaddrs.
constexpr std::string_view kTunnelsSource = "getifaddrs";

/// The most tunnel interface names the tunnels observation reports, so a device with very many interfaces or addresses
/// can't grow it without bound.
constexpr std::size_t kMaxTunnels = 100;

/// The interface-name prefixes of a tunnel: `utun` for a Network Extension packet tunnel, `ipsec` for a built-in IKEv2
/// or IPsec VPN, `ppp` for a PPP VPN, and `tun` and `tap` for the layer-3 and layer-2 interfaces of a TUN/TAP driver.
/// Physical interfaces (`en`, `pdp_ip`, `awdl`, `llw`) and the loopback never match.
constexpr auto kTunnelPrefixes = std::to_array<std::string_view>({"utun", "ipsec", "ppp", "tun", "tap"});

static_assert(kFamilyIPv4 == static_cast<std::uint32_t>(AF_INET));
#ifdef __APPLE__
static_assert(kInterfaceUp == static_cast<std::uint32_t>(IFF_UP));
#endif

/// Whether `name` is the name of a tunnel interface: one of kTunnelPrefixes followed by a run of digits and nothing
/// else, as the kernel names them (`utun3`, `ipsec0`). Requiring the digits keeps a differently-named interface that
/// merely starts with a prefix, such as the IPIP tunnel `tunl0`, from matching.
///
/// @param name The interface's name.
/// @return Whether the name is a tunnel's.
[[nodiscard]] bool is_tunnel_name(std::string_view name) {
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

/// Whether an entry of getifaddrs is one the tunnels observation reports: a tunnel interface that is up, with an IPv4
/// address.
///
/// @param name The interface's name.
/// @param flags The interface's flags, as `IFF_*` bits.
/// @param family The address family of the entry's address, or 0 when it has none.
/// @return Whether the entry names a tunnel that is up and carries an IPv4 address.
[[nodiscard]] bool is_reported(std::string_view name, std::uint32_t flags, std::uint32_t family) {
  return (flags & kInterfaceUp) != 0 && family == kFamilyIPv4 && is_tunnel_name(name);
}

/// Adds `name` to `tunnels`, then drops the largest name when `tunnels` holds more than kMaxTunnels, so the set keeps
/// the kMaxTunnels smallest names without duplicates.
///
/// @param tunnels The tunnel names found so far.
/// @param name The tunnel name to add.
void add_tunnel(std::set<std::string>& tunnels, std::string_view name) {
  tunnels.emplace(name);
  if (tunnels.size() > kMaxTunnels) {
    tunnels.erase(std::prev(tunnels.end()));
  }
}

}  // namespace

Observation observe_tunnels(std::span<const InterfaceAddress> entries) {
  std::set<std::string> tunnels;
  for (const InterfaceAddress& entry : entries) {
    if (is_reported(entry.name, entry.flags, entry.family)) {
      add_tunnel(tunnels, entry.name);
    }
  }
  return observed(kTunnelsSignal, kTunnelsSource, std::vector<std::string>{tunnels.begin(), tunnels.end()});
}

Observation observe_interfaces() {
  ifaddrs* list = nullptr;
  if (getifaddrs(&list) != 0) {
    return failed(kTunnelsSignal, kTunnelsSource);
  }
  std::set<std::string> tunnels;
  for (const ifaddrs* entry = list; entry != nullptr; entry = entry->ifa_next) {
    if (entry->ifa_name == nullptr) {
      continue;
    }
    const std::uint32_t family =
        entry->ifa_addr == nullptr ? 0 : static_cast<std::uint32_t>(entry->ifa_addr->sa_family);
    if (is_reported(entry->ifa_name, static_cast<std::uint32_t>(entry->ifa_flags), family)) {
      add_tunnel(tunnels, entry->ifa_name);
    }
  }
  freeifaddrs(list);
  return observed(kTunnelsSignal, kTunnelsSource, std::vector<std::string>{tunnels.begin(), tunnels.end()});
}

std::vector<Observation> mitm() {
  if (!kPhysicalDevice) {
    return {unsupported(kTunnelsSignal, kTunnelsSource)};
  }
  return {observe_interfaces()};
}

}  // namespace rasp::ios::checks
