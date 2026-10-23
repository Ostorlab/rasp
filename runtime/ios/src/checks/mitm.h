/// The iOS network-interception checks: the signs that the app's traffic is being routed through a man-in-the-middle,
/// namely a tunnel interface that a VPN or an on-device capture app opens and carries an IPv4 address on.

#pragma once

#include <cstdint>
#include <span>
#include <string>
#include <vector>

#include "rasp/observation.h"

namespace rasp::ios::checks {

/// The bit of an interface's flags that marks the interface as up, `IFF_UP`.
constexpr std::uint32_t kInterfaceUp = 1;
/// The address family of an IPv4 address, `AF_INET`.
constexpr std::uint32_t kFamilyIPv4 = 2;

/// One entry of the list getifaddrs returns: a network interface, with one of its addresses.
struct InterfaceAddress {
  /// The interface's name, such as `utun3` or `en0`.
  std::string name;
  /// The interface's flags, as a combination of `IFF_*` bits such as kInterfaceUp.
  std::uint32_t flags = 0;
  /// The address family of the entry's address, such as kFamilyIPv4, or 0 when the entry has no address.
  std::uint32_t family = 0;
};

/// Runs the network-interception checks and returns what they observed.
///
/// On a physical iOS device it reads the process's own network interfaces through getifaddrs and reports the tunnels
/// among them, as observe_interfaces does. Anywhere else, on a simulator, a Mac or a Linux host, the observation is
/// unsupported instead, so the result still shows that the check ran.
///
/// @return One observation: mitm.tunnels through getifaddrs.
[[nodiscard]] std::vector<Observation> mitm();

/// Reports the tunnel interfaces among `entries` that are up and carry an IPv4 address.
///
/// A man-in-the-middle proxy on iOS, or a VPN, captures the app's traffic through a virtual tunnel interface: the
/// `utun` interface a Network Extension packet tunnel opens, the `ipsec` interface of a built-in IKEv2 or IPsec VPN,
/// the `ppp` interface of an older PPP VPN, or a `tun` or `tap` interface. A name matches when it is one of these
/// prefixes followed by a run of digits and nothing else, such as `utun3`, `ipsec0` or `ppp0`. Stock iOS keeps several
/// `utun` interfaces open for its own services, so a name alone would match on every device. An interface is therefore
/// reported only when one of its entries has kInterfaceUp in its flags and an address of the kFamilyIPv4 family, the
/// kind of address a VPN app normally assigns to its tunnel. A tunnel whose only addresses are IPv6 is not reported,
/// whether it belongs to the system or to a VPN that assigns no IPv4 address. A legitimate VPN opens the same
/// interfaces as a capture app, so the probe reports every tunnel it finds and the server weighs it.
///
/// @param entries The entries to look at, such as the list getifaddrs returns, with an interface once per address.
/// @return One mitm.tunnels observation through getifaddrs: the names of the matching interfaces, sorted and without
/// duplicates, the 100 smallest when there are more. An empty list is a real answer, not a failure.
[[nodiscard]] Observation observe_tunnels(std::span<const InterfaceAddress> entries);

/// Reports the tunnel interfaces of the process that are up and carry an IPv4 address, read through getifaddrs.
///
/// The probe walks the list getifaddrs returns, matches each entry the way observe_tunnels does, and frees the list on
/// every path. The interfaces are read again on every call, so the probe also sees a tunnel opened after the app
/// started. getifaddrs exists on every POSIX system, so the probe also runs on a Mac or a Linux host.
///
/// @return One mitm.tunnels observation through getifaddrs, as observe_tunnels reports it. It has an error status
/// when getifaddrs fails.
[[nodiscard]] Observation observe_interfaces();

}  // namespace rasp::ios::checks
