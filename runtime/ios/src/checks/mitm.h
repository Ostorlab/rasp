/// The iOS network-interception checks: the signs that the app's traffic is being routed through a man-in-the-middle,
/// namely a tunnel interface that a VPN or an on-device capture app opens and carries an IPv4 address on, a proxy that
/// the system's proxy settings configure, and the user-installed certificate authorities that iOS doesn't expose.

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

/// The proxies of the system's current proxy settings, as CFNetworkCopySystemProxySettings returns them.
struct ProxySettings {
  /// Whether the manual HTTP proxy is enabled, the kCFNetworkProxiesHTTPEnable key.
  bool http_enabled = false;
  /// The host name or address of the manual HTTP proxy, the kCFNetworkProxiesHTTPProxy key, or empty when the settings
  /// give none.
  std::string http_host;
  /// The port of the manual HTTP proxy, the kCFNetworkProxiesHTTPPort key, or 0 when the settings give none.
  std::uint16_t http_port = 0;
  /// Whether proxy auto-config is enabled, the kCFNetworkProxiesProxyAutoConfigEnable key.
  bool auto_config_enabled = false;
  /// The URL of the proxy auto-config file, the kCFNetworkProxiesProxyAutoConfigURLString key, or empty when the
  /// settings give none.
  std::string auto_config_url;
};

/// Runs the network-interception checks and returns what they observed.
///
/// On a physical iOS device it reads the process's own network interfaces through getifaddrs and reports the tunnels
/// among them, as observe_interfaces does, then reads the system's proxy settings and reports the proxies they
/// configure, as observe_system_proxies does. Anywhere else, on a simulator, a Mac or a Linux host, every observation
/// is unsupported instead, so the result still shows that the checks ran.
///
/// mitm.user_cas is unsupported everywhere: iOS has no public API that lists the certificate authorities the user
/// installed, and the trust store is outside the app's sandbox. It is still reported, so the server sees the same
/// signals on iOS and Android.
///
/// @return Three observations, in this order: mitm.tunnels through getifaddrs, mitm.proxies through
/// CFNetworkCopySystemProxySettings, and mitm.user_cas through trust_store, which is always unsupported.
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

/// Reports the proxies that `settings` configure, one string per proxy.
///
/// The manual HTTP proxy is reported as `http <host>:<port>`, such as `http 192.168.1.10:8080`, when it is enabled and
/// has a host. A host that contains a colon, an IPv6 address, is written between brackets, such as
/// `http [fd00::2]:8080`, and a proxy with no port is written without one, such as `http proxy.example`. Proxy
/// auto-config is reported as `pac <url>`, such as `pac http://wpad.example/proxy.pac`, when it is enabled, or as `pac`
/// alone when it is enabled with no URL. An interception proxy such as Burp Suite or mitmproxy, set in the Wi-Fi
/// settings, shows up here, and so does a company's proxy, so the probe reports every proxy it finds and the server
/// weighs it.
///
/// @param settings The proxy settings, such as observe_system_proxies reads them.
/// @return One mitm.proxies observation through CFNetworkCopySystemProxySettings: the HTTP proxy first, then the proxy
/// auto-config, so at most two strings. An empty list means that no proxy is configured, a real answer, not a failure.
[[nodiscard]] Observation observe_proxies(const ProxySettings& settings);

/// Reports the proxies that the system's current proxy settings configure, read through
/// CFNetworkCopySystemProxySettings.
///
/// The probe reads the manual HTTP proxy and the proxy auto-config of the settings, which apply to the device's
/// primary network, and reports them as observe_proxies does. A VPN that carries the device's traffic becomes the
/// primary network, so while it is connected the probe reports the VPN's proxies, usually none, and not those of the
/// Wi-Fi network: the traffic then goes through the tunnel, not through the Wi-Fi proxy, and the tunnel is reported by
/// mitm.tunnels. A host or URL longer than 1024 bytes of UTF-8 is cut to
/// its first 1024 bytes, at a character boundary. The settings are read again on every call, so the probe also sees a
/// proxy set after the app started. CFNetwork exists only on Apple systems, so anywhere else the observation is
/// unsupported.
///
/// @return One mitm.proxies observation through CFNetworkCopySystemProxySettings, as observe_proxies reports it. It has
/// an error status when the call returns no settings, or when a value of the settings has the wrong type or a port is
/// out of range.
[[nodiscard]] Observation observe_system_proxies();

}  // namespace rasp::ios::checks
