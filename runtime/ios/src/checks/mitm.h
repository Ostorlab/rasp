/// iOS environmental observations of interface-name candidates, current proxy settings, and unavailable CA listing.
/// These observations do not establish malware, TLS interception, or routing of a particular connection.

#pragma once

#include <cstdint>
#include <span>
#include <string>
#include <sys/socket.h>
#include <vector>

#include "rasp/observation.h"

namespace rasp::ios::checks {

/// The bit of an interface's flags that marks the interface as up, `IFF_UP`.
constexpr std::uint32_t kInterfaceUp = 1;
/// The address family of an IPv4 address, `AF_INET`.
constexpr std::uint32_t kFamilyIPv4 = 2;
/// The native IPv6 family, whose numeric value differs between Darwin and host fixtures.
constexpr std::uint32_t kFamilyIPv6 = static_cast<std::uint32_t>(AF_INET6);

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

/// Reports UP interface-name candidates with an AF_INET or AF_INET6 entry, including link-local IPv6.
/// Known forms are utun/ipsec/ppp/tun/tap followed entirely by digits. System services and legitimate VPNs can
/// match; unknown names can be missed. An empty result means only that no entry matched this source's scope.
/// Every record charges sizeof(ifaddrs)+IFNAMSIZ against 65536 consumer bytes. Names must be nonempty,
/// shorter than IFNAMSIZ and contain no embedded NUL, including names of ineligible entries. More than 64
/// distinct matches, invalid names or an incomplete view return error without partial names.
/// @param entries Complete entries from a synthetic or current public view, including repeated address families.
/// @return Sorted/deduplicated matching names, or error without a value.
[[nodiscard]] Observation observe_tunnels(std::span<const InterfaceAddress> entries);

/// Reads one current public getifaddrs view using the same complete filtering/bounds as observe_tunnels.
/// Copies matching names before freeing the owned list exactly once on each nonnull-success exit. Null names,
/// missing terminators, API errors and consumer overflows are error; null/non-IP addresses are skipped safely.
/// OS allocation/free cost and latency have no caller-supplied hard bound. This does not prove current routing.
/// @return Owned names or error without a value. Successful empty list is a scoped empty observation.
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
/// The probe reads the exposed manual HTTP proxy and proxy auto-config keys from current systemwide settings.
/// These settings do not establish whether a particular connection uses a proxy or tunnel. A host or URL longer
/// than 1024 bytes of UTF-8 is cut to
/// its first 1024 bytes, at a character boundary. The settings are read again on every call, so the probe also sees a
/// proxy set after the app started. CFNetwork exists only on Apple systems, so anywhere else the observation is
/// unsupported.
///
/// @return One mitm.proxies observation through CFNetworkCopySystemProxySettings, as observe_proxies reports it. It has
/// an error status when the call returns no settings, or when a value of the settings has the wrong type or a port is
/// out of range.
[[nodiscard]] Observation observe_system_proxies();

}  // namespace rasp::ios::checks
