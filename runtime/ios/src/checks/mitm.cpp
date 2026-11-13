/// The iOS network-interception checks: the tunnel probe over the process's own network interfaces, the proxy probe
/// over the system's proxy settings, the user-authority probe that iOS doesn't support, and their unsupported result
/// off a physical device.

#include "checks/mitm.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <ifaddrs.h>
#include <iterator>
#include <memory>
#include <net/if.h>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <sys/socket.h>
#include <utility>
#include <vector>

#include "rasp/observation.h"

#ifdef __APPLE__
#include <CFNetwork/CFProxySupport.h>
#include <CoreFoundation/CFBase.h>
#include <CoreFoundation/CFDictionary.h>
#include <CoreFoundation/CFNumber.h>
#include <CoreFoundation/CFString.h>
#include <TargetConditionals.h>
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

/// The signal of the proxy probe.
constexpr std::string_view kProxiesSignal = "mitm.proxies";
/// The source of the proxy probe: the system's current proxy settings, read through CFNetworkCopySystemProxySettings.
constexpr std::string_view kProxiesSource = "CFNetworkCopySystemProxySettings";

/// The signal of the user-authority probe.
constexpr std::string_view kUserCasSignal = "mitm.user_cas";
/// The source of the user-authority probe: the trust store of the user-installed certificate authorities.
constexpr std::string_view kUserCasSource = "trust_store";

/// The text before the host of a manual HTTP proxy in the proxies observation.
constexpr std::string_view kHttpProxyPrefix = "http ";
/// The proxies observation's text for proxy auto-config, followed by a space and the URL when there is one.
constexpr std::string_view kAutoConfigProxy = "pac";

/// The existing cycle envelope accepts at most 64 names; larger views are error, never truncated success.
constexpr std::size_t kMaxTunnels = 64;
/// Accounted inspection budget; getifaddrs allocation and freeifaddrs latency are outside this consumer bound.
constexpr std::size_t kMaxInterfaceRecords = 65536 / (sizeof(ifaddrs) + IFNAMSIZ);

/// Fixed call-lifetime name storage; only the final completed result allocates owned output strings.
class InterfaceNames {
 public:
  /// Adds a previously validated name, with at most 64 bounded comparisons and no tree/string allocation.
  [[nodiscard]] bool add(std::string_view name) {
    for (const auto& slot : std::span(names_).first(size_)) {
      if (std::string_view{slot.data()} == name) {
        return true;
      }
    }
    if (size_ == kMaxTunnels) {
      return false;
    }
    std::ranges::copy(name, std::span(names_)[size_].begin());
    ++size_;
    return true;
  }

  /// Copies at most 64 complete names into the owned observation and sorts them once.
  [[nodiscard]] std::vector<std::string> value() const {
    std::vector<std::string> result;
    result.reserve(size_);
    for (const auto& slot : std::span(names_).first(size_)) {
      result.emplace_back(slot.data());
    }
    std::ranges::sort(result);
    return result;
  }

 private:
  std::array<std::array<char, IFNAMSIZ>, kMaxTunnels> names_{};
  std::size_t size_ = 0;
};

/// Validates a nullable OS name without reading beyond the platform interface-name bound.
[[nodiscard]] std::optional<std::string_view> interface_name(const char* name) {
  if (name == nullptr) {
    return std::nullopt;
  }
  const char* cursor = name;
  for (std::size_t length = 0; length < IFNAMSIZ; ++length) {
    if (*cursor == '\0') {
      return length == 0 ? std::nullopt : std::optional{std::string_view{name, length}};
    }
    cursor = std::next(cursor);
  }
  return std::nullopt;
}

/// Requires complete owned helper names, including nonmatching names.
[[nodiscard]] bool valid_name(std::string_view name) {
  return !name.empty() && name.size() < IFNAMSIZ && !name.contains('\0');
}

#ifdef __APPLE__
/// The most bytes of UTF-8 the proxy probe keeps of a proxy's host or auto-config URL, so a forged setting can't grow
/// the proxies observation without bound.
constexpr std::size_t kMaxProxyTextBytes = 1024;
#endif

/// The interface-name prefixes of a tunnel: `utun` for a Network Extension packet tunnel, `ipsec` for a built-in IKEv2
/// or IPsec VPN, `ppp` for a PPP VPN, and `tun` and `tap` for the layer-3 and layer-2 interfaces of a TUN/TAP driver.
/// Physical interfaces (`en`, `pdp_ip`, `awdl`, `llw`) and the loopback never match.
constexpr auto kTunnelPrefixes = std::to_array<std::string_view>({"utun", "ipsec", "ppp", "tun", "tap"});

static_assert(kFamilyIPv4 == static_cast<std::uint32_t>(AF_INET));
static_assert(kFamilyIPv6 == static_cast<std::uint32_t>(AF_INET6));
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

/// Whether an entry is an UP name candidate with an IPv4 or IPv6 address family.
///
/// @param name The interface's name.
/// @param flags The interface's flags, as `IFF_*` bits.
/// @param family The address family of the entry's address, or 0 when it has none.
/// @return Whether the entry qualifies as environmental name context.
[[nodiscard]] bool is_reported(std::string_view name, std::uint32_t flags, std::uint32_t family) {
  return (flags & kInterfaceUp) != 0 && (family == kFamilyIPv4 || family == kFamilyIPv6) && is_tunnel_name(name);
}

/// Writes a manual HTTP proxy the way the proxies observation reports it: `http <host>:<port>`, with the host between
/// brackets when it contains a colon, and without the colon and the port when the port is 0.
///
/// @param host The proxy's host name or address.
/// @param port The proxy's port, or 0 when it has none.
/// @return The proxy's text.
[[nodiscard]] std::string describe_http_proxy(std::string_view host, std::uint16_t port) {
  std::string text{kHttpProxyPrefix};
  if (host.contains(':')) {
    text += '[';
    text += host;
    text += ']';
  } else {
    text += host;
  }
  if (port != 0) {
    text += ':';
    text += std::to_string(port);
  }
  return text;
}

#ifdef __APPLE__
/// Reads the value of `key` in `settings` as an integer held by a CFNumber, the type the proxy settings use for their
/// enable flags and ports.
///
/// The value is owned by `settings`, under the Get rule, so it is not released.
///
/// @param settings The proxy settings.
/// @param key The key to read.
/// @return The integer, 0 when `settings` has no such key, or nothing when the value is not a CFNumber or doesn't fit
/// in 64 bits without loss.
[[nodiscard]] std::optional<std::int64_t> read_integer(CFDictionaryRef settings, CFStringRef key) {
  const void* value = CFDictionaryGetValue(settings, key);
  if (value == nullptr) {
    return 0;
  }
  if (CFGetTypeID(value) != CFNumberGetTypeID()) {
    return std::nullopt;
  }
  std::int64_t integer = 0;
  if (CFNumberGetValue(static_cast<CFNumberRef>(value), kCFNumberSInt64Type, &integer) == 0) {
    return std::nullopt;
  }
  return integer;
}

/// Reads the value of `key` in `settings` as UTF-8 text held by a CFString, the type the proxy settings use for hosts
/// and URLs.
///
/// At most kMaxProxyTextBytes bytes are kept: a longer string is cut at the last character that fits. A character
/// UTF-8 can't encode, a lone UTF-16 surrogate, is written as a question mark. The value is owned by `settings`, under
/// the Get rule, so it is not released.
///
/// @param settings The proxy settings.
/// @param key The key to read.
/// @return The text, empty when `settings` has no such key, or nothing when the value is not a CFString.
[[nodiscard]] std::optional<std::string> read_text(CFDictionaryRef settings, CFStringRef key) {
  const void* value = CFDictionaryGetValue(settings, key);
  if (value == nullptr) {
    return std::string{};
  }
  if (CFGetTypeID(value) != CFStringGetTypeID()) {
    return std::nullopt;
  }
  const auto* const string = static_cast<CFStringRef>(value);
  std::array<std::uint8_t, kMaxProxyTextBytes> buffer{};
  CFIndex used = 0;
  static_cast<void>(CFStringGetBytes(string, CFRangeMake(0, CFStringGetLength(string)), kCFStringEncodingUTF8, '?', 0,
                                     buffer.data(), static_cast<CFIndex>(buffer.size()), &used));
  return std::string(buffer.begin(), std::next(buffer.begin(), used));
}

/// Reads the manual HTTP proxy and the proxy auto-config of `settings`, the dictionary
/// CFNetworkCopySystemProxySettings returns.
///
/// A missing key reads as a disabled proxy, an empty host or URL, or no port. Every value `settings` holds is owned by
/// it, under the Get rule, so none is released.
///
/// @param settings The proxy settings.
/// @return The settings, or nothing when one of the values has the wrong type or the port is not between 0 and 65535.
[[nodiscard]] std::optional<ProxySettings> read_proxy_settings(CFDictionaryRef settings) {
  const std::optional<std::int64_t> http_enabled = read_integer(settings, kCFNetworkProxiesHTTPEnable);
  std::optional<std::string> http_host = read_text(settings, kCFNetworkProxiesHTTPProxy);
  const std::optional<std::int64_t> http_port = read_integer(settings, kCFNetworkProxiesHTTPPort);
  const std::optional<std::int64_t> auto_config_enabled =
      read_integer(settings, kCFNetworkProxiesProxyAutoConfigEnable);
  std::optional<std::string> auto_config_url = read_text(settings, kCFNetworkProxiesProxyAutoConfigURLString);
  if (!http_enabled.has_value() || !http_host.has_value() || !http_port.has_value() ||
      !std::in_range<std::uint16_t>(*http_port) || !auto_config_enabled.has_value() || !auto_config_url.has_value()) {
    return std::nullopt;
  }
  return ProxySettings{
      .http_enabled = *http_enabled != 0,
      .http_host = std::move(*http_host),
      .http_port = static_cast<std::uint16_t>(*http_port),
      .auto_config_enabled = *auto_config_enabled != 0,
      .auto_config_url = std::move(*auto_config_url),
  };
}
#endif

}  // namespace

Observation observe_tunnels(std::span<const InterfaceAddress> entries) {
  if (entries.size() > kMaxInterfaceRecords) {
    return failed(kTunnelsSignal, kTunnelsSource);
  }
  InterfaceNames tunnels;
  for (const InterfaceAddress& entry : entries) {
    if (!valid_name(entry.name) || (is_reported(entry.name, entry.flags, entry.family) && !tunnels.add(entry.name))) {
      return failed(kTunnelsSignal, kTunnelsSource);
    }
  }
  return observed(kTunnelsSignal, kTunnelsSource, tunnels.value());
}

Observation observe_interfaces() {
  ifaddrs* list = nullptr;
  if (getifaddrs(&list) != 0) {
    return failed(kTunnelsSignal, kTunnelsSource);
  }
  const std::unique_ptr<ifaddrs, decltype(&freeifaddrs)> owner(list, freeifaddrs);
  InterfaceNames tunnels;
  std::size_t records = 0;
  for (const ifaddrs* entry = owner.get(); entry != nullptr; entry = entry->ifa_next) {
    if (records == kMaxInterfaceRecords) {
      return failed(kTunnelsSignal, kTunnelsSource);
    }
    ++records;
    const auto name = interface_name(entry->ifa_name);
    if (!name.has_value()) {
      return failed(kTunnelsSignal, kTunnelsSource);
    }
    const std::uint32_t family =
        entry->ifa_addr == nullptr ? 0 : static_cast<std::uint32_t>(entry->ifa_addr->sa_family);
    if (is_reported(*name, static_cast<std::uint32_t>(entry->ifa_flags), family) && !tunnels.add(*name)) {
      return failed(kTunnelsSignal, kTunnelsSource);
    }
  }
  return observed(kTunnelsSignal, kTunnelsSource, tunnels.value());
}

Observation observe_proxies(const ProxySettings& settings) {
  std::vector<std::string> proxies;
  if (settings.http_enabled && !settings.http_host.empty()) {
    proxies.push_back(describe_http_proxy(settings.http_host, settings.http_port));
  }
  if (settings.auto_config_enabled) {
    std::string proxy{kAutoConfigProxy};
    if (!settings.auto_config_url.empty()) {
      proxy += ' ';
      proxy += settings.auto_config_url;
    }
    proxies.push_back(std::move(proxy));
  }
  return observed(kProxiesSignal, kProxiesSource, std::move(proxies));
}

Observation observe_system_proxies() {
#ifdef __APPLE__
  const CFDictionaryRef settings = CFNetworkCopySystemProxySettings();
  if (settings == nullptr) {
    return failed(kProxiesSignal, kProxiesSource);
  }
  const std::optional<ProxySettings> proxies =
      CFGetTypeID(settings) == CFDictionaryGetTypeID() ? read_proxy_settings(settings) : std::nullopt;
  CFRelease(settings);
  if (!proxies.has_value()) {
    return failed(kProxiesSignal, kProxiesSource);
  }
  return observe_proxies(*proxies);
#else
  return unsupported(kProxiesSignal, kProxiesSource);
#endif
}

std::vector<Observation> mitm() {
  std::vector<Observation> observations;
  observations.reserve(3);
  if (kPhysicalDevice) {
    observations.push_back(observe_interfaces());
    observations.push_back(observe_system_proxies());
  } else {
    observations.push_back(unsupported(kTunnelsSignal, kTunnelsSource));
    observations.push_back(unsupported(kProxiesSignal, kProxiesSource));
  }
  observations.push_back(unsupported(kUserCasSignal, kUserCasSource));
  return observations;
}

}  // namespace rasp::ios::checks
