/// The Android network-interception checks: the signs that the app's traffic is being routed through a
/// man-in-the-middle, namely a tunnel interface that captures traffic and a user-installed certificate authority that
/// lets a proxy decrypt TLS.

#pragma once

#include <string>
#include <string_view>
#include <vector>

#include "rasp/observation.h"

namespace rasp::android::checks {

/// Runs the network-interception checks and returns what they observed.
///
/// On Android it reads the process's own network interfaces through getifaddrs and reports the tunnels among them.
/// Anywhere else, such as on a Linux host, the observation is unsupported instead, so the server still sees that the
/// check ran. The user-authority probe always reports unsupported on a device: the user trust store is labeled
/// system_data_file under SELinux and no public SDK API exposes user-installed CAs, so an untrusted app process can't
/// enumerate them.
///
/// @return One observation per signal and source, in this order: mitm.tunnels through getifaddrs, then mitm.user_cas
/// through user_cacerts.
[[nodiscard]] std::vector<Observation> mitm();

/// Reports the tunnel interfaces among `interface_names`, the names the process's own network interfaces carry.
///
/// A man-in-the-middle proxy often captures the app's traffic through a virtual tunnel interface, the `tun` or `tap`
/// interface an on-device VPN app opens through the kernel's TUN/TAP driver. The same `tun` interface is the one a
/// legitimate VPN opens, so the probe reports every tunnel it finds and the server weighs it. A device with no capture
/// running carries only its physical interfaces, such as `wlan0` or `rmnet`, and reports nothing. On a device `mitm`
/// reads the names through getifaddrs, which an app process can call where it can't read `/proc/net/route`; a test
/// passes the names directly.
///
/// @param interface_names The names of the network interfaces to inspect, with or without duplicates.
/// @return One mitm.tunnels observation through getifaddrs: the tunnel interface names, without duplicates, the 100
/// smallest when there are more. It never has an error status; `mitm` reports the error when getifaddrs itself fails.
[[nodiscard]] Observation observe_tunnels(const std::vector<std::string>& interface_names);

/// Reports the user-installed certificate authorities in the trust store directory `cacerts_dir`.
///
/// To decrypt traffic without certificate warnings, an interception proxy must install its root certificate where the
/// app validates it, and on Android a certificate the user installs lands in the user trust store, apart from the
/// system authorities the device ships with. So a user-installed authority is a signal a decrypting proxy left behind,
/// not proof of one. Each authority is a file named after the hash of its subject; the probe reports those file names,
/// which name the authorities without reading their bytes. On a production device that store is unreadable by an app
/// process, so `mitm` reports mitm.user_cas as unsupported and doesn't call this probe; it exists so the listing logic
/// stays covered by tests, which pass a readable directory.
///
/// @param cacerts_dir The user trust store directory to list.
/// @return One mitm.user_cas observation through user_cacerts: every certificate file name, sorted and without
/// duplicates, since the user decides which to trust. It has an error status when the directory can't be listed or an
/// entry can't be read. An empty list means no authority is installed.
[[nodiscard]] Observation observe_user_cas(std::string_view cacerts_dir);

}  // namespace rasp::android::checks
