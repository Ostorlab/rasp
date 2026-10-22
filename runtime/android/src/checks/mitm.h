/// The Android network-interception checks: the signs that the app's traffic is being routed through a
/// man-in-the-middle, namely a tunnel interface that captures traffic and a user-installed certificate authority that
/// lets a proxy decrypt TLS.

#pragma once

#include <string_view>
#include <vector>

#include "rasp/observation.h"

namespace rasp::android::checks {

/// Runs the network-interception checks and returns what they observed.
///
/// On Android, the emulator included, it runs every probe. Anywhere else, such as on a Linux host, every observation
/// is unsupported instead, so the server still sees that the check ran.
///
/// @return One observation per signal and source, in this order: mitm.tunnels through proc_net_route, then
/// mitm.user_cas through user_cacerts.
[[nodiscard]] std::vector<Observation> mitm();

/// Reports the tunnel interfaces the kernel routes traffic through, from the route table at `route_path`.
///
/// A man-in-the-middle proxy often captures the app's traffic through a virtual tunnel interface, such as the `tun`
/// interface an on-device VPN app opens or the `ppp` interface a dial-up style tunnel opens. The route table names the
/// interface of every route on its own line, so this probe reports the routes whose interface is a tunnel. A device
/// with no capture running routes through its physical interfaces, such as `wlan0` or `rmnet`, and reports nothing. The
/// file is read whole, up to 256 KiB.
///
/// @param route_path The route table to read, `/proc/net/route` on a device.
/// @return One mitm.tunnels observation read through proc_net_route: the matching route lines, at most 32. It has an
/// error status when the file can't be read or is larger than 256 KiB.
[[nodiscard]] Observation observe_tunnels(std::string_view route_path);

/// Reports the user-installed certificate authorities in the trust store directory `cacerts_dir`.
///
/// To decrypt traffic without certificate warnings, an interception proxy must install its root certificate where the
/// app validates it, and on Android a certificate the user installs lands in the user trust store, apart from the
/// system authorities the device ships with. So a user-installed authority is a signal a decrypting proxy left behind,
/// not proof of one: this probe reports the authorities and the server decides. Each authority is a file named after
/// the hash of its subject; the probe reports those file names, which name the authorities without reading their bytes.
///
/// @param cacerts_dir The user trust store directory to list, `/data/misc/user/0/cacerts-added` on a device.
/// @return One mitm.user_cas observation read through user_cacerts: the certificate file names, the 32 smallest when
/// there are more. It has an error status when the directory can't be listed or an entry can't be read. An empty list,
/// the common case, means no user authority is installed.
[[nodiscard]] Observation observe_user_cas(std::string_view cacerts_dir);

}  // namespace rasp::android::checks
