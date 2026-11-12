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
/// On Android it reads the process's own network interfaces through getifaddrs and reports the tunnels among them, and
/// reads the aliases of the `AndroidCAStore` KeyStore through JNI and reports the user-installed authorities among
/// them. An app can't list the user trust store's folder, which SELinux labels system_data_file, but the KeyStore is
/// public API. To call it, the calling thread is attached to the app's Java VM the first time and stays attached, so
/// it must be the runtime's own thread, which never ends. Any exception a call throws is cleared, and the observation
/// then has an error status, as it has when the thread can't reach the VM. Anywhere else, such as on a Linux host,
/// every observation is unsupported instead, so the server still sees that the check ran.
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

/// Reports the user-installed certificate authorities among `aliases`, the aliases of the `AndroidCAStore` KeyStore.
///
/// To decrypt traffic without certificate warnings, an interception proxy must install its root certificate where the
/// app validates it, and on Android a certificate the user installs lands in the user trust store, apart from the
/// system authorities the device ships with. So a user-installed authority is a signal a decrypting proxy left behind,
/// not proof of one. The KeyStore names each user authority `user:` followed by its file name in the user trust store,
/// named after the hash of its subject, and each system one `system:` followed by its file name. The probe reports the
/// user authorities' file names, which name them without reading their bytes. On a device `mitm` reads the aliases
/// through JNI; a test passes them directly.
///
/// @param aliases The aliases of the `AndroidCAStore` KeyStore, with or without duplicates.
/// @return One mitm.user_cas observation through user_cacerts: the file name of every user authority, sorted and
/// without duplicates, since the user decides which to trust. An empty list means no authority is installed.
[[nodiscard]] Observation observe_user_cas(const std::vector<std::string>& aliases);

}  // namespace rasp::android::checks
