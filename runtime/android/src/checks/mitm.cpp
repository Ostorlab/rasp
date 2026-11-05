/// The Android network-interception checks: the tunnel probe over the process's own network interfaces, the
/// user-authority probe over the `AndroidCAStore` KeyStore, and their unsupported results off Android.

#include "checks/mitm.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <ifaddrs.h>
#include <iterator>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#ifdef __ANDROID__
#include <jni.h>
#endif

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

/// The prefix of a user-installed authority's alias in the `AndroidCAStore` KeyStore, followed by the authority's file
/// name. The authorities the device ships with have the prefix `system:` instead.
constexpr std::string_view kUserAliasPrefix = "user:";

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

#ifdef __ANDROID__
/// The most aliases read from the `AndroidCAStore` KeyStore, so a store that never ends can't keep the thread reading.
/// A device ships with about 150 authorities.
constexpr int kMaxAliases = 4096;

/// The local references a pass of ca_store_aliases makes, outside the loop over the aliases, which frees its own.
constexpr jint kLocalFrameCapacity = 16;

/// Whether the last JNI call threw. The exception is cleared, so it never reaches the app.
///
/// @param env The thread's JNI environment.
/// @return `true` when the call threw.
[[nodiscard]] bool threw(JNIEnv* env) {
  if (env->ExceptionCheck() == JNI_FALSE) {
    return false;
  }
  env->ExceptionClear();
  return true;
}

/// The JNI environment of the calling thread, which is attached to the app's Java VM the first time and stays attached:
/// the runtime's thread never ends, so it never has to detach.
///
/// @return The environment, or null when there is no Java VM or the thread can't be attached.
[[nodiscard]] JNIEnv* attached_env() {
  JavaVM* vm = nullptr;
  jsize count = 0;
  if (JNI_GetCreatedJavaVMs(&vm, 1, &count) != JNI_OK || count < 1 || vm == nullptr) {
    return nullptr;
  }
  JNIEnv* env = nullptr;
  if (vm->AttachCurrentThread(&env, nullptr) != JNI_OK) {
    return nullptr;
  }
  return env;
}

/// Reads the aliases of the `AndroidCAStore` KeyStore, inside a local frame that the caller pops.
///
/// @param env The thread's JNI environment.
/// @return The aliases, or nothing when a call fails or throws, or the store has more than kMaxAliases.
[[nodiscard]] std::optional<std::vector<std::string>> read_ca_store_aliases(JNIEnv* env) {
  jclass key_store = env->FindClass("java/security/KeyStore");
  jclass enumeration = env->FindClass("java/util/Enumeration");
  if (threw(env) || key_store == nullptr || enumeration == nullptr) {
    return std::nullopt;
  }
  jmethodID get_instance =
      env->GetStaticMethodID(key_store, "getInstance", "(Ljava/lang/String;)Ljava/security/KeyStore;");
  jmethodID load = env->GetMethodID(key_store, "load", "(Ljava/security/KeyStore$LoadStoreParameter;)V");
  jmethodID aliases = env->GetMethodID(key_store, "aliases", "()Ljava/util/Enumeration;");
  jmethodID has_more = env->GetMethodID(enumeration, "hasMoreElements", "()Z");
  jmethodID next = env->GetMethodID(enumeration, "nextElement", "()Ljava/lang/Object;");
  jstring type = env->NewStringUTF("AndroidCAStore");
  if (threw(env) || get_instance == nullptr || load == nullptr || aliases == nullptr || has_more == nullptr ||
      next == nullptr || type == nullptr) {
    return std::nullopt;
  }
  const jvalue type_argument{.l = type};
  jobject store = env->CallStaticObjectMethodA(key_store, get_instance, &type_argument);
  if (threw(env) || store == nullptr) {
    return std::nullopt;
  }
  const jvalue no_parameter{.l = nullptr};
  env->CallVoidMethodA(store, load, &no_parameter);
  if (threw(env)) {
    return std::nullopt;
  }
  jobject alias_enumeration = env->CallObjectMethodA(store, aliases, nullptr);
  if (threw(env) || alias_enumeration == nullptr) {
    return std::nullopt;
  }
  std::vector<std::string> found_aliases;
  for (int index = 0; index <= kMaxAliases; ++index) {
    const jboolean has_next = env->CallBooleanMethodA(alias_enumeration, has_more, nullptr);
    if (threw(env)) {
      return std::nullopt;
    }
    if (has_next == JNI_FALSE) {
      return found_aliases;
    }
    if (index == kMaxAliases) {
      return std::nullopt;
    }
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-static-cast-downcast): the aliases of a KeyStore are strings.
    auto* alias = static_cast<jstring>(env->CallObjectMethodA(alias_enumeration, next, nullptr));
    if (threw(env) || alias == nullptr) {
      return std::nullopt;
    }
    const char* alias_chars = env->GetStringUTFChars(alias, nullptr);
    if (alias_chars == nullptr) {
      static_cast<void>(threw(env));
      return std::nullopt;
    }
    found_aliases.emplace_back(alias_chars);
    env->ReleaseStringUTFChars(alias, alias_chars);
    env->DeleteLocalRef(alias);
  }
  return std::nullopt;
}

/// The aliases of the `AndroidCAStore` KeyStore, the system's view of the authorities the app's TLS trusts, read
/// through JNI on the calling thread, which is attached to the app's Java VM for it. Every local reference is freed.
///
/// @return The aliases, or nothing when the thread can't reach the VM, or a call fails or throws.
[[nodiscard]] std::optional<std::vector<std::string>> ca_store_aliases() {
  JNIEnv* env = attached_env();
  if (env == nullptr) {
    return std::nullopt;
  }
  if (env->PushLocalFrame(kLocalFrameCapacity) != JNI_OK) {
    static_cast<void>(threw(env));
    return std::nullopt;
  }
  std::optional<std::vector<std::string>> aliases = read_ca_store_aliases(env);
  env->PopLocalFrame(nullptr);
  return aliases;
}
#endif

}  // namespace

Observation observe_tunnels(const std::vector<std::string>& interface_names) {
  return observed(kTunnelsSignal, kTunnelsSource, tunnel_names(interface_names));
}

Observation observe_user_cas(const std::vector<std::string>& aliases) {
  std::set<std::string> names;
  for (const std::string_view alias : aliases) {
    if (alias.starts_with(kUserAliasPrefix)) {
      names.emplace(alias.substr(kUserAliasPrefix.size()));
    }
  }
  return observed(kUserCasSignal, kUserCasSource, std::vector<std::string>{names.begin(), names.end()});
}

std::vector<Observation> mitm() {
  if (!kOnAndroid) {
    return {unsupported(kTunnelsSignal, kTunnelsSource), unsupported(kUserCasSignal, kUserCasSource)};
  }
  const std::optional<std::vector<std::string>> names = tunnel_interface_names();
  Observation tunnels = names ? observe_tunnels(*names) : failed(kTunnelsSignal, kTunnelsSource);
  std::vector<Observation> observations;
  observations.reserve(2);
  observations.push_back(std::move(tunnels));
#ifdef __ANDROID__
  const std::optional<std::vector<std::string>> aliases = ca_store_aliases();
  observations.push_back(aliases ? observe_user_cas(*aliases) : failed(kUserCasSignal, kUserCasSource));
#endif
  return observations;
}

}  // namespace rasp::android::checks
