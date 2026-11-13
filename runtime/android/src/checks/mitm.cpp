/// The Android network-interception checks: the tunnel probe over the process's own network interfaces, the
/// user-authority probe over the `AndroidCAStore` KeyStore, and their unsupported results off Android.

#include "checks/mitm.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <ifaddrs.h>
#include <iterator>
#include <memory>
#include <optional>
#include <set>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#ifdef __ANDROID__
#include <jni.h>
#include <linux/if.h>

#include "util/jni.h"
#else
#include <net/if.h>
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

/// The existing cycle envelope accepts at most 64 names; larger views are error, never truncated success.
constexpr std::size_t kMaxEntries = 64;
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
    if (size_ == kMaxEntries) {
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
  std::array<std::array<char, IFNAMSIZ>, kMaxEntries> names_{};
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

/// Filters a complete finite helper inventory; an incomplete or malformed view has no partial value.
[[nodiscard]] std::optional<std::vector<std::string>> tunnel_names(const std::vector<std::string>& names) {
  if (names.size() > kMaxInterfaceRecords) {
    return std::nullopt;
  }
  InterfaceNames tunnels;
  for (const std::string& name : names) {
    if (!valid_name(name) || (is_tunnel(name) && !tunnels.add(name))) {
      return std::nullopt;
    }
  }
  return tunnels.value();
}

/// Inspects one owned public API view; family and flags deliberately do not restrict Android's name predicate.
[[nodiscard]] std::optional<std::vector<std::string>> tunnel_interface_names() {
  ifaddrs* list = nullptr;
  if (getifaddrs(&list) != 0) {
    return std::nullopt;
  }
  const std::unique_ptr<ifaddrs, decltype(&freeifaddrs)> owner(list, freeifaddrs);
  InterfaceNames tunnels;
  std::size_t records = 0;
  for (const ifaddrs* entry = owner.get(); entry != nullptr; entry = entry->ifa_next) {
    if (records == kMaxInterfaceRecords) {
      return std::nullopt;
    }
    ++records;
    const auto name = interface_name(entry->ifa_name);
    if (!name.has_value() || (is_tunnel(*name) && !tunnels.add(*name))) {
      return std::nullopt;
    }
  }
  return tunnels.value();
}

#ifdef __ANDROID__
/// The most aliases read from the `AndroidCAStore` KeyStore, so a store that never ends can't keep the thread reading.
/// A device ships with about 150 authorities.
constexpr int kMaxAliases = 4096;

/// The local references a pass of ca_store_aliases makes, outside the loop over the aliases, which frees its own.
constexpr jint kLocalFrameCapacity = 16;

using util::attached_env;
using util::threw;

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

Observation observe_interfaces() {
  auto names = tunnel_interface_names();
  return names.has_value() ? observed(kTunnelsSignal, kTunnelsSource, std::move(*names))
                           : failed(kTunnelsSignal, kTunnelsSource);
}

Observation observe_tunnels(const std::vector<std::string>& interface_names) {
  auto names = tunnel_names(interface_names);
  return names.has_value() ? observed(kTunnelsSignal, kTunnelsSource, std::move(*names))
                           : failed(kTunnelsSignal, kTunnelsSource);
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
  Observation tunnels = observe_interfaces();
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
