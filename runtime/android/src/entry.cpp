/// The entry point of librasp.so. A load-time constructor runs when the dynamic linker loads the library, the way iOS
/// starts from a constructor: it reads the packed payload from the app's own APK, runs the checks and decrypts the
/// app's dex files. It cannot hand them to Java itself, because `FindClass` resolves the app's own classes only inside
/// the class-loader context the platform sets up for `JNI_OnLoad`, not for a plain constructor. So a minimal
/// `JNI_OnLoad`, which the platform calls moments later while still loading the library, builds a class loader over the
/// decrypted dex files and stores it in the stub's field. Java calls no native method; the stub only reads that field,
/// and the library exports no `Java_...` entry.

#include <algorithm>
#include <cstdint>
#include <iterator>
#include <jni.h>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "apk/archive.h"
#include "apk/location.h"
#include "checks/debugger.h"
#include "checks/root.h"
#include "loader/loader.h"
#include "payload/cipher.h"
#include "payload/payload.h"
#include "rasp/observation.h"
#include "rasp/util/logging.h"
#include "rasp/version.h"

namespace {

/// The APK assets the packer writes: the payload key and the packed payload, both stored uncompressed.
constexpr const char* kKeyEntry = "assets/rasp/key.bin";
constexpr const char* kPayloadEntry = "assets/rasp/payload.bin";

/// The app's decrypted dex files and native-library directory, decrypted by the constructor and published by
/// JNI_OnLoad. Both run on the loading thread, the constructor first, so no synchronization is needed.
struct Pending {
  std::optional<std::vector<rasp::android::payload::Dex>> dexes;
  std::string library_dir;
};

/// The shared hand-off between the constructor and JNI_OnLoad, built on first use and never destroyed, so the library
/// has no static-init ordering and no exit-time destructor.
[[nodiscard]] Pending& pending() {
  // NOLINTNEXTLINE(cppcoreguidelines-owning-memory)
  static auto* const kState = new Pending();
  return *kState;
}

/// Whether the library is loaded inside a running JVM. On API 31 and newer, `JNI_GetCreatedJavaVMs` is part of the
/// platform's public native API, so a load-time constructor can tell without an exported JNI entry point.
[[nodiscard]] bool running_in_jvm() noexcept {
  JavaVM* vm = nullptr;
  jsize count = 0;
  return JNI_GetCreatedJavaVMs(&vm, 1, &count) == JNI_OK && count > 0;
}

/// Writes one development-build line to the log; release builds write nothing and hold no such text.
void log_line(std::string_view message) {
  if constexpr (rasp::kLoggingEnabled) {
    rasp::log(message);
  }
}

/// Logs the runtime version and each observation, in a development build only.
void log_observations(const std::vector<rasp::Observation>& observations) {
  if constexpr (rasp::kLoggingEnabled) {
    rasp::log(std::string(rasp::kRuntimeVersion) + " loaded");
    for (const rasp::Observation& observation : observations) {
      rasp::log(rasp::describe(observation));
    }
  }
}

/// Reads the app's dex files from its APK: reads the key and payload assets and decrypts them.
[[nodiscard]] std::optional<std::vector<rasp::android::payload::Dex>> recover_dexes(const std::string& apk) {
  const std::optional<std::vector<std::uint8_t>> key = rasp::android::apk::read_stored_entry(apk, kKeyEntry);
  if (!key.has_value() || key->size() != rasp::android::payload::kKeySize) {
    return std::nullopt;
  }
  const std::optional<std::vector<std::uint8_t>> payload = rasp::android::apk::read_stored_entry(apk, kPayloadEntry);
  if (!payload.has_value()) {
    return std::nullopt;
  }
  return rasp::android::payload::unpack(*key, *payload);
}

/// Runs the checks and decrypts the app's dex files when the dynamic linker loads librasp.so, holding them for
/// JNI_OnLoad to publish. The decrypted dex files are kept in memory and never written to disk.
__attribute__((constructor)) void rasp_start() noexcept {
  if (!running_in_jvm()) {
    return;
  }
  std::vector<rasp::Observation> observations = rasp::android::checks::root();
  std::ranges::move(rasp::android::checks::debugger(), std::back_inserter(observations));
  log_observations(observations);

  const std::optional<std::string> apk = rasp::android::apk::self_apk_path();
  const std::optional<std::string> library_dir = rasp::android::apk::self_library_dir();
  if (!apk.has_value() || !library_dir.has_value()) {
    log_line("could not locate the app");
    return;
  }
  std::optional<std::vector<rasp::android::payload::Dex>> dexes = recover_dexes(*apk);
  if (!dexes.has_value()) {
    log_line("could not recover the app");
    return;
  }
  pending().dexes = std::move(dexes);
  pending().library_dir = *library_dir;
}

}  // namespace

/// Publishes the class loader over the dex files the constructor decrypted, into the stub's field, so Android runs the
/// app's own code. It runs while the platform is still loading the library, in the class-loader context that lets
/// `FindClass` resolve the stub. When the constructor recovered nothing, or the loader can't be built, it leaves the
/// field unset and the stub refuses to start the app. This is the library's only exported symbol.
///
/// @param vm The Java virtual machine loading the library.
/// @return The JNI version the library needs.
extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* /*reserved*/) {
  void* raw_env = nullptr;
  if (vm->GetEnv(&raw_env, JNI_VERSION_1_6) != JNI_OK) {
    return JNI_VERSION_1_6;
  }
  auto* env = static_cast<JNIEnv*>(raw_env);
  Pending& state = pending();
  if (state.dexes.has_value()) {
    if (rasp::android::loader::publish(env, *state.dexes, state.library_dir)) {
      log_line("app class loader ready");
    } else {
      log_line("could not build the class loader");
    }
    state.dexes.reset();
  }
  return JNI_VERSION_1_6;
}
