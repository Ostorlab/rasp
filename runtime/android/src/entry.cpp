/// The entry point of librasp.so. The stub, co.ostorlab.rasp.RaspStub, calls it through JNI when the app starts,
/// before the app's own code is loaded.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <jni.h>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "checks/example.h"
#include "payload/payload.h"
#include "rasp/observation.h"
#include "rasp/util/logging.h"
#include "rasp/version.h"

namespace {

/// Copies the bytes of a Java byte array, or gives nothing when the JVM can't give access to them.
[[nodiscard]] std::optional<std::vector<std::uint8_t>> read_bytes(JNIEnv* env, jbyteArray array) {
  std::vector<std::uint8_t> copy(static_cast<std::size_t>(env->GetArrayLength(array)));
  void* const elements = env->GetPrimitiveArrayCritical(array, nullptr);
  if (elements == nullptr) {
    return std::nullopt;
  }
  std::ranges::copy(std::span(static_cast<const std::uint8_t*>(elements), copy.size()), copy.begin());
  env->ReleasePrimitiveArrayCritical(array, elements, JNI_ABORT);
  return copy;
}

/// Makes a Java byte array that holds `data`, or gives null when the JVM can't allocate it.
[[nodiscard]] jbyteArray to_java_bytes(JNIEnv* env, std::span<const std::uint8_t> data) {
  jbyteArray array = env->NewByteArray(static_cast<jsize>(data.size()));
  if (array == nullptr) {
    return nullptr;
  }
  void* const elements = env->GetPrimitiveArrayCritical(array, nullptr);
  if (elements == nullptr) {
    env->DeleteLocalRef(array);
    return nullptr;
  }
  std::ranges::copy(data, static_cast<std::uint8_t*>(elements));
  env->ReleasePrimitiveArrayCritical(array, elements, 0);
  return array;
}

/// Makes a Java array that holds the bytes of each dex file, in order, or gives null when the JVM can't allocate it.
[[nodiscard]] jobjectArray to_java_dexes(JNIEnv* env, const std::vector<rasp::android::payload::Dex>& dexes) {
  jclass byte_array_class = env->FindClass("[B");
  if (byte_array_class == nullptr) {
    return nullptr;
  }
  jobjectArray result = env->NewObjectArray(static_cast<jsize>(dexes.size()), byte_array_class, nullptr);
  if (result == nullptr) {
    return nullptr;
  }
  jsize index = 0;
  for (const rasp::android::payload::Dex& dex : dexes) {
    jbyteArray buffer = to_java_bytes(env, dex.data);
    if (buffer == nullptr) {
      return nullptr;
    }
    env->SetObjectArrayElement(result, index, buffer);
    env->DeleteLocalRef(buffer);
    ++index;
  }
  return result;
}

}  // namespace

/// Runs the checks, then recovers the app's dex files from the payload for the stub to load.
///
/// In a development build, it also logs the runtime version and each observation. The dex files are decrypted in
/// memory and never written to disk. When it returns null, the JVM may have a pending exception, such as an
/// OutOfMemoryError.
///
/// @param env The JNI environment of the calling thread.
/// @param stub_class The RaspStub class, which JNI passes to a static native method. It is not used.
/// @param key The payload key, from the app's `assets/rasp/config.json`.
/// @param payload The packed payload, the app's `assets/rasp/payload.bin`.
/// @return The bytes of each dex file, in load order. Null when `key` or `payload` is null, when the payload can't be
/// decrypted or read (see rasp::android::payload::unpack), or when the JVM can't allocate the arrays.
extern "C" JNIEXPORT jobjectArray JNICALL Java_co_ostorlab_rasp_RaspStub_raspStart(JNIEnv* env,
                                                                                   [[maybe_unused]] jclass stub_class,
                                                                                   jbyteArray key, jbyteArray payload) {
  const std::vector<rasp::Observation> observations = rasp::android::checks::example();
  if constexpr (rasp::kLoggingEnabled) {
    rasp::log(std::string(rasp::kRuntimeVersion) + " loaded");
    for (const rasp::Observation& observation : observations) {
      rasp::log(rasp::describe(observation));
    }
  }

  if (key == nullptr || payload == nullptr) {
    return nullptr;
  }
  const std::optional<std::vector<std::uint8_t>> key_bytes = read_bytes(env, key);
  if (!key_bytes) {
    return nullptr;
  }
  const std::optional<std::vector<std::uint8_t>> payload_bytes = read_bytes(env, payload);
  if (!payload_bytes) {
    return nullptr;
  }
  const std::optional<std::vector<rasp::android::payload::Dex>> dexes =
      rasp::android::payload::unpack(*key_bytes, *payload_bytes);
  if (!dexes) {
    return nullptr;
  }
  return to_java_dexes(env, *dexes);
}
