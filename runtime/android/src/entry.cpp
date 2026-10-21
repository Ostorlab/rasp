/// The native surface for the on-demand loader: one method that decrypts a single business dex frame.
///
/// The Java loader reads an encrypted business dex from the APK and calls this to get its plaintext bytes. The key is
/// read from the APK here, so it never passes through Java.

#include <jni.h>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "apk/archive.h"
#include "apk/location.h"
#include "payload/cipher.h"

namespace {

/// The APK asset that holds the payload key.
constexpr const char* kKeyEntry = "assets/rasp/key.bin";

/// Reads the payload key from the app's own APK, or nothing when it can't be found.
[[nodiscard]] std::optional<std::vector<std::uint8_t>> read_key() {
  const std::optional<std::string> apk = rasp::android::apk::self_apk_path();
  if (!apk.has_value()) {
    return std::nullopt;
  }
  return rasp::android::apk::read_stored_entry(*apk, kKeyEntry);
}

}  // namespace

/// Decrypts one business dex frame for the Java loader. The frame is one ChaCha20-Poly1305 frame the packer wrote.
///
/// @param env The JNI environment of the calling thread.
/// @param frame The encrypted business dex frame.
/// @return The decrypted dex bytes, or null when the key can't be read or the frame can't be decrypted.
extern "C" JNIEXPORT jbyteArray JNICALL Java_co_ostorlab_rasp_Native_decrypt(JNIEnv* env, jclass /*clazz*/,
                                                                             jbyteArray frame) {
  if (frame == nullptr) {
    return nullptr;
  }
  const std::optional<std::vector<std::uint8_t>> key = read_key();
  if (!key.has_value()) {
    return nullptr;
  }
  const jsize length = env->GetArrayLength(frame);
  std::vector<std::uint8_t> frame_bytes(static_cast<std::size_t>(length));
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
  env->GetByteArrayRegion(frame, 0, length, reinterpret_cast<jbyte*>(frame_bytes.data()));
  const std::optional<std::vector<std::uint8_t>> plaintext = rasp::android::payload::decrypt(*key, frame_bytes);
  if (!plaintext.has_value()) {
    return nullptr;
  }
  jbyteArray result = env->NewByteArray(static_cast<jsize>(plaintext->size()));
  if (result == nullptr) {
    env->ExceptionClear();
    return nullptr;
  }
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
  env->SetByteArrayRegion(result, 0, static_cast<jsize>(plaintext->size()),
                          reinterpret_cast<const jbyte*>(plaintext->data()));
  return result;
}
