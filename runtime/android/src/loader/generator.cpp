/// The native dex generator: parses the packer's map, reads the encrypted dex from the APK, decrypts it, and builds the
/// GeneratedDex the Java loader needs. The map, the key, the read, and the decrypt all stay in native code; Java only
/// declares the native method and wraps the result.

#include "loader/generator.h"

#include <jni.h>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

#include "apk/archive.h"
#include "apk/location.h"
#include "payload/cipher.h"

namespace rasp::android::loader {

namespace {

/// The APK asset holding the key, and the prefix the business dexes live under.
constexpr const char* kKeyEntry = "assets/rasp/key.bin";
constexpr const char* kAssetPrefix = "assets/";

/// The class-to-dex map lives in this binary, not in a readable asset. The packer overwrites the region below with an
/// 8-byte magic, a 32-bit little-endian length, then that many bytes of map text (`binary.class.Name,business/<i>.dex`
/// per line). The region is a fixed reserve; a map larger than it needs a bigger reserve (or an append scheme).
constexpr std::size_t kMapCapacity = 1U << 20;
constexpr std::size_t kMapMagicSize = 8;
constexpr std::size_t kMapHeaderSize = kMapMagicSize + 4;
constexpr unsigned char kMapMagic[kMapMagicSize] = {'R', 'A', 'S', 'P', 'M', 'A', 'P', '1'};

/// The reserved region. Volatile so the compiler reads it at run time rather than assuming its built-in (empty)
/// contents, and used so it is kept even though this code only reads it.
// NOLINTNEXTLINE(cppcoreguidelines-avoid-c-arrays,cppcoreguidelines-avoid-non-const-global-variables,modernize-avoid-c-arrays)
__attribute__((section(".raspmap"), used)) volatile unsigned char g_rasp_map[kMapCapacity] = {
    'R', 'A', 'S', 'P', 'M', 'A', 'P', '1'};

/// Reads the class map the packer wrote into g_rasp_map, or nothing when it is absent or malformed.
[[nodiscard]] std::optional<std::vector<std::uint8_t>> read_embedded_map() {
  for (std::size_t i = 0; i < kMapMagicSize; ++i) {
    if (g_rasp_map[i] != kMapMagic[i]) {
      return std::nullopt;
    }
  }
  std::uint32_t length = 0;
  for (std::size_t i = 0; i < 4; ++i) {
    length |= static_cast<std::uint32_t>(g_rasp_map[kMapMagicSize + i]) << (8U * i);
  }
  if (length == 0 || length > kMapCapacity - kMapHeaderSize) {
    return std::nullopt;
  }
  std::vector<std::uint8_t> map(length);
  for (std::uint32_t i = 0; i < length; ++i) {
    map[i] = g_rasp_map[kMapHeaderSize + i];
  }
  return map;
}

/// The classes (nested class included) the generator builds, and their JNI signatures.
constexpr const char* kGeneratedDexClass = "co/ostorlab/rasp/GeneratingClassLoader$GeneratedDex";
constexpr const char* kGeneratedDexSignature = "([BLjava/util/Set;)V";
constexpr const char* kHashSetClass = "java/util/HashSet";
constexpr const char* kAddName = "add";
constexpr const char* kAddSignature = "(Ljava/lang/Object;)Z";

/// The map, key, and APK path the generator needs, read once from the app's own APK.
struct State {
  std::string apk;
  std::vector<std::uint8_t> key;
  std::unordered_map<std::string, std::string> class_to_file;
  std::unordered_map<std::string, std::vector<std::string>> file_to_classes;
  bool ok = false;
};

/// Parses the packer's map (one `binary.class.Name,business/<i>.dex` per line) into both lookup directions.
void parse_map(std::string_view text, State& state) {
  std::size_t start = 0;
  while (start < text.size()) {
    std::size_t end = text.find('\n', start);
    if (end == std::string_view::npos) {
      end = text.size();
    }
    const std::string_view line = text.substr(start, end - start);
    start = end + 1;
    const std::size_t comma = line.find(',');
    if (comma == std::string_view::npos || comma == 0) {
      continue;
    }
    std::string name(line.substr(0, comma));
    std::string file(line.substr(comma + 1));
    state.file_to_classes[file].push_back(name);
    state.class_to_file.emplace(std::move(name), std::move(file));
  }
}

/// Reads the key and map from the app's APK and parses the map. On any failure, leaves `ok` false.
[[nodiscard]] State* build_state() {
  // NOLINTNEXTLINE(cppcoreguidelines-owning-memory)
  auto* state = new State();
  const std::optional<std::string> apk = rasp::android::apk::self_apk_path();
  if (!apk.has_value()) {
    return state;
  }
  state->apk = *apk;
  const std::optional<std::vector<std::uint8_t>> key = rasp::android::apk::read_stored_entry(*apk, kKeyEntry);
  const std::optional<std::vector<std::uint8_t>> map = read_embedded_map();
  if (!key.has_value() || !map.has_value()) {
    return state;
  }
  state->key = *key;
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
  parse_map(std::string_view(reinterpret_cast<const char*>(map->data()), map->size()), *state);
  state->ok = true;
  return state;
}

/// The generator's state, built on first use and never destroyed, so there is no exit-time destructor.
[[nodiscard]] State& state() {
  static State* const kState = build_state();
  return *kState;
}

/// Makes a Java byte array holding `data`, or null (with no pending exception) when the JVM can't allocate it.
[[nodiscard]] jbyteArray to_java_bytes(JNIEnv* env, const std::vector<std::uint8_t>& data) {
  jbyteArray array = env->NewByteArray(static_cast<jsize>(data.size()));
  if (array == nullptr) {
    env->ExceptionClear();
    return nullptr;
  }
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
  env->SetByteArrayRegion(array, 0, static_cast<jsize>(data.size()), reinterpret_cast<const jbyte*>(data.data()));
  return array;
}

/// Makes a `java.util.Set<String>` holding each name, or null when a JNI call fails.
[[nodiscard]] jobject to_java_set(JNIEnv* env, const std::vector<std::string>& names) {
  jclass set_class = env->FindClass(kHashSetClass);
  if (set_class == nullptr) {
    env->ExceptionClear();
    return nullptr;
  }
  jmethodID constructor = env->GetMethodID(set_class, "<init>", "()V");
  jmethodID add = env->GetMethodID(set_class, kAddName, kAddSignature);
  if (constructor == nullptr || add == nullptr) {
    env->ExceptionClear();
    return nullptr;
  }
  jobject set = env->NewObject(set_class, constructor);
  if (set == nullptr) {
    env->ExceptionClear();
    return nullptr;
  }
  for (const std::string& name : names) {
    jstring element = env->NewStringUTF(name.c_str());
    if (element == nullptr) {
      env->ExceptionClear();
      return nullptr;
    }
    env->CallBooleanMethod(set, add, element);
    env->DeleteLocalRef(element);
  }
  return set;
}

/// Builds a `GeneratingClassLoader.GeneratedDex` from the decrypted dex, or null when a JNI call fails.
[[nodiscard]] jobject to_generated_dex(JNIEnv* env, const GeneratedDex& dex) {
  jbyteArray bytes = to_java_bytes(env, dex.bytes);
  if (bytes == nullptr) {
    return nullptr;
  }
  jobject names = to_java_set(env, dex.class_names);
  if (names == nullptr) {
    return nullptr;
  }
  jclass generated = env->FindClass(kGeneratedDexClass);
  if (generated == nullptr) {
    env->ExceptionClear();
    return nullptr;
  }
  jmethodID constructor = env->GetMethodID(generated, "<init>", kGeneratedDexSignature);
  if (constructor == nullptr) {
    env->ExceptionClear();
    return nullptr;
  }
  return env->NewObject(generated, constructor, bytes, names);
}

/// The native method bound to GeneratingClassLoader.generate. Not an exported symbol: RegisterNatives binds it by
/// pointer, so its name does not matter and the library's symbols can be stripped or renamed.
[[nodiscard]] jobject generate_jni(JNIEnv* env, jobject /*thiz*/, jstring class_name) {
  if (class_name == nullptr) {
    return nullptr;
  }
  const char* chars = env->GetStringUTFChars(class_name, nullptr);
  if (chars == nullptr) {
    return nullptr;
  }
  const std::optional<GeneratedDex> dex = generate(chars);
  env->ReleaseStringUTFChars(class_name, chars);
  if (!dex.has_value()) {
    return nullptr;
  }
  return to_generated_dex(env, *dex);
}

}  // namespace

std::optional<GeneratedDex> generate(std::string_view class_name) {
  State& current = state();
  if (!current.ok) {
    return std::nullopt;
  }
  const auto entry = current.class_to_file.find(std::string(class_name));
  if (entry == current.class_to_file.end()) {
    return std::nullopt;
  }
  const std::string& file = entry->second;
  const std::optional<std::vector<std::uint8_t>> frame =
      rasp::android::apk::read_stored_entry(current.apk, std::string(kAssetPrefix) + file);
  if (!frame.has_value()) {
    return std::nullopt;
  }
  const std::optional<std::vector<std::uint8_t>> dex = rasp::android::payload::decrypt(current.key, *frame);
  if (!dex.has_value()) {
    return std::nullopt;
  }
  return GeneratedDex{.bytes = *dex, .class_names = current.file_to_classes.at(file)};
}

}  // namespace rasp::android::loader

/// Binds GeneratingClassLoader.generate to the native generator with RegisterNatives when the library loads, so the
/// generator is not an exported `Java_...` symbol and the library's symbols can be stripped or renamed. JNI_OnLoad is
/// the only symbol the VM resolves by name.
///
/// @param vm The Java virtual machine loading the library.
/// @return The JNI version the library needs, or JNI_ERR when the method can't be bound.
extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* /*reserved*/) {
  void* raw_env = nullptr;
  if (vm->GetEnv(&raw_env, JNI_VERSION_1_6) != JNI_OK) {
    return JNI_ERR;
  }
  auto* env = static_cast<JNIEnv*>(raw_env);
  jclass loader = env->FindClass("co/ostorlab/rasp/GeneratingClassLoader");
  if (loader == nullptr) {
    env->ExceptionClear();
    return JNI_ERR;
  }
  const JNINativeMethod method = {
      .name = "generate",
      .signature = "(Ljava/lang/String;)Lco/ostorlab/rasp/GeneratingClassLoader$GeneratedDex;",
      // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
      .fnPtr = reinterpret_cast<void*>(&rasp::android::loader::generate_jni),
  };
  const jint registered = env->RegisterNatives(loader, &method, 1);
  env->DeleteLocalRef(loader);
  if (registered != JNI_OK) {
    env->ExceptionClear();
    return JNI_ERR;
  }
  return JNI_VERSION_1_6;
}
