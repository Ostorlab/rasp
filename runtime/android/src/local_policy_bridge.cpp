/// Bounded JNI copies into the same approved C facade; Java receives owned primitive bytes.
#include "local_policy_bridge.h"

#include <array>
#include <atomic>
#include <cstddef>
#include <jni.h>
#include <memory>
#include <span>
#include <utility>
#ifndef __ANDROID__
#include <jni_md.h>
#endif

#include "rasp/local_policy_host.h"
#include "util/jni.h"

namespace rasp::android {
namespace {
/// Binding health does not imply policy or snapshot availability.
std::atomic<bool>& binding() {
  static constinit std::atomic<bool> ready{false};
  return ready;
}
/// Length-check UTF-16 before bounded copying; no unbounded GetStringUTFChars allocation.
bool copy_string(JNIEnv* env, jstring value, std::span<char> output) {
  if (value == nullptr) {
    return false;
  }
  const jsize length = env->GetStringLength(value);
  if (util::threw(env) || length <= 0 || length > 64 || std::cmp_greater_equal(length, output.size())) {
    return false;
  }
  std::array<jchar, 65> characters{};
  env->GetStringRegion(value, 0, length, characters.data());
  if (util::threw(env)) {
    return false;
  }
  for (std::size_t index = 0; std::cmp_less(index, length); ++index) {
    if (std::span(characters)[index] == 0 || std::span(characters)[index] > 127) {
      return false;
    }
    std::span{output}[index] = static_cast<char>(std::span(characters)[index]);
  }
  return true;
}
/// Copy a trivially owned C result, including zeroed padding; Android ABI is little-endian.
template <typename Result>
jbyteArray bytes(JNIEnv* env, const Result& result) {
  static_assert(sizeof(Result) <= 7168);
  jbyteArray output = env->NewByteArray(static_cast<jsize>(sizeof(result)));
  if (util::threw(env) || output == nullptr) {
    return nullptr;
  }
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): fixed primitive ABI copy into an owned Java byte array.
  env->SetByteArrayRegion(output, 0, static_cast<jsize>(sizeof(result)), reinterpret_cast<const jbyte*>(&result));
  if (util::threw(env)) {
    env->DeleteLocalRef(output);
    return nullptr;
  }
  return output;
}
/// Query actual worker config through the shipping primitive API.
jbyteArray info(JNIEnv* env, jclass /*unused*/) {
  if (!binding().load(std::memory_order_acquire)) {
    return nullptr;
  }
  const auto result = std::make_unique<struct RaspLocalPolicyInfoV1>();
  static_cast<void>(rasp_local_policy_info_v1(result.get(), sizeof(*result)));
  return bytes(env, *result);
}
/// No Java caller can supply a typed report, clock, action override or policy setter.
jbyteArray gate(JNIEnv* env, jclass /*unused*/, jstring operation, jstring expected_hash) {
  if (!binding().load(std::memory_order_acquire)) {
    return nullptr;
  }
  struct RaspLocalGateRequestV1 request{};
  request.abi_version = 1;
  request.struct_size = sizeof(request);
  if (!copy_string(env, operation, request.operation) ||
      !copy_string(env, expected_hash, request.expected_policy_sha256)) {
    return nullptr;
  }
  const auto result = std::make_unique<struct RaspLocalGateResultV1>();
  static_cast<void>(rasp_local_policy_gate_v1(&request, sizeof(request), result.get(), sizeof(*result)));
  return bytes(env, *result);
}
}  // namespace

bool register_local_policy_bridge(JNIEnv* env) {
  binding().store(false, std::memory_order_release);
  jclass bridge = env->FindClass("co/ostorlab/rasp/RuntimeBridge");
  bool failed = util::threw(env) || bridge == nullptr;
  auto info_name = std::to_array("localPolicyInfoNative");
  auto info_signature = std::to_array("()[B");
  auto gate_name = std::to_array("gateLocalOperationNative");
  auto gate_signature = std::to_array("(Ljava/lang/String;Ljava/lang/String;)[B");
  const std::array methods{
      JNINativeMethod{
          .name = info_name.data(),
          .signature = info_signature.data(),
          // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): JNI RegisterNatives requires this ABI function pointer conversion.
          .fnPtr = reinterpret_cast<void*>(&info),
      },
      JNINativeMethod{
          .name = gate_name.data(),
          .signature = gate_signature.data(),
          // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): JNI RegisterNatives requires this ABI function pointer conversion.
          .fnPtr = reinterpret_cast<void*>(&gate),
      },
  };
  if (!failed) {
    const auto status = env->RegisterNatives(bridge, methods.data(), static_cast<jint>(methods.size()));
    failed = util::threw(env) || status != JNI_OK;
  }
  if (bridge != nullptr) {
    env->DeleteLocalRef(bridge);
  }
  binding().store(!failed, std::memory_order_release);
  return !failed;
}
}  // namespace rasp::android
