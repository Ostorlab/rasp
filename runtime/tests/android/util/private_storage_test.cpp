/// VM attachment failures at the JNI boundary; successful Android/File behavior is checked separately on a real JVM.
#include "rasp/private_storage.h"

#include <cstdint>
#include <gtest/gtest.h>
#include <jni.h>
#include <jni_md.h>

namespace {
/// Distinct failures that a real JVM cannot safely be forced to trigger on demand.
enum class VmFault : std::uint8_t {
  kNoVm,
  kEnumeration,
  kNullVm,
  kMultipleVms,
  kGetEnv,
  kAttach,
  kNullAttachedEnv,
  kNullExistingEnv,
  kFrame,
  kDetach,
};
struct VmState {
  VmFault fault = VmFault::kNoVm;
  int attaches = 0;
  int detaches = 0;
  int pops = 0;
};
/// Isolates the fake outside-world state to the current native test thread.
VmState& state() {
  thread_local VmState value;
  return value;
}
/// Fake errors never leave pending exceptions in this minimal VM boundary fixture.
jboolean exception_check(JNIEnv* /*env*/) { return JNI_FALSE; }
/// Models local-frame exhaustion or a real frame with no references.
jint push_frame(JNIEnv* /*env*/, jint /*capacity*/) { return state().fault == VmFault::kFrame ? JNI_ERR : JNI_OK; }
/// Counts required frame cleanup when storage has no supported Application yet.
jobject pop_frame(JNIEnv* /*env*/, jobject /*result*/) {
  ++state().pops;
  return nullptr;
}
/// Builds only the VM environment operations reached before a retained Application exists.
JNIEnv* fixture_env() {
  thread_local JNINativeInterface_ table{};
  table.ExceptionCheck = exception_check;
  table.PushLocalFrame = push_frame;
  table.PopLocalFrame = pop_frame;
  thread_local JNIEnv_ environment{&table};
  return &environment;
}
/// Distinguishes an unavailable VM version, missing existing env, and a detached native worker.
jint get_env(JavaVM* /*vm*/, void** env, jint /*version*/) {
  *env = nullptr;
  if (state().fault == VmFault::kGetEnv) {
    return JNI_EVERSION;
  }
  if (state().fault == VmFault::kNullExistingEnv) {
    return JNI_OK;
  }
  return JNI_EDETACHED;
}
/// Models failed or null worker attachment and otherwise supplies the bounded fixture environment.
jint attach(JavaVM* /*vm*/, void** env, void* /*args*/) {
  ++state().attaches;
  *env = nullptr;
  if (state().fault == VmFault::kAttach) {
    return JNI_ERR;
  }
  if (state().fault != VmFault::kNullAttachedEnv) {
    *env = fixture_env();
  }
  return JNI_OK;
}
/// Counts release ownership and makes detach failure explicit.
jint detach(JavaVM* /*vm*/) {
  ++state().detaches;
  return state().fault == VmFault::kDetach ? JNI_ERR : JNI_OK;
}
/// Models a single VM invocation table, never replacing the storage algorithm or Application bridge.
JavaVM* fixture_vm() {
  thread_local JNIInvokeInterface_ table{};
  table.GetEnv = get_env;
  table.AttachCurrentThread = attach;
  table.DetachCurrentThread = detach;
  thread_local JavaVM_ vm{&table};
  return &vm;
}
}  // namespace

/// Substitutes only the JNI VM enumeration boundary for this dedicated native test executable.
/// Darwin assembly labels include the C ABI underscore; this fixture must match the actual JNI call reference.
#ifdef __APPLE__
extern "C" jint enumerate_vms(JavaVM** /*vm*/, jsize /*unused*/, jsize* /*count*/) __asm__("_JNI_GetCreatedJavaVMs");
#else
extern "C" jint enumerate_vms(JavaVM** /*vm*/, jsize /*unused*/, jsize* /*count*/) __asm__("JNI_GetCreatedJavaVMs");
#endif
extern "C" jint enumerate_vms(JavaVM** vm, jsize /*capacity*/, jsize* count) {
  *vm = state().fault == VmFault::kNullVm ? nullptr : fixture_vm();
  *count = 1;
  if (state().fault == VmFault::kNoVm) {
    *count = 0;
  }
  if (state().fault == VmFault::kMultipleVms) {
    *count = 2;
  }
  return state().fault == VmFault::kEnumeration ? JNI_ERR : JNI_OK;
}

namespace rasp {
namespace {
/// Checks one failed outside-world VM boundary with the expected attachment lifetime.
void check_vm_fault(VmFault fault) {
  state() = VmState{.fault = fault};
  const auto storage = acquire_private_storage();
  ASSERT_FALSE(storage.has_value());
  EXPECT_EQ(storage.error(), StorageError::kUnavailable);
  if (fault == VmFault::kFrame || fault == VmFault::kDetach || fault == VmFault::kNullAttachedEnv) {
    EXPECT_EQ(state().attaches, 1);
    EXPECT_EQ(state().detaches, 1);
  }
}

TEST(AndroidPrivateStorageVm, acquire_whenVmOrWorkerAttachmentFails_returnsUnavailableAndReleasesOwnedAttachment) {
  for (const VmFault fault : {
           VmFault::kNoVm,
           VmFault::kEnumeration,
           VmFault::kNullVm,
           VmFault::kMultipleVms,
           VmFault::kGetEnv,
           VmFault::kAttach,
           VmFault::kNullAttachedEnv,
           VmFault::kNullExistingEnv,
           VmFault::kFrame,
           VmFault::kDetach,
       }) {
    check_vm_fault(fault);
  }
}
}  // namespace
}  // namespace rasp
