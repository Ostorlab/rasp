/// Sanitizer-friendly JNI boundary fixture testing the production singleton's ownership and concurrent publication.

#include "util/application_context.h"

#include <array>
#include <atomic>
#include <gtest/gtest.h>
#include <jni.h>
#include <jni_md.h>
#include <thread>

/// Completes JNI's opaque method handle for this boundary fixture; production never dereferences it.
struct _jmethodID {};

namespace {

/// Fake VM reference tables and Context responses; the Context store itself is the production implementation.
struct Boundary {
  _jobject application;
  _jclass type;
  _jmethodID method;
  std::atomic<int> globals{0};
  std::atomic<int> locals{0};
  bool null_application = false;
  bool is_application = true;
  bool fail_global = false;
  bool fail_local = false;
  bool pending_exception = false;
};

/// Returns the fixture state, which outlives the production process-lifetime reference.
Boundary& boundary() {
  static Boundary instance;
  return instance;
}

/// Models local frame allocation without a running Java heap.
jint push_frame(JNIEnv* /*env*/, jint /*capacity*/) { return JNI_OK; }
/// Models local frame release.
jobject pop_frame(JNIEnv* /*env*/, jobject result) { return result; }
/// Models a boot-class lookup.
jclass find_class(JNIEnv* /*env*/, const char* /*name*/) { return &boundary().type; }
/// Models resolution of getApplicationContext.
jmethodID method(JNIEnv* /*env*/, jclass /*type*/, const char* /*name*/, const char* /*signature*/) {
  return &boundary().method;
}
/// Models normalization to the Application.
jobject call(JNIEnv* /*env*/, jobject /*object*/, jmethodID /*method*/, const jvalue* /*arguments*/) {
  return boundary().null_application ? nullptr : &boundary().application;
}
/// Models the Application type check.
jboolean is_application(JNIEnv* /*env*/, jobject /*object*/, jclass /*type*/) {
  return boundary().is_application ? JNI_TRUE : JNI_FALSE;
}
/// Allocates a tracked global reference, or injects VM allocation failure.
jobject global_ref(JNIEnv* /*env*/, jobject object) {
  if (boundary().fail_global) {
    boundary().pending_exception = true;
    return nullptr;
  }
  boundary().globals.fetch_add(1);
  return object;
}
/// Releases a losing initializer's candidate reference.
void delete_global(JNIEnv* /*env*/, jobject /*object*/) { boundary().globals.fetch_sub(1); }
/// Creates a tracked, thread-owned local reference.
jobject local_ref(JNIEnv* /*env*/, jobject object) {
  if (boundary().fail_local) {
    boundary().pending_exception = true;
    return nullptr;
  }
  boundary().locals.fetch_add(1);
  return object;
}
/// Releases a reader's local reference.
void delete_local(JNIEnv* /*env*/, jobject /*object*/) { boundary().locals.fetch_sub(1); }
/// Models the VM's object identity comparison.
jboolean same_object(JNIEnv* /*env*/, jobject left, jobject right) { return left == right ? JNI_TRUE : JNI_FALSE; }
/// Models the VM's pending exception state.
jboolean exception_check(JNIEnv* /*env*/) { return boundary().pending_exception ? JNI_TRUE : JNI_FALSE; }
/// Models clearing a JNI failure before returning to the host.
void exception_clear(JNIEnv* /*env*/) { boundary().pending_exception = false; }

/// Builds only the JNI operations this production accessor uses.
JNINativeInterface_ make_table() {
  JNINativeInterface_ table{};
  table.PushLocalFrame = push_frame;
  table.PopLocalFrame = pop_frame;
  table.FindClass = find_class;
  table.GetMethodID = method;
  table.CallObjectMethodA = call;
  table.IsInstanceOf = is_application;
  table.NewGlobalRef = global_ref;
  table.DeleteGlobalRef = delete_global;
  table.NewLocalRef = local_ref;
  table.DeleteLocalRef = delete_local;
  table.IsSameObject = same_object;
  table.ExceptionCheck = exception_check;
  table.ExceptionClear = exception_clear;
  return table;
}

/// Invalid inputs never publish a global reference.
void check_invalid_inputs(JNIEnv* env, jobject application) {
  using rasp::android::util::ContextInitResult;
  EXPECT_EQ(rasp::android::util::initialize_application_context(env, nullptr), ContextInitResult::kInvalidContext);
  boundary().null_application = true;
  EXPECT_EQ(rasp::android::util::initialize_application_context(env, application), ContextInitResult::kInvalidContext);
  boundary().null_application = false;
  boundary().is_application = false;
  EXPECT_EQ(rasp::android::util::initialize_application_context(env, application), ContextInitResult::kInvalidContext);
  boundary().is_application = true;
}

/// Allocation failures are cleared without publishing state.
void check_allocation_failure(JNIEnv* env, jobject application) {
  using rasp::android::util::ContextInitResult;
  boundary().fail_global = true;
  EXPECT_EQ(rasp::android::util::initialize_application_context(env, application), ContextInitResult::kJniError);
  EXPECT_FALSE(boundary().pending_exception);
  EXPECT_EQ(boundary().globals.load(), 0);
  boundary().fail_global = false;
}

/// Repeatedly initializes and releases each reader's own local reference.
void run_reader(const JNINativeInterface_& table, std::atomic<int>& initializers, jobject application) {
  using rasp::android::util::ContextInitResult;
  JNIEnv thread_env{.functions = &table};
  for (int pass = 0; pass < 1000; ++pass) {
    const auto result = rasp::android::util::initialize_application_context(&thread_env, application);
    if (result == ContextInitResult::kInitialized) {
      initializers.fetch_add(1);
    } else {
      EXPECT_EQ(result, ContextInitResult::kAlreadyInitialized);
    }
    const auto context = rasp::android::util::application_context(&thread_env);
    ASSERT_TRUE(context.has_value());
    EXPECT_EQ(*context, application);
    thread_env.DeleteLocalRef(*context);
  }
}

/// The process-lifetime reference is unique and readers leave no outstanding local references.
void check_final_references(JNIEnv* env) {
  EXPECT_EQ(boundary().globals.load(), 1);
  EXPECT_EQ(boundary().locals.load(), 0);
  boundary().fail_local = true;
  EXPECT_FALSE(rasp::android::util::application_context(env).has_value());
  EXPECT_FALSE(boundary().pending_exception);
  boundary().fail_local = false;
}

TEST(ApplicationContext, initialize_whenConcurrentWithReaders_retainsOneGlobalAndReleasesLocals) {
  const auto table = make_table();
  JNIEnv env{.functions = &table};
  jobject application = &boundary().application;
  check_invalid_inputs(&env, application);
  check_allocation_failure(&env, application);
  std::atomic<int> initializers{0};
  std::array<std::thread, 8> threads;
  for (auto& thread : threads) {
    thread = std::thread([&table, &initializers, application] { run_reader(table, initializers, application); });
  }
  for (auto& thread : threads) {
    thread.join();
  }
  EXPECT_EQ(initializers.load(), 1);
  check_final_references(&env);
}

}  // namespace
