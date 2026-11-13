/// JNI error-boundary tests run under sanitizers without loading a Java VM.
#include <cstdint>
#include <gtest/gtest.h>
#include <jni.h>
#include <jni_md.h>
#include <string>

#include "checks/loader_provenance.h"
#include "rasp/observation.h"

namespace {
/// Owns one test-call JNI function table and cleanup counters.
struct State {
  bool exception = false;
  bool push_failure = false;
  bool pop_failure = false;
  int frames = 0;
  int pops = 0;
  int clears = 0;
  std::int64_t time = 0;
};
State& state() {
  static State value;
  return value;
}
jboolean exception_check(JNIEnv* /*env*/) { return state().exception ? JNI_TRUE : JNI_FALSE; }
void clear(JNIEnv* /*env*/) {
  state().exception = false;
  ++state().clears;
}
jint push(JNIEnv* /*env*/, jint /*capacity*/) {
  if (state().push_failure) {
    state().exception = true;
    return -1;
  }
  ++state().frames;
  return 0;
}
jobject pop(JNIEnv* /*env*/, jobject /*object*/) {
  --state().frames;
  ++state().pops;
  state().exception = state().pop_failure;
  return nullptr;
}
jclass object_class(JNIEnv* /*env*/, jobject /*object*/) {
  state().exception = true;
  return nullptr;
}
std::int64_t advancing_clock() {
  const auto current = state().time;
  state().time += 100000000;
  return current;
}
std::int64_t invalid_clock() { return -1; }
class LoaderBoundaryTest : public testing::Test {
 protected:
  void SetUp() override {
    state() = {};
    functions_.ExceptionCheck = exception_check;
    functions_.ExceptionClear = clear;
    functions_.PushLocalFrame = push;
    functions_.PopLocalFrame = pop;
    functions_.GetObjectClass = object_class;
    env_.functions = &functions_;
  }
  JNIEnv* env() { return &env_; }
  jobject application() { return &application_; }

 private:
  JNINativeInterface_ functions_{};
  JNIEnv env_{};
  _jobject application_{};
};
TEST_F(LoaderBoundaryTest, probeException_whenRepeated_releasesFramesAndClearsOnlyProbeExceptions) {
  for (int index = 0; index < 1000; ++index) {
    const auto rows = rasp::android::checks::read_loader_provenance(env(), application());
    ASSERT_EQ(rows[0].status, rasp::Status::kError);
    ASSERT_FALSE(state().exception);
    ASSERT_EQ(state().frames, 0);
  }
  EXPECT_EQ(state().pops, 1000);
  EXPECT_EQ(state().clears, 1000);
}
TEST_F(LoaderBoundaryTest, frameAllocationFailure_whenExceptionRaised_clearsItWithoutPoppingAbsentFrame) {
  state().push_failure = true;
  const auto rows = rasp::android::checks::read_loader_provenance(env(), application());
  EXPECT_EQ(rows[0].status, rasp::Status::kError);
  EXPECT_FALSE(state().exception);
  EXPECT_EQ(state().pops, 0);
}
TEST_F(LoaderBoundaryTest, cleanupFailure_whenPopRaisesException_returnsCleanupError) {
  state().pop_failure = true;
  const auto rows = rasp::android::checks::read_loader_provenance(env(), application());
  EXPECT_NE(rasp::describe(rows[1]).find("reason=cleanup"), std::string::npos);
  EXPECT_FALSE(state().exception);
  EXPECT_EQ(state().frames, 0);
}
TEST_F(LoaderBoundaryTest, invalidClock_whenBeforeFrameAllocation_returnsUnknownWithoutJNIWork) {
  const auto rows = rasp::android::checks::read_loader_provenance(env(), application(), invalid_clock);
  EXPECT_EQ(rows[0].status, rasp::Status::kError);
  EXPECT_EQ(state().pops, 0);
  EXPECT_EQ(state().clears, 0);
}
TEST_F(LoaderBoundaryTest, preexistingException_whenEntered_preservesHostException) {
  state().exception = true;
  const auto rows = rasp::android::checks::read_loader_provenance(env(), application());
  EXPECT_EQ(rows[0].status, rasp::Status::kError);
  EXPECT_TRUE(state().exception);
  EXPECT_EQ(state().pops, 0);
  EXPECT_EQ(state().clears, 0);
}
TEST_F(LoaderBoundaryTest, elapsedBudget_whenReached_returnsTimeoutBeforeAllocatingFrame) {
  const auto rows = rasp::android::checks::read_loader_provenance(env(), application(), advancing_clock);
  EXPECT_EQ(rows[0].status, rasp::Status::kTimeout);
  EXPECT_EQ(state().pops, 0);
}
TEST_F(LoaderBoundaryTest, absentClock_whenEntered_returnsErrorWithoutNativeWork) {
  const auto rows = rasp::android::checks::read_loader_provenance(env(), application(), nullptr);
  EXPECT_EQ(rows[0].status, rasp::Status::kError);
  EXPECT_EQ(state().pops, 0);
}
}  // namespace
