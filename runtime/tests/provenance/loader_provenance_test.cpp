/// Real-JVM public parent traversal, with only Android Application services supplied by Java fixtures.
#include "checks/loader_provenance.h"

#include <array>
#include <cstdint>
#include <gtest/gtest.h>
#include <jni.h>
#include <string>
#include <variant>
#include <vector>

#include "rasp/observation.h"
#include "rasp/posix/provenance.h"

namespace {
/// A fixed source clock isolates reference/API behavior from scheduler latency.
std::int64_t clock() { return 0; }
/// Owns one real JVM per test process; none of these entry points is shipped.
class LoaderProvenanceTest : public testing::Test {
 protected:
  /// Starts a checked real JVM using only the dedicated public-service fixture classes.
  void SetUp() override {
    std::string path = "-Djava.class.path=" RASP_PROVENANCE_CLASSES;
    std::string checked = "-Xcheck:jni";
    std::array<JavaVMOption, 2> options{
        {{.optionString = path.data(), .extraInfo = nullptr}, {.optionString = checked.data(), .extraInfo = nullptr}},
    };
    JavaVMInitArgs arguments{
        .version = JNI_VERSION_1_6,
        .nOptions = 2,
        .options = options.data(),
        .ignoreUnrecognized = JNI_FALSE,
    };
    void* environment = nullptr;
    ASSERT_EQ(JNI_CreateJavaVM(&vm_, &environment, &arguments), JNI_OK);
    env_ = static_cast<JNIEnv*>(environment);
  }
  /// Destroys the isolated test VM after all probe-owned local frames have been released.
  void TearDown() override {
    if (vm_ != nullptr) {
      EXPECT_EQ(vm_->DestroyJavaVM(), JNI_OK);
    }
  }
  /// Creates an Application service fixture through its ordinary public constructor.
  jobject application(int depth = 3, int mode = 0) {
    jclass type = env()->FindClass("fixture/provenance/LoaderFixture$Application");
    auto* const constructor = env()->GetMethodID(type, "<init>", "(II)V");
    const std::array<jvalue, 2> values{{{.i = depth}, {.i = mode}}};
    jobject result = env()->NewObjectA(type, constructor, values.data());
    env()->DeleteLocalRef(type);
    return result;
  }
  JNIEnv* env() { return env_; }

 private:
  JavaVM* vm_ = nullptr;
  JNIEnv* env_ = nullptr;
};
TEST_F(LoaderProvenanceTest, collect_whenLegitimateCustomChain_reportsTopologyWithoutNames) {
  const auto result = rasp::android::checks::read_loader_provenance(env(), application(), clock);
  ASSERT_EQ(result[0].status, rasp::Status::kOk);
  const auto& rows = std::get<std::vector<std::string>>(result[0].value);
  ASSERT_EQ(rows.size(), 3U);
  EXPECT_EQ(rows.back(), "v=1;depth=2;kind=custom;parent=null");
  EXPECT_EQ(rasp::describe(result[0]).find("PluginLoader"), std::string::npos);
  EXPECT_EQ(env()->ExceptionCheck(), JNI_FALSE);
}
TEST_F(LoaderProvenanceTest, collect_whenApplicationRefuses_clearsOnlyProbeExceptionAndErrors) {
  const auto result = rasp::android::checks::read_loader_provenance(env(), application(3, 1), clock);
  EXPECT_EQ(result[0].status, rasp::Status::kError);
  EXPECT_EQ(env()->ExceptionCheck(), JNI_FALSE);
}
TEST_F(LoaderProvenanceTest, collect_whenRootChangesBetweenPasses_reportsRace) {
  const auto result = rasp::android::checks::read_loader_provenance(env(), application(3, 2), clock);
  EXPECT_EQ(result[0].status, rasp::Status::kError);
  EXPECT_NE(rasp::describe(result[1]).find("reason=race"), std::string::npos);
}
TEST_F(LoaderProvenanceTest, collect_whenDepthExceedsSixteen_hasNoPartialSuccessfulChain) {
  const auto result = rasp::android::checks::read_loader_provenance(env(), application(17), clock);
  EXPECT_EQ(result[0].status, rasp::Status::kError);
  EXPECT_TRUE(std::holds_alternative<std::monostate>(result[0].value));
}
TEST_F(LoaderProvenanceTest, locations_whenPublicMetadataAvailable_returnsExactLocalRootsOnly) {
  const auto result = rasp::android::checks::read_provenance_locations(env(), application(), clock);
  ASSERT_TRUE(result.has_value());
  EXPECT_EQ(result->apk_paths, (std::vector<std::string>{"/data/app/secret/base.apk", "/data/app/secret/feature.apk"}));
  EXPECT_EQ(result->native_directory, "/data/app/secret/lib");
  EXPECT_TRUE(result->available);
  EXPECT_EQ(env()->ExceptionCheck(), JNI_FALSE);
}
TEST_F(LoaderProvenanceTest, locations_whenSplitCountExceedsLimit_returnsNoPartialRoots) {
  const auto result = rasp::android::checks::read_provenance_locations(env(), application(3, 3), clock);
  EXPECT_FALSE(result.has_value());
  EXPECT_EQ(result.error(), rasp::provenance::Error::kInputLimit);
}
TEST_F(LoaderProvenanceTest, locations_whenPublicPathIsAmbiguous_doesNotClaimAppOwnership) {
  const auto result = rasp::android::checks::read_provenance_locations(env(), application(3, 4), clock);
  EXPECT_FALSE(result.has_value());
  EXPECT_EQ(result.error(), rasp::provenance::Error::kMalformed);
}
TEST_F(LoaderProvenanceTest, collect_whenPreexistingException_returnsErrorWithoutClearingHostException) {
  jobject app = application();
  jclass error = env()->FindClass("java/lang/IllegalStateException");
  ASSERT_EQ(env()->ThrowNew(error, "host-owned exception"), JNI_OK);
  const auto result = rasp::android::checks::read_loader_provenance(env(), app, clock);
  EXPECT_EQ(env()->ExceptionCheck(), JNI_TRUE);
  env()->ExceptionClear();
  EXPECT_EQ(result[0].status, rasp::Status::kError);
}
}  // namespace
