/// Tests for the iOS virtualizer check.

#include "checks/virtualizer.h"

#include <array>
#include <gtest/gtest.h>
#include <iterator>
#include <string>
#include <vector>

#include "rasp/observation.h"

namespace rasp::ios::checks {
namespace {

TEST(Virtualizer, observeContainerPath_whenInsideSystemLayout_reportsFalse) {
  EXPECT_EQ(observe_container_path("/private/var/containers/Bundle/Application/1234-ABCD/Example.app/Example"),
            (Observation{.signal = "virt.exec_path", .source = "dyld", .status = Status::kOk, .value = false}));
}

TEST(Virtualizer, observeContainerPath_whenOutsideSystemLayout_reportsTrue) {
  EXPECT_EQ(observe_container_path("/private/var/mobile/Containers/Data/Application/host/Example.app/Example"),
            (Observation{.signal = "virt.exec_path", .source = "dyld", .status = Status::kOk, .value = true}));
}

TEST(Virtualizer, observeForeignImages_whenAllWithinLegitimateRoots_reportsEmpty) {
  const std::string bundle = "/private/var/containers/Bundle/Application/1234/Example.app";
  const std::array<std::string, 3> images = {
      "/usr/lib/libSystem.B.dylib",
      "/System/Library/Frameworks/UIKit.framework/UIKit",
      bundle + "/Example",
  };

  const std::vector<std::string> none;
  EXPECT_EQ(observe_foreign_images(images, bundle),
            (Observation{.signal = "virt.foreign_images", .source = "dyld", .status = Status::kOk, .value = none}));
}

TEST(Virtualizer, observeForeignImages_whenHostRuntimeMapped_reportsIt) {
  const std::string bundle = "/private/var/containers/Bundle/Application/1234/Example.app";
  const std::string host = "/private/var/mobile/Containers/Data/Application/host/runtime.dylib";
  const std::array<std::string, 2> images = {"/usr/lib/libSystem.B.dylib", host};

  const std::vector<std::string> expected = {host};
  EXPECT_EQ(observe_foreign_images(images, bundle),
            (Observation{.signal = "virt.foreign_images", .source = "dyld", .status = Status::kOk, .value = expected}));
}

TEST(Virtualizer, observeForeignImages_whenBundleUnknown_doesNotExcuseBundlePaths) {
  const std::string app_image = "/private/var/containers/Bundle/Application/1234/Example.app/Example";
  const std::array<std::string, 2> images = {"/usr/lib/libSystem.B.dylib", app_image};

  const std::vector<std::string> expected = {app_image};
  EXPECT_EQ(observe_foreign_images(images, ""),
            (Observation{.signal = "virt.foreign_images", .source = "dyld", .status = Status::kOk, .value = expected}));
}

TEST(Virtualizer, observeForeignImages_whenCryptexSystemImage_treatsItAsLegitimate) {
  // Modern iOS serves stock OS frameworks from a cryptex path that does not start with /System/.
  const std::array<std::string, 2> images = {
      "/private/preboot/Cryptexes/OS/System/Library/Frameworks/WebKit.framework/WebKit",
      "/private/preboot/0A1B2C3D/Cryptexes/OS/System/Library/Frameworks/Foundation.framework/Foundation",
  };

  const std::vector<std::string> none;
  EXPECT_EQ(observe_foreign_images(images, "/some/bundle.app"),
            (Observation{.signal = "virt.foreign_images", .source = "dyld", .status = Status::kOk, .value = none}));
}

TEST(Virtualizer, observeForeignImages_whenSiblingOfBundleDirectory_reportsIt) {
  const std::string bundle = "/private/var/containers/Bundle/Application/1234/Example.app";
  // A sibling directory that shares the bundle's name as a prefix must not be excused as the bundle.
  const std::string sibling = bundle + ".backup/runtime.dylib";
  const std::array<std::string, 1> images = {sibling};

  const std::vector<std::string> expected = {sibling};
  EXPECT_EQ(observe_foreign_images(images, bundle),
            (Observation{.signal = "virt.foreign_images", .source = "dyld", .status = Status::kOk, .value = expected}));
}

TEST(Virtualizer, observeForeignImages_whenMoreThanTheCap_reportsOnlyTheFirst64InOrder) {
  std::vector<std::string> images;
  images.reserve(70);
  for (int index = 0; index < 70; ++index) {
    images.push_back("/private/var/mobile/host/lib" + std::to_string(index) + ".dylib");
  }

  // Only the first 64, in encounter order.
  const std::vector<std::string> expected(images.begin(), std::next(images.begin(), 64));
  EXPECT_EQ(observe_foreign_images(images, "/some/bundle.app"),
            (Observation{.signal = "virt.foreign_images", .source = "dyld", .status = Status::kOk, .value = expected}));
}

#ifndef __APPLE__
TEST(Virtualizer, virtualizer_whenOffAPhysicalDevice_reportsEveryProbeAsUnsupported) {
  EXPECT_EQ(virtualizer(),
            (std::vector<Observation>{
                {.signal = "virt.exec_path", .source = "dyld", .status = Status::kUnsupported, .value = {}},
                {.signal = "virt.foreign_images", .source = "dyld", .status = Status::kUnsupported, .value = {}},
            }));
}
#endif

}  // namespace
}  // namespace rasp::ios::checks
