/// Tests for the iOS hooking checks: the loaded-image probe that reports images of instrumentation and hooking
/// frameworks, and the probe that reports the value of `DYLD_INSERT_LIBRARIES`.

#include "checks/hooks.h"

#include <cstddef>
#include <gtest/gtest.h>
#include <string>
#include <utility>
#include <vector>

#include "rasp/observation.h"

#ifdef __APPLE__
#include <variant>
#endif

namespace rasp::ios::checks {
namespace {

/// The images of a clean app: its own executable, a framework it embeds, and system libraries.
[[nodiscard]] std::vector<std::string> clean_images() {
  return {
      "/private/var/containers/Bundle/Application/0A1B2C3D/App.app/App",
      "/private/var/containers/Bundle/Application/0A1B2C3D/App.app/Frameworks/RaspRuntime.framework/RaspRuntime",
      "/usr/lib/libSystem.B.dylib",
      "/System/Library/Frameworks/UIKit.framework/UIKit",
      "/private/preboot/Cryptexes/OS/System/Library/Frameworks/WebKit.framework/WebKit",
  };
}

/// The hook.maps_hits observation that reports `paths`.
[[nodiscard]] Observation maps_hits(std::vector<std::string> paths) {
  return {.signal = "hook.maps_hits", .source = "dyld", .status = Status::kOk, .value = std::move(paths)};
}

TEST(Hooks, observeImages_whenNoImageNamesAFramework_reportsAnEmptyList) {
  EXPECT_EQ(observe_images(clean_images()), maps_hits({}));
}

TEST(Hooks, observeImages_whenTheAppEmbedsSubstrateSdk_reportsAnEmptyList) {
  std::vector<std::string> images = clean_images();
  images.emplace_back(
      "/private/var/containers/Bundle/Application/0A1B2C3D/App.app/Frameworks/SubstrateSdk.framework/SubstrateSdk");

  EXPECT_EQ(observe_images(images), maps_hits({}));
}

TEST(Hooks, observeImages_whenTheAppBundleIsNamedAfterAMarker_reportsAnEmptyList) {
  const std::vector<std::string> images = {
      "/private/var/containers/Bundle/Application/0A1B2C3D/GadgetFlow.app/GadgetFlow",
      "/private/var/containers/Bundle/Application/0A1B2C3D/GadgetFlow.app/Frameworks/Alamofire.framework/Alamofire",
      "/private/var/containers/Bundle/Application/0A1B2C3D/GadgetFlow.app/Frameworks/RaspRuntime.framework/RaspRuntime",
      "/private/var/containers/Bundle/Application/0A1B2C3D/Substrate.app/Substrate",
      "/private/var/containers/Bundle/Application/0A1B2C3D/FridaTools.app/Frameworks/Core.framework/Core",
  };

  EXPECT_EQ(observe_images(images), maps_hits({}));
}

TEST(Hooks, observeImages_whenAFileNameHoldsAMarkerWordInsideAnotherWord_reportsAnEmptyList) {
  const std::vector<std::string> images = {
      "/private/var/containers/Bundle/Application/0A1B2C3D/Friday.app/Friday",
      "/private/var/containers/Bundle/Application/0A1B2C3D/App.app/Frameworks/BelleKit.framework/BelleKit",
      "/private/var/containers/Bundle/Application/0A1B2C3D/App.app/Frameworks/GadgetKit.framework/GadgetKit",
  };

  EXPECT_EQ(observe_images(images), maps_hits({}));
}

TEST(Hooks, observeImages_whenATweakFolderIsNotAtTheStartOfThePath_reportsAnEmptyList) {
  const std::vector<std::string> images = {
      "/private/var/containers/Bundle/Application/0A1B2C3D/App.app/usr/lib/ellekit/Helper.dylib",
      "/private/var/mobile/Library/MobileSubstrate/DynamicLibraries/Helper.dylib",
      "/var/jbx/usr/lib/TweakInject/Helper.dylib",
      "/private/preboot/Cryptexes/OS/usr/lib/TweakInject/Helper.dylib",
  };

  EXPECT_EQ(observe_images(images), maps_hits({}));
}

TEST(Hooks, observeImages_whenAFileNameHoldsAMarker_reportsItForEveryMarker) {
  const std::vector<std::string> images = {
      "/private/var/tmp/frida-0123abcd/frida-agent.dylib",
      "/private/var/containers/Bundle/Application/0A1B2C3D/App.app/Frameworks/frida-gadget-16.5.2-ios-universal.dylib",
      "/private/var/containers/Bundle/Application/0A1B2C3D/App.app/Frameworks/FridaGadget.dylib",
      "/usr/lib/libcycript.dylib",
      "/Library/Frameworks/CydiaSubstrate.framework/CydiaSubstrate",
      "/Library/MobileSubstrate/MobileSubstrate.dylib",
      "/usr/lib/libsubstrate.dylib",
      "/usr/lib/substrate/SubstrateLoader.dylib",
      "/usr/lib/substrate/SubstrateInserter.dylib",
      "/usr/lib/substrate/SubstrateBootstrap.dylib",
      "/usr/lib/libsubstitute.dylib",
      "/usr/lib/libhooker.dylib",
      "/usr/lib/libblackjack.dylib",
      "/var/jb/usr/lib/libellekit.dylib",
      "/usr/lib/TweakInject.dylib",
      "/var/jb/usr/lib/TweakLoader.dylib",
      "/private/var/containers/Bundle/Application/0A1B2C3D/App.app/Frameworks/SSLKillSwitch2.dylib",
  };

  EXPECT_EQ(observe_images(images), maps_hits(images));
}

TEST(Hooks, observeImages_whenAnImageIsInATweakFolder_reportsItUnderEveryJailbreakRoot) {
  const std::vector<std::string> roots = {
      "",
      "/var/jb",
      "/private/var/jb",
      "/private/preboot/0A1B2C3D4E5F/dopamine-a1B2c3/procursus",
      "/private/preboot/0A1B2C3D4E5F/jb-a1B2c3/procursus",
  };
  const std::vector<std::string> files = {
      "/Library/MobileSubstrate/DynamicLibraries/Helper.dylib",
      "/usr/lib/TweakInject/Helper.dylib",
      "/usr/lib/ellekit/libinjector.dylib",
      "/Library/Substitute/DynamicLibraries/Helper.dylib",
      "/Library/Substitute/Helpers/bundle-loader.dylib",
  };
  std::vector<std::string> images;
  for (const std::string& root : roots) {
    for (const std::string& file : files) {
      images.push_back(root + file);
    }
  }

  EXPECT_EQ(observe_images(images), maps_hits(images));
}

TEST(Hooks, observeImages_whenFrameworksAreLoaded_reportsTheirPathsInOrder) {
  const std::string gadget = "/private/var/containers/Bundle/Application/0A1B2C3D/App.app/Frameworks/FridaGadget.dylib";
  const std::string tweak = "/Library/MobileSubstrate/DynamicLibraries/SSLKillSwitch2.dylib";
  const std::string ellekit = "/var/jb/usr/lib/libellekit.dylib";
  std::vector<std::string> images = clean_images();
  images.insert(images.begin() + 1, gadget);
  images.push_back(tweak);
  images.push_back(ellekit);

  EXPECT_EQ(observe_images(images), maps_hits({gadget, tweak, ellekit}));
}

TEST(Hooks, observeImages_whenAMarkerHasAnotherCase_matchesCaseInsensitively) {
  const std::string tweak_inject = "/usr/lib/TWEAKINJECT.dylib";
  const std::vector<std::string> images = {tweak_inject};

  EXPECT_EQ(observe_images(images), maps_hits({tweak_inject}));
}

TEST(Hooks, observeImages_whenATweakFolderHasAnotherCase_matchesCaseInsensitively) {
  const std::string tweak = "/PRIVATE/PREBOOT/0A1B2C3D4E5F/JB-A1B2C3/PROCURSUS/USR/LIB/TWEAKINJECT/Helper.dylib";
  const std::vector<std::string> images = {tweak};

  EXPECT_EQ(observe_images(images), maps_hits({tweak}));
}

TEST(Hooks, observeImages_whenMoreThan32ImagesMatch_reportsTheFirst32) {
  constexpr std::size_t kImageCount = 40;
  std::vector<std::string> images;
  images.reserve(kImageCount);
  for (std::size_t index = 0; index < kImageCount; ++index) {
    images.push_back("/Library/MobileSubstrate/DynamicLibraries/Tweak" + std::to_string(index) + ".dylib");
  }

  const std::vector<std::string> first(images.begin(), images.begin() + 32);
  EXPECT_EQ(observe_images(images), maps_hits(first));
}

#ifdef __APPLE__
TEST(Hooks, observeLoadedImages_whenDyldCanBeRead_reportsAListOfPaths) {
  const Observation observation = observe_loaded_images();
  EXPECT_EQ(observation.signal, "hook.maps_hits");
  EXPECT_EQ(observation.source, "dyld");
  EXPECT_EQ(observation.status, Status::kOk);
  EXPECT_TRUE(std::holds_alternative<std::vector<std::string>>(observation.value));
}
#else
TEST(Hooks, observeLoadedImages_whenTheSystemHasNoDyld_reportsUnsupported) {
  EXPECT_EQ(observe_loaded_images(),
            (Observation{.signal = "hook.maps_hits", .source = "dyld", .status = Status::kUnsupported, .value = {}}));
}
#endif

TEST(Hooks, observeInsertedLibraries_whenTheVariableIsUnset_reportsAnEmptyString) {
  EXPECT_EQ(
      observe_inserted_libraries(""),
      (Observation{.signal = "hook.dyld_env", .source = "getenv", .status = Status::kOk, .value = std::string()}));
}

TEST(Hooks, observeInsertedLibraries_whenLibrariesAreInserted_reportsTheValueAsItIs) {
  const std::string value = "/usr/lib/systemhook.dylib:/var/jb/usr/lib/ellekit/libinjector.dylib";

  EXPECT_EQ(observe_inserted_libraries(value),
            (Observation{.signal = "hook.dyld_env", .source = "getenv", .status = Status::kOk, .value = value}));
}

TEST(Hooks, observeInsertedLibraries_whenTheValueIsLongerThan4096Bytes_reportsTheFirst4096) {
  const std::string value = std::string(4096, 'a') + "/usr/lib/libhooker.dylib";

  EXPECT_EQ(
      observe_inserted_libraries(value),
      (Observation{
          .signal = "hook.dyld_env", .source = "getenv", .status = Status::kOk, .value = std::string(4096, 'a')}));
}

TEST(Hooks, hooks_whenOffAPhysicalDevice_reportsEveryCheckAsUnsupported) {
  EXPECT_EQ(hooks("/usr/lib/systemhook.dylib"),
            (std::vector<Observation>{
                {.signal = "hook.maps_hits", .source = "dyld", .status = Status::kUnsupported, .value = {}},
                {.signal = "hook.dyld_env", .source = "getenv", .status = Status::kUnsupported, .value = {}},
            }));
}

}  // namespace
}  // namespace rasp::ios::checks
