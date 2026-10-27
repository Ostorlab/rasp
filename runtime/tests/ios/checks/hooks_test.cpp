/// Tests for the iOS hooking checks: the loaded-image probe that reports images of instrumentation and hooking
/// frameworks, the probe that reports the value of `DYLD_INSERT_LIBRARIES`, the probe that connects to a loopback
/// port, and the probe that reports memory regions that are both writable and executable.

#include "checks/hooks.h"

#include <cstddef>
#include <cstdint>
#include <gtest/gtest.h>
#include <netinet/in.h>
#include <string>
#include <sys/socket.h>
#include <unistd.h>
#include <utility>
#include <variant>
#include <vector>

#include "rasp/observation.h"

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

/// A TCP socket bound to a free port of the loopback address, 127.0.0.1, closed when the object goes away.
class LoopbackSocket {
 public:
  /// Opens the socket and binds it to a port the system picks. bound is false when either step failed.
  LoopbackSocket() : descriptor_(socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) {
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    socklen_t size = sizeof(address);
    // NOLINTBEGIN(cppcoreguidelines-pro-type-reinterpret-cast)
    bound_ = descriptor_ >= 0 && bind(descriptor_, reinterpret_cast<const sockaddr*>(&address), size) == 0 &&
             getsockname(descriptor_, reinterpret_cast<sockaddr*>(&address), &size) == 0;
    // NOLINTEND(cppcoreguidelines-pro-type-reinterpret-cast)
    port_ = ntohs(address.sin_port);
  }
  /// Deleted: a copy would close the same socket twice.
  LoopbackSocket(const LoopbackSocket&) = delete;
  /// Deleted: a copy would close the same socket twice.
  LoopbackSocket& operator=(const LoopbackSocket&) = delete;
  /// Deleted: a moved-from object would still close the socket.
  LoopbackSocket(LoopbackSocket&&) = delete;
  /// Deleted: a moved-from object would still close the socket.
  LoopbackSocket& operator=(LoopbackSocket&&) = delete;
  /// Closes the socket.
  ~LoopbackSocket() {
    if (descriptor_ >= 0) {
      static_cast<void>(close(descriptor_));
    }
  }

  /// Whether the socket was opened and bound to a port.
  [[nodiscard]] bool bound() const { return bound_; }

  /// Makes the socket accept connections on its port.
  ///
  /// @return Whether listen succeeded.
  [[nodiscard]] bool listen() const { return ::listen(descriptor_, 1) == 0; }

  /// The port the socket is bound to, in host byte order.
  [[nodiscard]] std::uint16_t port() const { return port_; }

 private:
  /// The socket's file descriptor, negative when it couldn't be opened.
  int descriptor_;
  /// Whether the socket was bound to a port.
  bool bound_ = false;
  /// The port the socket is bound to, in host byte order.
  std::uint16_t port_ = 0;
};

/// The protection that allows every access.
constexpr std::uint32_t kReadWriteExecute = kProtectionRead | kProtectionWrite | kProtectionExecute;
/// The protection of code: read and run.
constexpr std::uint32_t kReadExecute = kProtectionRead | kProtectionExecute;
/// The protection of data: read and write.
constexpr std::uint32_t kReadWrite = kProtectionRead | kProtectionWrite;

/// The regions of a clean app: its code, its data, its heap, a guard page and the shared region.
[[nodiscard]] std::vector<MemoryRegion> clean_regions() {
  return {
      {.start = 0x104a3c000, .end = 0x104a40000, .protection = kReadExecute, .max_protection = kReadExecute},
      {.start = 0x104a40000, .end = 0x104a44000, .protection = kReadWrite, .max_protection = kReadWrite},
      {.start = 0x105000000, .end = 0x105800000, .protection = kReadWrite, .max_protection = kReadWriteExecute},
      {.start = 0x16f000000, .end = 0x16f004000, .protection = 0, .max_protection = kReadWriteExecute},
      {.start = 0x180000000, .end = 0x200000000, .protection = kReadExecute, .max_protection = kReadExecute},
  };
}

/// The hook.rwx_regions observation that reports `regions`.
[[nodiscard]] Observation rwx_regions(std::vector<std::string> regions) {
  return {.signal = "hook.rwx_regions", .source = "vm_region", .status = Status::kOk, .value = std::move(regions)};
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

TEST(Hooks, observeLoopbackPort_whenAServerListensOnThePort_reportsTrue) {
  const LoopbackSocket server;
  ASSERT_TRUE(server.bound());
  ASSERT_TRUE(server.listen());

  EXPECT_EQ(observe_loopback_port(server.port()),
            (Observation{.signal = "hook.frida_port", .source = "connect", .status = Status::kOk, .value = true}));
}

TEST(Hooks, observeLoopbackPort_whenNothingListensOnThePort_reportsFalse) {
  const LoopbackSocket closed_port;
  ASSERT_TRUE(closed_port.bound());

  EXPECT_EQ(observe_loopback_port(closed_port.port()),
            (Observation{.signal = "hook.frida_port", .source = "connect", .status = Status::kOk, .value = false}));
}

TEST(Hooks, observeRegions_whenNoRegionIsWritableAndExecutable_reportsAnEmptyList) {
  EXPECT_EQ(observe_regions(clean_regions()), rwx_regions({}));
}

TEST(Hooks, observeRegions_whenOnlyTheMaximumProtectionIsWritableAndExecutable_reportsAnEmptyList) {
  const std::vector<MemoryRegion> regions = {
      {.start = 0x105000000, .end = 0x105800000, .protection = kReadWrite, .max_protection = kReadWriteExecute},
      {.start = 0x106000000, .end = 0x106004000, .protection = kReadExecute, .max_protection = kReadWriteExecute},
  };

  EXPECT_EQ(observe_regions(regions), rwx_regions({}));
}

TEST(Hooks, observeRegions_whenRegionsAreWritableAndExecutable_reportsTheirAddressesAndProtectionsInOrder) {
  const MemoryRegion read_write_execute = {
      .start = 0x104a44000,
      .end = 0x104a48000,
      .protection = kReadWriteExecute,
      .max_protection = kReadWriteExecute,
  };
  const MemoryRegion write_execute = {
      .start = 0x280000000,
      .end = 0x280100000,
      .protection = kProtectionWrite | kProtectionExecute,
      .max_protection = kReadWriteExecute,
  };
  std::vector<MemoryRegion> regions = clean_regions();
  regions.insert(regions.begin() + 1, read_write_execute);
  regions.push_back(write_execute);

  EXPECT_EQ(observe_regions(regions), rwx_regions({
                                          "0000000104a44000-0000000104a48000 rwx/rwx",
                                          "0000000280000000-0000000280100000 -wx/rwx",
                                      }));
}

TEST(Hooks, observeRegions_whenAnAddressUsesEveryDigit_writesAll16Digits) {
  const std::vector<MemoryRegion> regions = {
      {
          .start = 0xfedcba9876543000,
          .end = 0xffffffffffffffff,
          .protection = kReadWriteExecute,
          .max_protection = kReadWriteExecute,
      },
  };

  EXPECT_EQ(observe_regions(regions), rwx_regions({"fedcba9876543000-ffffffffffffffff rwx/rwx"}));
}

TEST(Hooks, observeRegions_whenAProtectionHasOtherBits_writesOnlyReadWriteAndExecute) {
  constexpr std::uint32_t kCopy = 0x10;
  const std::vector<MemoryRegion> regions = {
      {
          .start = 0x104a44000,
          .end = 0x104a48000,
          .protection = kReadWriteExecute | kCopy,
          .max_protection = kReadWriteExecute | kCopy,
      },
  };

  EXPECT_EQ(observe_regions(regions), rwx_regions({"0000000104a44000-0000000104a48000 rwx/rwx"}));
}

TEST(Hooks, observeRegions_whenMoreThan32RegionsMatch_reportsTheFirst32) {
  constexpr std::size_t kRegionCount = 40;
  constexpr std::uint64_t kPageSize = 0x4000;
  std::vector<MemoryRegion> regions;
  regions.reserve(kRegionCount);
  for (std::size_t index = 0; index < kRegionCount; ++index) {
    const std::uint64_t start = 0x300000000 + (index * kPageSize);
    regions.push_back({
        .start = start,
        .end = start + kPageSize,
        .protection = kReadWriteExecute,
        .max_protection = kReadWriteExecute,
    });
  }

  const Observation observation = observe_regions(regions);
  ASSERT_TRUE(std::holds_alternative<std::vector<std::string>>(observation.value));
  const auto& reported = std::get<std::vector<std::string>>(observation.value);
  ASSERT_EQ(reported.size(), 32U);
  EXPECT_EQ(reported.front(), "0000000300000000-0000000300004000 rwx/rwx");
  EXPECT_EQ(reported.back(), "000000030007c000-0000000300080000 rwx/rwx");
}

#ifdef __APPLE__
TEST(Hooks, observeMemoryRegions_whenTheTaskCanBeRead_reportsAListOfRegions) {
  const Observation observation = observe_memory_regions();
  EXPECT_EQ(observation.signal, "hook.rwx_regions");
  EXPECT_EQ(observation.source, "vm_region");
  EXPECT_EQ(observation.status, Status::kOk);
  EXPECT_TRUE(std::holds_alternative<std::vector<std::string>>(observation.value));
}
#else
TEST(Hooks, observeMemoryRegions_whenTheSystemHasNoMach_reportsUnsupported) {
  EXPECT_EQ(
      observe_memory_regions(),
      (Observation{.signal = "hook.rwx_regions", .source = "vm_region", .status = Status::kUnsupported, .value = {}}));
}
#endif

TEST(Hooks, hooks_whenOffAPhysicalDevice_reportsEveryCheckAsUnsupported) {
  EXPECT_EQ(hooks("/usr/lib/systemhook.dylib"),
            (std::vector<Observation>{
                {.signal = "hook.maps_hits", .source = "dyld", .status = Status::kUnsupported, .value = {}},
                {.signal = "hook.dyld_env", .source = "getenv", .status = Status::kUnsupported, .value = {}},
                {.signal = "hook.frida_port", .source = "connect", .status = Status::kUnsupported, .value = {}},
                {.signal = "hook.rwx_regions", .source = "vm_region", .status = Status::kUnsupported, .value = {}},
            }));
}

}  // namespace
}  // namespace rasp::ios::checks
