/// The iOS hooking checks: the loaded-image probe, the read of `DYLD_INSERT_LIBRARIES` at load time and the probe that
/// reports it, the probe that connects to Frida's default port, the probe that walks the app's memory regions for ones
/// that are both writable and executable, and their unsupported result off a physical device. The markers and folders
/// draw on the names and places Frida, Cycript, Substrate, the tweak loaders and SSL Kill Switch install their
/// libraries under, on rootful and rootless jailbreaks.

#include "checks/hooks.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <fcntl.h>
#include <netinet/in.h>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <sys/poll.h>
#include <sys/socket.h>
#include <unistd.h>
#include <utility>
#include <vector>

#include "rasp/observation.h"

#ifdef __APPLE__
#include <TargetConditionals.h>
#include <mach-o/dyld.h>
#include <mach/kern_return.h>
#include <mach/mach_init.h>
#include <mach/mach_port.h>
#include <mach/message.h>
#include <mach/port.h>
#include <mach/vm_map.h>
#include <mach/vm_prot.h>
#include <mach/vm_region.h>
#include <mach/vm_types.h>
#endif

namespace rasp::ios::checks {

namespace {

#if defined(__APPLE__) && TARGET_OS_IOS && !TARGET_OS_SIMULATOR
/// Whether this build runs on a physical iOS device, the only place the probe means anything.
constexpr bool kPhysicalDevice = true;
#else
/// Whether this build runs on a physical iOS device, the only place the probe means anything.
constexpr bool kPhysicalDevice = false;
#endif

/// The signal of the probe that reports images of a known instrumentation or hooking framework.
constexpr std::string_view kMapsHitsSignal = "hook.maps_hits";
/// The source of the probe.
constexpr std::string_view kDyldSource = "dyld";

/// The signal of the probe that reports the value of `DYLD_INSERT_LIBRARIES`.
constexpr std::string_view kDyldEnvSignal = "hook.dyld_env";
/// The source of the probe.
constexpr std::string_view kGetenvSource = "getenv";
/// The environment variable that asks dyld to insert libraries into the process.
constexpr const char* kInsertLibrariesVariable = "DYLD_INSERT_LIBRARIES";
/// The most bytes of the variable's value the probe reports.
constexpr std::size_t kMaxInsertedLibrariesSize = 4096;

/// The signal of the probe that reports whether Frida's default port accepts a connection.
constexpr std::string_view kFridaPortSignal = "hook.frida_port";
/// The source of the probe.
constexpr std::string_view kConnectSource = "connect";
/// The TCP port that frida-server and Frida Gadget listen on by default.
constexpr std::uint16_t kFridaPort = 27042;
/// The most milliseconds the probe waits for its connection to be accepted or refused.
constexpr int kConnectTimeoutMilliseconds = 250;

/// The signal of the probe that reports the regions of the app's memory that are both writable and executable.
constexpr std::string_view kRwxRegionsSignal = "hook.rwx_regions";
/// The source of the probe.
constexpr std::string_view kVmRegionSource = "vm_region";

#ifdef __APPLE__
/// The most images the probe reads from dyld's list. A real app loads far fewer.
constexpr std::uint32_t kMaxImages = 4096;
/// The most regions the probe reads from the task's address space. A real app has far fewer.
constexpr std::size_t kMaxRegions = 65536;

static_assert(kProtectionRead == static_cast<std::uint32_t>(VM_PROT_READ));
static_assert(kProtectionWrite == static_cast<std::uint32_t>(VM_PROT_WRITE));
static_assert(kProtectionExecute == static_cast<std::uint32_t>(VM_PROT_EXECUTE));
#endif

/// The most paths reported in the list.
constexpr std::size_t kMaxPaths = 32;
/// The most regions reported in the list.
constexpr std::size_t kMaxRegionsReported = 32;
/// The number of hexadecimal digits an address is written with.
constexpr std::size_t kAddressDigits = 16;
/// The hexadecimal digits, in order of value.
constexpr std::string_view kHexDigits = "0123456789abcdef";

/// The text that marks the file name of an image of a known instrumentation or hooking framework, in lowercase, matched
/// anywhere in the last component of the path without regard to case. Each one is part of the name of a file these
/// frameworks install, not a whole word that an app's own framework could also use. It covers Frida's agent and gadget
/// (`frida-agent.dylib`, `frida-gadget.dylib` and `FridaGadget.dylib`), Cycript, Substrate (`CydiaSubstrate`,
/// `MobileSubstrate.dylib`, `libsubstrate.dylib` and its loader, inserter and bootstrap), the hooking libraries that
/// replace it (Substitute, libhooker with libblackjack, and ElleKit), the TweakInject and TweakLoader tweak loaders,
/// and SSL Kill Switch.
constexpr auto kFrameworkMarkers = std::to_array<std::string_view>({
    "frida-agent",
    "frida-gadget",
    "fridagadget",
    "libcycript",
    "cydiasubstrate",
    "mobilesubstrate",
    "libsubstrate",
    "substrateloader",
    "substrateinserter",
    "substratebootstrap",
    "libsubstitute",
    "libhooker",
    "libblackjack",
    "libellekit",
    "tweakinject",
    "tweakloader",
    "sslkillswitch",
});

/// The folders that only hold the files of a tweak loader or of the tweaks it loads, in lowercase, relative to the root
/// of the jailbreak and matched at the start of the path without regard to case. An image in one of them is reported
/// whatever its file name: Substrate's `DynamicLibraries` folder, the `TweakInject` folder of the loaders that replace
/// it, ElleKit's own folder, which holds its `libinjector.dylib` loader, and Substitute's tweak and helper folders.
constexpr auto kTweakFolders = std::to_array<std::string_view>({
    "/library/mobilesubstrate/dynamiclibraries/",
    "/usr/lib/tweakinject/",
    "/usr/lib/ellekit/",
    "/library/substitute/dynamiclibraries/",
    "/library/substitute/helpers/",
});

/// The roots a rootless jailbreak installs its files under, in lowercase, each followed by a slash. `/var/jb` is the
/// path jailbreaks give their files, and `/private/var/jb` is the same folder as dyld names it, since `/var` is a link
/// to `/private/var`.
constexpr auto kJailbreakRoots = std::to_array<std::string_view>({
    "/var/jb/",
    "/private/var/jb/",
});

/// The start of the real folder that `/var/jb` links to on a rootless jailbreak, in lowercase. dyld names an image by
/// its real path, with every link resolved, such as
/// `/private/preboot/HASH/dopamine-ID/procursus/usr/lib/TweakInject/Tweak.dylib`.
constexpr std::string_view kPrebootFolder = "/private/preboot/";

/// The folder inside kPrebootFolder that is the root of a rootless jailbreak, in lowercase.
constexpr std::string_view kProcursusFolder = "/procursus/";

/// Returns `text` in lowercase.
///
/// @param text The text to convert.
/// @return A copy of `text` with every ASCII letter in lowercase.
[[nodiscard]] std::string lowercase(std::string_view text) {
  std::string lowered(text);
  std::ranges::transform(lowered, lowered.begin(), [](char character) {
    return static_cast<char>(std::tolower(static_cast<unsigned char>(character)));
  });
  return lowered;
}

/// Returns `path` relative to the root of the jailbreak that installed it.
///
/// A path under `/var/jb/` or `/private/var/jb/` loses that root. A path under kPrebootFolder loses everything up to
/// its first kProcursusFolder. Any other path, the path of a rootful jailbreak's file among them, is returned as it is.
///
/// @param path The lowercase path of an image.
/// @return The part of `path` that starts at the slash after the jailbreak's root, or `path` itself.
[[nodiscard]] std::string_view without_jailbreak_root(std::string_view path) {
  for (const std::string_view root : kJailbreakRoots) {
    if (path.starts_with(root)) {
      return path.substr(root.size() - 1);
    }
  }
  if (path.starts_with(kPrebootFolder)) {
    const std::size_t procursus = path.find(kProcursusFolder, kPrebootFolder.size() - 1);
    if (procursus != std::string_view::npos) {
      return path.substr(procursus + kProcursusFolder.size() - 1);
    }
  }
  return path;
}

/// Returns the file name of `path`, the part after its last slash.
///
/// @param path The path of an image.
/// @return The last component of `path`, or `path` itself when it has no slash.
[[nodiscard]] std::string_view file_name(std::string_view path) {
  const std::size_t slash = path.rfind('/');
  return slash == std::string_view::npos ? path : path.substr(slash + 1);
}

/// Whether `path` is the path of an image that names a known instrumentation or hooking framework.
///
/// It does when the image is in one of kTweakFolders, under any jailbreak root, or when its file name contains one of
/// kFrameworkMarkers. Both are matched without regard to case. The folders of the path above the file, such as the
/// name of the app's bundle, are never matched against the markers.
///
/// @param path The path of an image.
/// @return Whether the image is a known framework's.
[[nodiscard]] bool names_framework(std::string_view path) {
  const std::string lowered = lowercase(path);
  const std::string_view relative = without_jailbreak_root(lowered);
  if (std::ranges::any_of(kTweakFolders,
                          [relative](std::string_view folder) { return relative.starts_with(folder); })) {
    return true;
  }
  const std::string_view name = file_name(lowered);
  return std::ranges::any_of(kFrameworkMarkers, [name](std::string_view marker) { return name.contains(marker); });
}

/// Makes `descriptor` a socket that doesn't block and, on Apple systems, one that never raises `SIGPIPE`.
///
/// @param descriptor The socket to set up.
/// @return Whether every option was set.
[[nodiscard]] bool prepare_socket(int descriptor) {
#ifdef __APPLE__
  const int enabled = 1;
  if (setsockopt(descriptor, SOL_SOCKET, SO_NOSIGPIPE, &enabled, sizeof(enabled)) != 0) {
    return false;
  }
#endif
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg)
  const int flags = fcntl(descriptor, F_GETFL);
  if (flags < 0) {
    return false;
  }
  const auto non_blocking = static_cast<int>(static_cast<unsigned int>(flags) | static_cast<unsigned int>(O_NONBLOCK));
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-vararg)
  return fcntl(descriptor, F_SETFL, non_blocking) == 0;
}

/// Returns what a connection's error code says about the connection.
///
/// @param error The error code of the connection: 0 when it was accepted, or an `errno` value.
/// @return true when the connection was accepted, false when it was refused with `ECONNREFUSED`, and nothing for any
/// other error.
[[nodiscard]] std::optional<bool> connection_accepted(int error) {
  if (error == 0) {
    return true;
  }
  if (error == ECONNREFUSED) {
    return false;
  }
  return std::nullopt;
}

/// Waits at most kConnectTimeoutMilliseconds for the connection that `descriptor` started to be accepted or refused.
///
/// @param descriptor A socket that doesn't block, whose connection is in progress.
/// @return true when the connection was accepted, false when it was refused, and nothing when the wait timed out, poll
/// or getsockopt failed, or the connection failed with another error.
[[nodiscard]] std::optional<bool> wait_for_connection(int descriptor) {
  pollfd request{.fd = descriptor, .events = POLLOUT, .revents = 0};
  if (poll(&request, 1, kConnectTimeoutMilliseconds) != 1) {
    return std::nullopt;
  }
  int error = 0;
  socklen_t size = sizeof(error);
  if (getsockopt(descriptor, SOL_SOCKET, SO_ERROR, &error, &size) != 0 || size != sizeof(error)) {
    return std::nullopt;
  }
  return connection_accepted(error);
}

/// Returns the address of `port` on the loopback address, 127.0.0.1.
///
/// @param port The TCP port, in host byte order.
/// @return The IPv4 socket address, in network byte order.
[[nodiscard]] sockaddr_in loopback_address(std::uint16_t port) {
  sockaddr_in address{};
  address.sin_family = AF_INET;
  address.sin_port = htons(port);
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  return address;
}

/// Connects `descriptor` to `address`, and waits for the connection to be accepted or refused.
///
/// @param descriptor A TCP socket that is not connected yet.
/// @param address The address to connect to.
/// @return true when the connection was accepted, false when it was refused, and nothing when a system call failed or
/// the connection was neither accepted nor refused within kConnectTimeoutMilliseconds.
[[nodiscard]] std::optional<bool> connect_socket(int descriptor, const sockaddr_in& address) {
  if (!prepare_socket(descriptor)) {
    return std::nullopt;
  }
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
  if (connect(descriptor, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) == 0) {
    return true;
  }
  const int error = errno;
  if (error == EINPROGRESS) {
    return wait_for_connection(descriptor);
  }
  return connection_accepted(error);
}

/// Whether `region`'s current protection allows both writing and running its memory.
///
/// @param region The region to look at.
/// @return Whether its protection has both kProtectionWrite and kProtectionExecute.
[[nodiscard]] bool writable_executable(const MemoryRegion& region) {
  constexpr std::uint32_t kWritableExecutable = kProtectionWrite | kProtectionExecute;
  return (region.protection & kWritableExecutable) == kWritableExecutable;
}

/// Appends `address` to `text` as kAddressDigits lowercase hexadecimal digits, with leading zeros.
///
/// @param text The text to append to.
/// @param address The address to write.
void append_address(std::string& text, std::uint64_t address) {
  for (std::size_t digit = kAddressDigits; digit > 0; --digit) {
    const std::uint64_t shift = (digit - 1) * 4;
    text.push_back(kHexDigits[static_cast<std::size_t>((address >> shift) & 0xFU)]);
  }
}

/// Appends `protection` to `text` as the three letters `r`, `w` and `x`, with a dash in place of each access it
/// doesn't allow.
///
/// @param text The text to append to.
/// @param protection The protection to write, as Mach protection bits.
void append_protection(std::string& text, std::uint32_t protection) {
  text.push_back((protection & kProtectionRead) != 0 ? 'r' : '-');
  text.push_back((protection & kProtectionWrite) != 0 ? 'w' : '-');
  text.push_back((protection & kProtectionExecute) != 0 ? 'x' : '-');
}

/// Returns the text observe_regions reports for `region`: its start and end addresses, its current protection and its
/// maximum protection.
///
/// @param region The region to describe.
/// @return The text, such as `0000000104a3c000-0000000104a40000 rwx/rwx`.
[[nodiscard]] std::string describe_region(const MemoryRegion& region) {
  std::string text;
  append_address(text, region.start);
  text.push_back('-');
  append_address(text, region.end);
  text.push_back(' ');
  append_protection(text, region.protection);
  text.push_back('/');
  append_protection(text, region.max_protection);
  return text;
}

#ifdef __APPLE__
/// What read_region found at an address.
enum class RegionLookup : std::uint8_t {
  /// A region holds the address or comes after it.
  kRegion,
  /// No region is left at or above the address.
  kEnd,
  /// vm_region_64 failed, returned values that can't describe a region, or returned a port right that couldn't be
  /// released.
  kFailed,
};

/// Reads the region of the app's task that holds `address` or, when no region holds it, the first region above it.
///
/// It calls vm_region_64 with the `VM_REGION_BASIC_INFO_64` flavor, and releases the port right the call returns in
/// `object_name`, if any. The region must not be empty, must not wrap around the end of the address space, and must
/// end above `address`.
///
/// @param address The address to look from.
/// @param region Set to the region found, when the result is RegionLookup::kRegion.
/// @return RegionLookup::kRegion when a region was found, RegionLookup::kEnd when vm_region_64 reports
/// `KERN_INVALID_ADDRESS`, and RegionLookup::kFailed for any other failure.
[[nodiscard]] RegionLookup read_region(std::uint64_t address, MemoryRegion& region) {
  auto region_address = static_cast<vm_address_t>(address);
  vm_size_t size = 0;
  vm_region_basic_info_data_64_t info{};
  mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
  mach_port_t object_name = MACH_PORT_NULL;
  // NOLINTBEGIN(cppcoreguidelines-pro-type-reinterpret-cast)
  const kern_return_t result = vm_region_64(mach_task_self(), &region_address, &size, VM_REGION_BASIC_INFO_64,
                                            reinterpret_cast<vm_region_info_t>(&info), &count, &object_name);
  // NOLINTEND(cppcoreguidelines-pro-type-reinterpret-cast)
  if (MACH_PORT_VALID(object_name) && mach_port_deallocate(mach_task_self(), object_name) != KERN_SUCCESS) {
    return RegionLookup::kFailed;
  }
  if (result == KERN_INVALID_ADDRESS) {
    return RegionLookup::kEnd;
  }
  const auto start = static_cast<std::uint64_t>(region_address);
  const auto length = static_cast<std::uint64_t>(size);
  if (result != KERN_SUCCESS || count != VM_REGION_BASIC_INFO_COUNT_64 || length == 0 || start > UINT64_MAX - length ||
      start + length <= address) {
    return RegionLookup::kFailed;
  }
  region = {
      .start = start,
      .end = start + length,
      .protection = static_cast<std::uint32_t>(info.protection),
      .max_protection = static_cast<std::uint32_t>(info.max_protection),
  };
  return RegionLookup::kRegion;
}

/// Reads every region of the app's task, from address 0 up, with read_region.
///
/// @return The regions in order of address, or nothing when read_region failed or the task has more than kMaxRegions
/// regions.
[[nodiscard]] std::optional<std::vector<MemoryRegion>> read_regions() {
  std::vector<MemoryRegion> regions;
  std::uint64_t address = 0;
  for (std::size_t index = 0; index <= kMaxRegions; ++index) {
    MemoryRegion region;
    const RegionLookup lookup = read_region(address, region);
    if (lookup == RegionLookup::kEnd) {
      return regions;
    }
    if (lookup == RegionLookup::kFailed || index == kMaxRegions) {
      return std::nullopt;
    }
    regions.push_back(region);
    address = region.end;
  }
  return std::nullopt;
}
#endif

}  // namespace

Observation observe_images(std::span<const std::string> image_paths) {
  std::vector<std::string> paths;
  for (const std::string& path : image_paths) {
    if (!names_framework(path)) {
      continue;
    }
    paths.push_back(path);
    if (paths.size() == kMaxPaths) {
      break;
    }
  }
  return observed(kMapsHitsSignal, kDyldSource, std::move(paths));
}

Observation observe_loaded_images() {
#ifdef __APPLE__
  const std::uint32_t count = _dyld_image_count();
  if (count > kMaxImages) {
    return failed(kMapsHitsSignal, kDyldSource);
  }
  std::vector<std::string> images;
  images.reserve(count);
  for (std::uint32_t index = 0; index < count; ++index) {
    const char* const name = _dyld_get_image_name(index);
    if (name != nullptr) {
      images.emplace_back(name);
    }
  }
  return observe_images(images);
#else
  return unsupported(kMapsHitsSignal, kDyldSource);
#endif
}

std::string read_inserted_libraries() {
  // NOLINTNEXTLINE(concurrency-mt-unsafe)
  const char* const value = std::getenv(kInsertLibrariesVariable);
  return value == nullptr ? std::string() : std::string(std::string_view(value).substr(0, kMaxInsertedLibrariesSize));
}

Observation observe_inserted_libraries(std::string_view inserted_libraries) {
  return observed(kDyldEnvSignal, kGetenvSource, std::string(inserted_libraries.substr(0, kMaxInsertedLibrariesSize)));
}

Observation observe_loopback_port(std::uint16_t port) {
  const int descriptor = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (descriptor < 0) {
    return failed(kFridaPortSignal, kConnectSource);
  }
  const std::optional<bool> accepted = connect_socket(descriptor, loopback_address(port));
  if (close(descriptor) != 0 || !accepted.has_value()) {
    return failed(kFridaPortSignal, kConnectSource);
  }
  return observed(kFridaPortSignal, kConnectSource, *accepted);
}

Observation observe_regions(std::span<const MemoryRegion> regions) {
  std::vector<std::string> descriptions;
  for (const MemoryRegion& region : regions) {
    if (!writable_executable(region)) {
      continue;
    }
    descriptions.push_back(describe_region(region));
    if (descriptions.size() == kMaxRegionsReported) {
      break;
    }
  }
  return observed(kRwxRegionsSignal, kVmRegionSource, std::move(descriptions));
}

Observation observe_memory_regions() {
#ifdef __APPLE__
  const std::optional<std::vector<MemoryRegion>> regions = read_regions();
  if (!regions) {
    return failed(kRwxRegionsSignal, kVmRegionSource);
  }
  return observe_regions(*regions);
#else
  return unsupported(kRwxRegionsSignal, kVmRegionSource);
#endif
}

std::vector<Observation> hooks(std::string_view inserted_libraries) {
  if (!kPhysicalDevice) {
    return {
        unsupported(kMapsHitsSignal, kDyldSource),
        unsupported(kDyldEnvSignal, kGetenvSource),
        unsupported(kFridaPortSignal, kConnectSource),
        unsupported(kRwxRegionsSignal, kVmRegionSource),
    };
  }
  return {
      observe_loaded_images(),
      observe_inserted_libraries(inserted_libraries),
      observe_loopback_port(kFridaPort),
      observe_memory_regions(),
  };
}

}  // namespace rasp::ios::checks
