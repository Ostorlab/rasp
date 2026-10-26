/// The iOS hooking checks: whether an instrumentation or hooking framework has loaded its code into the app's process,
/// which libraries the app's environment asks dyld to insert into it, and whether a server listens on Frida's default
/// port.

#pragma once

#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "rasp/observation.h"

namespace rasp::ios::checks {

/// Runs the hooking checks and returns what they observed.
///
/// It reads the list of images loaded in the process and reports the ones that look like a known instrumentation or
/// hooking framework (Frida, Cycript, Substrate and the tweak loaders that replace it, SSL Kill Switch and the like).
/// It also reports `inserted_libraries`, the value of `DYLD_INSERT_LIBRARIES` that read_inserted_libraries read when
/// the runtime loaded, and whether a TCP connection to port 27042 of the loopback address is accepted, the port that
/// frida-server and Frida Gadget listen on by default. The checks report the raw paths and the raw values; the server
/// decides.
///
/// On a physical iOS device it runs the probes. Anywhere else, on a simulator, a Mac or a Linux host, every observation
/// is unsupported instead, so the result still shows that the check ran.
///
/// @param inserted_libraries The value of `DYLD_INSERT_LIBRARIES` when the runtime loaded, as read_inserted_libraries
/// returns it.
/// @return One observation per signal and source, in this order: hook.maps_hits read through dyld, hook.dyld_env read
/// through getenv, then hook.frida_port read through connect.
[[nodiscard]] std::vector<Observation> hooks(std::string_view inserted_libraries);

/// Reports the paths of `image_paths` that name a known instrumentation or hooking framework.
///
/// A path names a framework when its file name, the last component of the path, contains a known marker, such as
/// `frida-gadget`, `fridagadget`, `mobilesubstrate`, `libhooker` or `libellekit`. The folders above the file, such as
/// the name of the app's bundle, are not matched against the markers, so an app named after a marker, or a framework
/// such as `SubstrateSdk`, is not reported.
///
/// A path also names a framework when it is in a folder that only holds tweaks or a tweak loader, such as
/// `/Library/MobileSubstrate/DynamicLibraries/`, `/usr/lib/TweakInject/` or `/usr/lib/ellekit/`, whatever its file
/// name. The folder is matched at the start of the path, or right after the root of a rootless jailbreak: `/var/jb`,
/// `/private/var/jb`, or the real folder `/var/jb` links to, which dyld reports as a path under `/private/preboot/`
/// that goes through a `procursus` folder. Markers and folders are both matched without regard to case.
///
/// The list holds at most the first 32 matching paths, in the order of `image_paths`. An empty list is a real answer,
/// not a failure.
///
/// @param image_paths The paths of the images to look at, such as the images loaded in the process.
/// @return One hook.maps_hits observation read through dyld, with the matching paths.
[[nodiscard]] Observation observe_images(std::span<const std::string> image_paths);

/// Reports the images loaded in the process that name a known instrumentation or hooking framework.
///
/// The probe walks dyld's list of loaded images with _dyld_image_count and _dyld_get_image_name, and passes their paths
/// to observe_images. The list is read again on every call, so it also sees a framework loaded after the app started.
/// Another thread can load or unload an image during the walk: an image unloaded during the walk has no name, and is
/// skipped, and an image loaded during the walk may be missed until the next call. On a system without dyld, such as
/// Linux, there is nothing to read.
///
/// @return One hook.maps_hits observation read through dyld, as observe_images reports it. It has an error status when
/// the process has more than 4096 images, and the unsupported status on a system without dyld.
[[nodiscard]] Observation observe_loaded_images();

/// Returns the value of `DYLD_INSERT_LIBRARIES` in the app's environment, the variable that asks dyld to load extra
/// libraries into the process before the app's own code.
///
/// It reads the variable with getenv and returns a copy of at most its first 4096 bytes. getenv isn't safe while
/// another thread changes the environment with setenv or unsetenv, and the environment belongs to the app, whose
/// threads may do so at any moment. So it must only be called while the runtime loads, on the app's main thread, before
/// the app's own code runs, and the copy is what the checks report from then on. A change the app makes to the variable
/// later is not seen.
///
/// @return The value of the variable, at most its first 4096 bytes, or an empty string when it is unset.
[[nodiscard]] std::string read_inserted_libraries();

/// Reports `inserted_libraries`, the value of `DYLD_INSERT_LIBRARIES` when the runtime loaded.
///
/// The value is reported as it is, a list of paths separated by colons, and the probe doesn't judge it. At most its
/// first 4096 bytes are reported. An empty value is a real answer, not a failure: the variable was unset, or was set to
/// an empty value. dyld reads the variable before the runtime loads, and code that ran before the runtime, such as a
/// library the variable inserted, can remove it from the environment, so an empty value doesn't mean that no library
/// was inserted.
///
/// @param inserted_libraries The value of the variable, as read_inserted_libraries returns it.
/// @return One hook.dyld_env observation read through getenv, with the value as a string.
[[nodiscard]] Observation observe_inserted_libraries(std::string_view inserted_libraries);

/// Reports whether a TCP connection to `port` of the loopback address, 127.0.0.1, is accepted.
///
/// frida-server, and Frida Gadget when it waits for a client, listen on port 27042 of the loopback address by default,
/// and hooks passes that port. The probe opens a TCP socket that doesn't block, connects it to the port, waits at most
/// 250 milliseconds for the connection to be accepted or refused, and closes the socket without sending anything. It
/// reports what it saw and doesn't judge it: another program listening on the port is reported the same way, and a
/// Frida server listening on another port isn't seen. The connection is tried again on every call, so the probe also
/// sees a server started after the app. The loopback address is not on a local network, so on iOS 14 and later the
/// connection doesn't bring up the local network permission alert. The probe uses only POSIX sockets, so it also runs
/// on a Mac or a Linux host.
///
/// @param port The TCP port to connect to, in host byte order.
/// @return One hook.frida_port observation read through connect: true when the connection is accepted, false when it
/// is refused. It has an error status when a system call fails, or when the connection is neither accepted nor refused
/// within 250 milliseconds.
[[nodiscard]] Observation observe_loopback_port(std::uint16_t port);

}  // namespace rasp::ios::checks
