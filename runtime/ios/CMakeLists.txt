enable_language(OBJCXX)
set(CMAKE_OBJCXX_STANDARD 23)
set(CMAKE_OBJCXX_STANDARD_REQUIRED ON)
set(CMAKE_OBJCXX_EXTENSIONS OFF)
set(CMAKE_OBJCXX_VISIBILITY_PRESET hidden)

# O-MVLL obfuscation of the first-party iOS runtime (Phase 1, compile-time only; see cmake/omvll_ios.cmake). The plugin
# is vendored under third_party/omvll; obfuscation is on by default for Release builds, off for Debug and host builds.
include(${CMAKE_CURRENT_SOURCE_DIR}/../cmake/omvll_ios.cmake)

add_library(RaspRuntime SHARED
  src/builtin.cpp
  src/entry.cpp
  src/monitoring.cpp
  src/checks/debugger.cpp
  src/checks/emulator.cpp
  src/checks/hooks.cpp
  src/checks/identity.cpp
  src/checks/integrity.cpp
  src/checks/jailbreak.cpp
  src/checks/mitm.cpp
  src/checks/virtualizer.cpp
  src/util/private_storage.mm
  src/util/process_query.cpp
  src/util/macho.cpp
  src/util/sha256.cpp)
target_include_directories(RaspRuntime PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src ${PROJECT_SOURCE_DIR}/posix/include)
set_source_files_properties(src/util/private_storage.mm PROPERTIES COMPILE_OPTIONS "-fobjc-arc;-fno-objc-exceptions")
target_link_libraries(RaspRuntime PRIVATE rasp_core rasp_plugins rasp_tfpsacrypto rasp_warnings rasp_language
  rasp_shipped "$<LINK_LIBRARY:FRAMEWORK,Foundation>" "$<LINK_LIBRARY:FRAMEWORK,CFNetwork>" "$<LINK_LIBRARY:FRAMEWORK,CoreFoundation>")
set_source_files_properties(src/entry.cpp PROPERTIES COMPILE_OPTIONS -Wno-global-constructors)

# Obfuscate the RaspRuntime target's own sources (ios/src/*.cpp). target_compile_options is PRIVATE, so the plugin
# applies only to this target's translation units: the first-party static libraries it links (rasp_core, rasp_plugins)
# are already compiled and ship un-obfuscated, and third-party code (tf-psa-crypto, yyjson) is left out by the scheme in
# cmake/omvll_config.py in any case. No-op unless RASP_OBFUSCATE_IOS is on.
rasp_obfuscate_ios(RaspRuntime)

if(RASP_LOGGING)
  target_sources(RaspRuntime PRIVATE src/util/logging.cpp)
endif()

set_target_properties(RaspRuntime PROPERTIES
  FRAMEWORK TRUE
  INSTALL_NAME_DIR "@rpath"
  BUILD_WITH_INSTALL_NAME_DIR ON
  MACOSX_FRAMEWORK_IDENTIFIER co.ostorlab.rasp.runtime
  MACOSX_FRAMEWORK_SHORT_VERSION_STRING ${PROJECT_VERSION}
  MACOSX_FRAMEWORK_BUNDLE_VERSION ${PROJECT_VERSION}
  MACOSX_FRAMEWORK_INFO_PLIST ${CMAKE_CURRENT_SOURCE_DIR}/Info.plist.in)

include(${PROJECT_SOURCE_DIR}/cmake/capabilities.cmake)
rasp_capabilities(RaspRuntime ios "${CMAKE_OSX_ARCHITECTURES}" ${CMAKE_OSX_DEPLOYMENT_TARGET})
