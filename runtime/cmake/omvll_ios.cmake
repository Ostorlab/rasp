# Obfuscates the iOS runtime with the O-MVLL clang plugin (https://obfuscator.re/o-mvll/) vendored in
# third_party/omvll/, by the scheme in omvll_config.py. This is Phase 1 of iOS obfuscation: compile-time obfuscation
# only (Layer A). There is no at-rest encryption or self-decrypt bootstrap yet (Layer B / Phase 2), so unlike Android
# the whole framework is obfuscated in place and the data-read literals in omvll_config.py (__rasp_config, the Mach-O
# lookup strings) stay readable in the shipped framework until Phase 2 adds an at-rest layer. On by default for Release.
#
# This mirrors cmake/omvll.cmake (Android) with the host/target gate flipped to macOS/arm64. O-MVLL is ABI-locked to one
# clang: the plugin and the clang that loads it must come from the same LLVM. The iOS framework builds with Xcode 27's
# clang (see .github/workflows/runtime.yml), so this vendors the O-MVLL 1.11.0 macOS plugin built for Xcode 27 -- NOT the
# Android NDK/clang-21 plugin, which cannot load here. The archive is repacked from O-MVLL's 1.11.0 macOS release
# (https://github.com/open-obfuscator/o-mvll/releases/tag/1.11.0) to just the Xcode plugin and the Python stdlib, the
# same way the Android archive is packed.
set(RASP_OMVLL_IOS_ARCHIVE
  ${CMAKE_CURRENT_LIST_DIR}/../third_party/omvll/omvll-1.11.0-xcode27-macos-arm64.tar.xz
  CACHE FILEPATH "The vendored iOS O-MVLL plugin archive")
set(RASP_OMVLL_IOS_SHA256 16fe9a48a4840aebd4969a8a255c66ad7283344799b5ff079cc9a6c266f5a445 CACHE STRING
  "SHA-256 of RASP_OMVLL_IOS_ARCHIVE")
set(RASP_OMVLL_IOS_DIR ${CMAKE_BINARY_DIR}/omvll-ios)

set(RASP_OMVLL_PLUGIN "" CACHE FILEPATH
  "Override O-MVLL's plugin dylib; empty uses the plugin vendored under third_party/omvll")
set(RASP_OMVLL_PYTHONPATH "" CACHE PATH
  "Override O-MVLL's Python standard library; empty uses the one vendored under third_party/omvll")
set(RASP_OMVLL_CONFIG ${CMAKE_CURRENT_LIST_DIR}/omvll_config.py CACHE FILEPATH
  "The O-MVLL obfuscation scheme (shared with Android)")

# On by default for Release, off for Debug/host builds -- the same rule as Android. Debug/host builds do not obfuscate,
# so iOS unit tests run against readable code; only Release (what ships) is obfuscated.
if(CMAKE_BUILD_TYPE STREQUAL "Release")
  set(_rasp_obfuscate_ios_default ON)
else()
  set(_rasp_obfuscate_ios_default OFF)
endif()
option(RASP_OBFUSCATE_IOS "Obfuscate the first-party iOS runtime with O-MVLL (default: on for Release)"
  ${_rasp_obfuscate_ios_default})

# Obfuscates `target`, when RASP_OBFUSCATE_IOS is on.
function(rasp_obfuscate_ios target)
  if(NOT RASP_OBFUSCATE_IOS)
    message(STATUS "O-MVLL off (RASP_OBFUSCATE_IOS=OFF); ${target} is not obfuscated")
    return()
  endif()
  target_compile_options(${target} PRIVATE -fpass-plugin=${RASP_OMVLL_IOS_RESOLVED_PLUGIN})
  set_target_properties(${target} PROPERTIES
    C_COMPILER_LAUNCHER "${RASP_OMVLL_IOS_LAUNCHER}"
    CXX_COMPILER_LAUNCHER "${RASP_OMVLL_IOS_LAUNCHER}")
  message(STATUS "O-MVLL on; ${target} is obfuscated with ${RASP_OMVLL_IOS_RESOLVED_PLUGIN}")
endfunction()

if(RASP_OBFUSCATE_IOS)
  # The iOS plugin runs only on a macOS arm64 host, for an Apple target, with Xcode's clang (LLVM 23). The Android gate
  # hard-fails off Linux/NDK; this is the mirror -- it hard-fails off macOS/Apple/AppleClang.
  if(NOT (CMAKE_SYSTEM_NAME STREQUAL "iOS" OR CMAKE_SYSTEM_NAME STREQUAL "Darwin"))
    message(FATAL_ERROR "RASP_OBFUSCATE_IOS is only supported for the Apple build; the iOS O-MVLL plugin is an "
      "Apple/LLVM clang plugin (building for '${CMAKE_SYSTEM_NAME}')")
  endif()
  if(NOT CMAKE_HOST_SYSTEM_NAME STREQUAL "Darwin" OR NOT CMAKE_HOST_SYSTEM_PROCESSOR STREQUAL "arm64")
    message(FATAL_ERROR "RASP_OBFUSCATE_IOS needs a macOS arm64 build host; the iOS O-MVLL plugin is a macOS-arm64 "
      "clang plugin (host is ${CMAKE_HOST_SYSTEM_NAME}/${CMAKE_HOST_SYSTEM_PROCESSOR})")
  endif()
  if(NOT CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    message(FATAL_ERROR "RASP_OBFUSCATE_IOS needs Xcode's clang; this compiler is "
      "${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}")
  endif()

  if(NOT EXISTS ${RASP_OMVLL_IOS_ARCHIVE})
    message(FATAL_ERROR "RASP_OBFUSCATE_IOS is ON but the iOS O-MVLL plugin is missing at ${RASP_OMVLL_IOS_ARCHIVE}.")
  endif()
  if(RASP_OMVLL_IOS_SHA256 STREQUAL "")
    message(FATAL_ERROR "RASP_OBFUSCATE_IOS is ON but RASP_OMVLL_IOS_SHA256 is unset; set it from the vendored archive "
      "so the build verifies the plugin.")
  endif()

  file(SHA256 ${RASP_OMVLL_IOS_ARCHIVE} _rasp_omvll_ios_actual)
  if(NOT _rasp_omvll_ios_actual STREQUAL RASP_OMVLL_IOS_SHA256)
    message(FATAL_ERROR
      "vendored iOS O-MVLL ${RASP_OMVLL_IOS_ARCHIVE} has sha256 ${_rasp_omvll_ios_actual}, "
      "expected ${RASP_OMVLL_IOS_SHA256}")
  endif()
  # Extract into a directory named after the verified SHA, so the loaded plugin always matches the pinned archive:
  # when the archive is updated, the new SHA gives a new directory, and a stale dylib from an old archive is never used.
  set(RASP_OMVLL_IOS_DIR ${RASP_OMVLL_IOS_DIR}/${RASP_OMVLL_IOS_SHA256})
  if(NOT EXISTS ${RASP_OMVLL_IOS_DIR}/omvll-xcode.dylib)
    file(MAKE_DIRECTORY ${RASP_OMVLL_IOS_DIR})
    file(ARCHIVE_EXTRACT INPUT ${RASP_OMVLL_IOS_ARCHIVE} DESTINATION ${RASP_OMVLL_IOS_DIR})
  endif()

  if(RASP_OMVLL_PLUGIN)
    set(RASP_OMVLL_IOS_RESOLVED_PLUGIN ${RASP_OMVLL_PLUGIN})
  else()
    set(RASP_OMVLL_IOS_RESOLVED_PLUGIN ${RASP_OMVLL_IOS_DIR}/omvll-xcode.dylib)
  endif()
  if(RASP_OMVLL_PYTHONPATH)
    set(RASP_OMVLL_IOS_RESOLVED_PYTHONPATH ${RASP_OMVLL_PYTHONPATH})
  else()
    set(RASP_OMVLL_IOS_RESOLVED_PYTHONPATH ${RASP_OMVLL_IOS_DIR}/Lib)
  endif()

  foreach(_rasp_omvll_ios_path
      "${RASP_OMVLL_IOS_RESOLVED_PLUGIN}" "${RASP_OMVLL_IOS_RESOLVED_PYTHONPATH}" "${RASP_OMVLL_CONFIG}")
    if(NOT EXISTS "${_rasp_omvll_ios_path}")
      message(FATAL_ERROR "RASP_OBFUSCATE_IOS: a configured path does not exist: ${_rasp_omvll_ios_path}")
    endif()
  endforeach()

  # O-MVLL reads omvll.yml from the compiler's working directory or a parent of it.
  file(WRITE "${CMAKE_BINARY_DIR}/omvll.yml"
    "OMVLL_PYTHONPATH: \"${RASP_OMVLL_IOS_RESOLVED_PYTHONPATH}\"\nOMVLL_CONFIG: \"${RASP_OMVLL_CONFIG}\"\n")

  set(RASP_OMVLL_IOS_LAUNCHER ${CMAKE_COMMAND} -E env)
endif()
