# Obfuscates the iOS runtime with the O-MVLL clang plugin (https://obfuscator.re/o-mvll/) vendored in
# third_party/omvll/, by the scheme in omvll_config.py. This is Phase 1 of iOS obfuscation: compile-time obfuscation
# only (Layer A). There is no at-rest encryption or self-decrypt bootstrap in this parent, so
# nothing is encrypted at rest: transformed code ships in place and the data-read literals in omvll_config.py
# (__rasp_config, the Mach-O lookup strings, the iOS checks' path and marker literals) stay readable in the shipped
# framework. The plugin is applied to the RaspRuntime target alone, so it
# processes its own C++/Objective-C++ sources and directly compiled core host bridge; static libraries (rasp_core,
# rasp_plugins) are compiled without the plugin. On by default for Release.
#
# Android has no plugin integration in this parent. O-MVLL is ABI-locked to one
# clang: the plugin and the clang that loads it must come from the same LLVM. The iOS framework builds with Xcode 27's
# clang (see .github/workflows/runtime.yml), so this vendors the O-MVLL 1.11.0 macOS plugin built for Xcode 27 -- NOT the
# Android NDK/clang-21 plugin, which cannot load here. The archive is repacked from O-MVLL's 1.11.0 macOS release
# (https://github.com/open-obfuscator/o-mvll/releases/tag/1.11.0) to just the Xcode plugin and the Python stdlib,
# without introducing another compiler or a download.
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
  "The O-MVLL obfuscation scheme")

# On by default for Release, off for Debug/host builds. Debug/host builds do not obfuscate,
# so iOS unit tests run against readable code; only Release (what ships) is obfuscated.
if(CMAKE_BUILD_TYPE STREQUAL "Release")
  set(_rasp_obfuscate_ios_default ON)
else()
  set(_rasp_obfuscate_ios_default OFF)
endif()
option(RASP_OBFUSCATE_IOS "Obfuscate the first-party iOS runtime with O-MVLL (default: on for Release)"
  ${_rasp_obfuscate_ios_default})
if(DEFINED RASP_OMVLL_SEED OR DEFINED RASP_OMVLL_SEED_MODE)
  message(FATAL_ERROR "O-MVLL seed settings are environment inputs, not CMake cache variables")
endif()
if(NOT RASP_OBFUSCATE_IOS AND (DEFINED ENV{RASP_OMVLL_SEED} OR DEFINED ENV{RASP_OMVLL_SEED_MODE}))
  message(FATAL_ERROR "Explicit O-MVLL seed settings require RASP_OBFUSCATE_IOS=ON")
endif()

# Obfuscates `target`, when RASP_OBFUSCATE_IOS is on.
function(rasp_obfuscate_ios target)
  if(NOT RASP_OBFUSCATE_IOS)
    message(STATUS "O-MVLL off (RASP_OBFUSCATE_IOS=OFF); ${target} is not obfuscated")
    return()
  endif()
  target_compile_options(${target} PRIVATE -fpass-plugin=${RASP_OMVLL_IOS_RESOLVED_PLUGIN})
  set_target_properties(${target} PROPERTIES
    C_COMPILER_LAUNCHER "${RASP_OMVLL_IOS_LAUNCHER}"
    CXX_COMPILER_LAUNCHER "${RASP_OMVLL_IOS_LAUNCHER}"
    OBJCXX_COMPILER_LAUNCHER "${RASP_OMVLL_IOS_LAUNCHER}")
  message(STATUS "O-MVLL on; ${target} is obfuscated with ${RASP_OMVLL_IOS_RESOLVED_PLUGIN}")
endfunction()

if(RASP_OBFUSCATE_IOS)
  # The iOS plugin requires a macOS arm64 host and its matching Xcode compiler. The vendored plugin embeds LLVM
  # 21.1.6; the separate LLVM 23 tidy/libc++ tooling is not the compiler ABI that loads this plugin. These gates
  # do not attest the exact Xcode build or compiler bytes; platform CI remains required.
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
  # The launcher preparation also compares the default extracted plugin with the archive member, rather than
  # trusting an existing cache directory merely because its name contains the archive hash.
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

  find_package(Python3 REQUIRED COMPONENTS Interpreter)
  set(_rasp_omvll_launcher ${CMAKE_CURRENT_LIST_DIR}/omvll_launcher.py)
  set(_rasp_omvll_policy ${CMAKE_BINARY_DIR}/omvll-seed-policy.json)
  set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
    ${_rasp_omvll_launcher} ${CMAKE_CURRENT_LIST_DIR}/omvll_seed.py ${RASP_OMVLL_CONFIG})
  set(_rasp_omvll_archive_argument)
  if(NOT RASP_OMVLL_PLUGIN)
    list(APPEND _rasp_omvll_archive_argument --archive ${RASP_OMVLL_IOS_ARCHIVE})
  endif()
  # -E ignores Python environment injection; -s omits user site packages while retaining the launcher's helper.
  # One seed is captured for the build directory; regeneration without the original shell environment retains it.
  execute_process(
    COMMAND ${Python3_EXECUTABLE} -E -s -B ${_rasp_omvll_launcher} freeze
      --state ${_rasp_omvll_policy} --previous-sha256 "${RASP_OMVLL_POLICY_SHA256}"
      --yaml ${CMAKE_BINARY_DIR}/omvll.yml --config ${RASP_OMVLL_CONFIG}
      --plugin ${RASP_OMVLL_IOS_RESOLVED_PLUGIN} --pythonpath ${RASP_OMVLL_IOS_RESOLVED_PYTHONPATH}
      ${_rasp_omvll_archive_argument}
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    RESULT_VARIABLE _rasp_omvll_policy_result
    OUTPUT_VARIABLE _rasp_omvll_policy_sha256
    ERROR_VARIABLE _rasp_omvll_policy_error
    OUTPUT_STRIP_TRAILING_WHITESPACE)
  if(NOT _rasp_omvll_policy_result EQUAL 0)
    message(FATAL_ERROR "O-MVLL policy capture failed: ${_rasp_omvll_policy_error}")
  endif()
  set(RASP_OMVLL_POLICY_SHA256 "${_rasp_omvll_policy_sha256}" CACHE INTERNAL "Frozen O-MVLL compile policy digest" FORCE)
  set(RASP_OMVLL_IOS_LAUNCHER ${Python3_EXECUTABLE} -E -s -B ${_rasp_omvll_launcher} run
    --state ${_rasp_omvll_policy} --sha256 ${RASP_OMVLL_POLICY_SHA256} --)
endif()
