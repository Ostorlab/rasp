# Wires O-MVLL (https://obfuscator.re/o-mvll/) into the first-party runtime targets, so their code is
# obfuscated at build time. O-MVLL is a clang pass plugin, loaded with -fpass-plugin. The obfuscation
# scheme is omvll_config.py, next to this file; both the scheme and this wiring are committed.
#
# Obfuscation is on by default for a Release build and off for a Debug build, and RASP_OBFUSCATE
# overrides either way. It works only when the Android library is built on a Linux x86_64 host, because
# the vendored plugin is a linux-x86_64 clang plugin, ABI-locked to one NDK: O-MVLL 1.11.0 against NDK
# r29 (clang 21, revision r563880c). The plugin and the Python standard library it needs are vendored as
# a compressed archive under third_party/omvll/, checked against a recorded SHA-256 and extracted into
# the build tree, the same way third_party/libcxx is handled.

set(RASP_OMVLL_ARCHIVE
  ${CMAKE_CURRENT_LIST_DIR}/../third_party/omvll/omvll-1.11.0-ndk-r29-clang21-linux-x86_64.tar.xz)
set(RASP_OMVLL_SHA256 070ce0de8bf11a6d0cb4668b149771e21454170d9f31211cca9b9780dbecdd71)
set(RASP_OMVLL_DIR ${CMAKE_BINARY_DIR}/omvll)

set(RASP_OMVLL_PLUGIN "" CACHE FILEPATH
  "Override O-MVLL's omvll-ndk.so; empty uses the plugin vendored under third_party/omvll")
set(RASP_OMVLL_PYTHONPATH "" CACHE PATH
  "Override O-MVLL's Python standard library; empty uses the one vendored under third_party/omvll")
set(RASP_OMVLL_CONFIG ${CMAKE_CURRENT_LIST_DIR}/omvll_config.py CACHE FILEPATH
  "The O-MVLL obfuscation scheme")

if(CMAKE_BUILD_TYPE STREQUAL "Release")
  set(_rasp_obfuscate_default ON)
else()
  set(_rasp_obfuscate_default OFF)
endif()
option(RASP_OBFUSCATE "Obfuscate the first-party runtime code with O-MVLL (default: on for Release)"
  ${_rasp_obfuscate_default})

# Obfuscates `target` with O-MVLL. A no-op when RASP_OBFUSCATE is off, so Debug and host builds stay
# readable and need none of the plugin.
function(rasp_obfuscate target)
  if(NOT RASP_OBFUSCATE)
    message(STATUS "O-MVLL off (RASP_OBFUSCATE=OFF); ${target} is not obfuscated")
    return()
  endif()
  target_compile_options(${target} PRIVATE -fpass-plugin=${RASP_OMVLL_RESOLVED_PLUGIN})
  set_target_properties(${target} PROPERTIES CXX_COMPILER_LAUNCHER "${RASP_OMVLL_LAUNCHER}")
  message(STATUS "O-MVLL on; ${target} is obfuscated with ${RASP_OMVLL_RESOLVED_PLUGIN}")
endfunction()

if(RASP_OBFUSCATE)
  # The vendored plugin is an Android-NDK clang plugin for a linux-x86_64 host, so it can only run on
  # that host and only transforms an Android build. Fail at configure time, with a clear reason, rather
  # than later as an opaque plugin-load error.
  if(NOT CMAKE_SYSTEM_NAME STREQUAL "Android")
    message(FATAL_ERROR "RASP_OBFUSCATE is only supported for the Android build; the vendored O-MVLL "
      "plugin is an Android-NDK clang plugin (building for '${CMAKE_SYSTEM_NAME}')")
  endif()
  if(NOT CMAKE_HOST_SYSTEM_NAME STREQUAL "Linux" OR NOT CMAKE_HOST_SYSTEM_PROCESSOR STREQUAL "x86_64")
    message(FATAL_ERROR "RASP_OBFUSCATE needs a Linux x86_64 build host; the vendored O-MVLL plugin is a "
      "linux-x86_64 clang plugin (host is ${CMAKE_HOST_SYSTEM_NAME}/${CMAKE_HOST_SYSTEM_PROCESSOR})")
  endif()
  # O-MVLL 1.11.0 is ABI-locked to NDK r29's clang 21; another toolchain loads the plugin but mismatches
  # its LLVM, so require r29 and clang 21 up front.
  if(NOT ANDROID_NDK_REVISION MATCHES "^29\\.")
    message(FATAL_ERROR "RASP_OBFUSCATE needs Android NDK r29; this NDK is revision ${ANDROID_NDK_REVISION}")
  endif()
  if(NOT CMAKE_CXX_COMPILER_VERSION MATCHES "^21\\.")
    message(FATAL_ERROR "RASP_OBFUSCATE needs NDK r29's clang 21; this compiler is "
      "${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}")
  endif()

  file(SHA256 ${RASP_OMVLL_ARCHIVE} _rasp_omvll_actual)
  if(NOT _rasp_omvll_actual STREQUAL RASP_OMVLL_SHA256)
    message(FATAL_ERROR
      "vendored O-MVLL ${RASP_OMVLL_ARCHIVE} has sha256 ${_rasp_omvll_actual}, expected ${RASP_OMVLL_SHA256}")
  endif()
  if(NOT EXISTS ${RASP_OMVLL_DIR}/omvll-ndk.so)
    file(MAKE_DIRECTORY ${RASP_OMVLL_DIR})
    file(ARCHIVE_EXTRACT INPUT ${RASP_OMVLL_ARCHIVE} DESTINATION ${RASP_OMVLL_DIR})
  endif()

  if(RASP_OMVLL_PLUGIN)
    set(RASP_OMVLL_RESOLVED_PLUGIN ${RASP_OMVLL_PLUGIN})
  else()
    set(RASP_OMVLL_RESOLVED_PLUGIN ${RASP_OMVLL_DIR}/omvll-ndk.so)
  endif()
  if(RASP_OMVLL_PYTHONPATH)
    set(RASP_OMVLL_RESOLVED_PYTHONPATH ${RASP_OMVLL_PYTHONPATH})
  else()
    set(RASP_OMVLL_RESOLVED_PYTHONPATH ${RASP_OMVLL_DIR}/Lib)
  endif()

  foreach(_rasp_omvll_path
      "${RASP_OMVLL_RESOLVED_PLUGIN}" "${RASP_OMVLL_RESOLVED_PYTHONPATH}" "${RASP_OMVLL_CONFIG}")
    if(NOT EXISTS "${_rasp_omvll_path}")
      message(FATAL_ERROR "RASP_OBFUSCATE: a configured path does not exist: ${_rasp_omvll_path}")
    endif()
  endforeach()

  # O-MVLL reads the config and stdlib paths from omvll.yml in the compiler's working directory or any
  # parent of it. The compiler runs under the build tree, so one written at its root is found.
  file(WRITE "${CMAKE_BINARY_DIR}/omvll.yml"
    "OMVLL_PYTHONPATH: \"${RASP_OMVLL_RESOLVED_PYTHONPATH}\"\nOMVLL_CONFIG: \"${RASP_OMVLL_CONFIG}\"\n")

  # The plugin is built against the NDK toolchain, so run the compiler with that toolchain's own lib
  # directory on LD_LIBRARY_PATH, where its libc++ lives, so the plugin resolves against the same one.
  get_filename_component(_rasp_ndk_bin ${CMAKE_CXX_COMPILER} DIRECTORY)
  get_filename_component(_rasp_ndk_toolchain ${_rasp_ndk_bin} DIRECTORY)
  set(RASP_OMVLL_LAUNCHER ${CMAKE_COMMAND} -E env LD_LIBRARY_PATH=${_rasp_ndk_toolchain}/lib)
endif()
