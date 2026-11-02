# Obfuscates the self-decrypt bootstrap with the O-MVLL clang plugin (https://obfuscator.re/o-mvll/), by the scheme in
# omvll_config.py. The plugin is a 22 MB binary, so it is NOT committed: it is downloaded by pinned SHA-256 (like
# runtime/tests fetches GoogleTest) from RASP_OMVLL_URL. O-MVLL is opt-in here (RASP_OBFUSCATE, default off): a build
# without the plugin URL still works; a production build sets -DRASP_OBFUSCATE=ON and the artifact URL. Adapted from the
# feature/android-obfuscation branch's omvll.cmake, in pinned-download form.

set(RASP_OMVLL_SHA256 070ce0de8bf11a6d0cb4668b149771e21454170d9f31211cca9b9780dbecdd71)
set(RASP_OMVLL_URL "" CACHE STRING
  "URL of the O-MVLL plugin archive (omvll-1.11.0-ndk-r29-clang21-linux-x86_64.tar.xz); its SHA-256 is pinned")
set(RASP_OMVLL_DIR ${CMAKE_BINARY_DIR}/omvll)
set(RASP_OMVLL_ARCHIVE ${RASP_OMVLL_DIR}/omvll.tar.xz)

set(RASP_OMVLL_PLUGIN "" CACHE FILEPATH
  "Override O-MVLL's omvll-ndk.so; empty uses the one downloaded from RASP_OMVLL_URL")
set(RASP_OMVLL_PYTHONPATH "" CACHE PATH
  "Override O-MVLL's Python standard library; empty uses the one downloaded from RASP_OMVLL_URL")
set(RASP_OMVLL_CONFIG ${CMAKE_CURRENT_LIST_DIR}/omvll_config.py CACHE FILEPATH
  "The O-MVLL obfuscation scheme")

option(RASP_OBFUSCATE "Obfuscate the self-decrypt bootstrap with O-MVLL (needs the plugin; default off)" OFF)

# Obfuscates `target`'s bootstrap translation units, when RASP_OBFUSCATE is on. The scheme in omvll_config.py is a no-op
# on every non-bootstrap module, so applying the plugin to the whole target only costs build time.
function(rasp_obfuscate target)
  if(NOT RASP_OBFUSCATE)
    message(STATUS "O-MVLL off (RASP_OBFUSCATE=OFF); ${target}'s bootstrap is not obfuscated")
    return()
  endif()
  target_compile_options(${target} PRIVATE -fpass-plugin=${RASP_OMVLL_RESOLVED_PLUGIN})
  set_target_properties(${target} PROPERTIES
    C_COMPILER_LAUNCHER "${RASP_OMVLL_LAUNCHER}"
    CXX_COMPILER_LAUNCHER "${RASP_OMVLL_LAUNCHER}")
  message(STATUS "O-MVLL on; ${target}'s bootstrap is obfuscated with ${RASP_OMVLL_RESOLVED_PLUGIN}")
endfunction()

if(RASP_OBFUSCATE)
  # The plugin runs only on a Linux x86_64 host, for an Android build, with NDK r29's clang 21.
  if(NOT CMAKE_SYSTEM_NAME STREQUAL "Android")
    message(FATAL_ERROR "RASP_OBFUSCATE is only supported for the Android build (building for '${CMAKE_SYSTEM_NAME}')")
  endif()
  if(NOT CMAKE_HOST_SYSTEM_NAME STREQUAL "Linux" OR NOT CMAKE_HOST_SYSTEM_PROCESSOR STREQUAL "x86_64")
    message(FATAL_ERROR "RASP_OBFUSCATE needs a Linux x86_64 build host (host is "
      "${CMAKE_HOST_SYSTEM_NAME}/${CMAKE_HOST_SYSTEM_PROCESSOR})")
  endif()
  if(NOT ANDROID_NDK_REVISION MATCHES "^29\\.")
    message(FATAL_ERROR "RASP_OBFUSCATE needs Android NDK r29; this NDK is revision ${ANDROID_NDK_REVISION}")
  endif()
  if(NOT CMAKE_CXX_COMPILER_VERSION MATCHES "^21\\.")
    message(FATAL_ERROR "RASP_OBFUSCATE needs NDK r29's clang 21; this compiler is "
      "${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}")
  endif()

  if(RASP_OMVLL_PLUGIN)
    set(RASP_OMVLL_RESOLVED_PLUGIN ${RASP_OMVLL_PLUGIN})
    set(RASP_OMVLL_RESOLVED_PYTHONPATH ${RASP_OMVLL_PYTHONPATH})
  else()
    if(NOT RASP_OMVLL_URL)
      message(FATAL_ERROR "RASP_OBFUSCATE needs RASP_OMVLL_URL (the plugin archive is not committed) or RASP_OMVLL_PLUGIN")
    endif()
    if(NOT EXISTS ${RASP_OMVLL_DIR}/omvll-ndk.so)
      file(MAKE_DIRECTORY ${RASP_OMVLL_DIR})
      file(DOWNLOAD ${RASP_OMVLL_URL} ${RASP_OMVLL_ARCHIVE} EXPECTED_HASH SHA256=${RASP_OMVLL_SHA256} SHOW_PROGRESS)
      file(ARCHIVE_EXTRACT INPUT ${RASP_OMVLL_ARCHIVE} DESTINATION ${RASP_OMVLL_DIR})
    endif()
    set(RASP_OMVLL_RESOLVED_PLUGIN ${RASP_OMVLL_DIR}/omvll-ndk.so)
    set(RASP_OMVLL_RESOLVED_PYTHONPATH ${RASP_OMVLL_DIR}/Lib)
  endif()

  foreach(_rasp_omvll_path "${RASP_OMVLL_RESOLVED_PLUGIN}" "${RASP_OMVLL_RESOLVED_PYTHONPATH}" "${RASP_OMVLL_CONFIG}")
    if(NOT EXISTS "${_rasp_omvll_path}")
      message(FATAL_ERROR "RASP_OBFUSCATE: a configured path does not exist: ${_rasp_omvll_path}")
    endif()
  endforeach()

  # O-MVLL reads omvll.yml from the compiler's working directory or a parent of it.
  file(WRITE "${CMAKE_BINARY_DIR}/omvll.yml"
    "OMVLL_PYTHONPATH: \"${RASP_OMVLL_RESOLVED_PYTHONPATH}\"\nOMVLL_CONFIG: \"${RASP_OMVLL_CONFIG}\"\n")

  # The plugin needs the NDK toolchain's own libc++.
  get_filename_component(_rasp_ndk_bin ${CMAKE_CXX_COMPILER} DIRECTORY)
  get_filename_component(_rasp_ndk_toolchain ${_rasp_ndk_bin} DIRECTORY)
  set(RASP_OMVLL_LAUNCHER ${CMAKE_COMMAND} -E env LD_LIBRARY_PATH=${_rasp_ndk_toolchain}/lib)
endif()
