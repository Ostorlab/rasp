# Compiles the on-demand class loader's dex and embeds it in the runtime, when CMake configures the build.
#
# The loader is written in Java, in android/src/loader/GeneratingClassLoader.java. This module compiles that source
# to a dex with javac and d8 from the Android SDK, reads the dex bytes, and writes them into a generated C++ header,
# generated/loader/loader_dex_bytes.h, as the kLoaderDexBytes array. The rasp_loader_dex INTERFACE library puts that
# generated header on the include path, so loader_dex.cpp can return the bytes; the native install() loads this dex to
# create the class loader at run time.
#
# The dex is rebuilt whenever the Java source changes (CMAKE_CONFIGURE_DEPENDS). Compiling it needs javac, from a JDK,
# and the Android SDK's android.jar and d8. When they are missing, an Android build fails, because the library must
# embed the dex; a host build only leaves out this target and its test.

set(RASP_LOADER_DEX_SOURCE ${CMAKE_CURRENT_LIST_DIR}/../android/src/loader/GeneratingClassLoader.java)
set(RASP_LOADER_DEX_DIR ${CMAKE_BINARY_DIR}/loader-dex)
set(RASP_LOADER_DEX_INCLUDE_DIR ${CMAKE_BINARY_DIR}/generated)

if(NOT RASP_ANDROID_SDK)
  set(_rasp_android_sdk "$ENV{ANDROID_HOME}")
  if(NOT _rasp_android_sdk)
    set(_rasp_android_sdk "$ENV{ANDROID_SDK_ROOT}")
  endif()
  set(RASP_ANDROID_SDK "${_rasp_android_sdk}" CACHE PATH
    "The Android SDK whose android.jar and d8 compile the class loader's dex" FORCE)
endif()

find_program(RASP_JAVAC javac HINTS ENV JAVA_HOME PATH_SUFFIXES bin)
set(_rasp_android_jars "")
set(_rasp_d8s "")
if(RASP_ANDROID_SDK)
  file(GLOB _rasp_android_jars ${RASP_ANDROID_SDK}/platforms/android-*/android.jar)
  file(GLOB _rasp_d8s ${RASP_ANDROID_SDK}/build-tools/*/d8)
endif()

set(_rasp_loader_dex_missing "")
if(NOT RASP_JAVAC)
  list(APPEND _rasp_loader_dex_missing "javac from a JDK, on PATH or in JAVA_HOME")
endif()
if(NOT RASP_ANDROID_SDK)
  list(APPEND _rasp_loader_dex_missing
    "the Android SDK: set ANDROID_HOME, ANDROID_SDK_ROOT or -DRASP_ANDROID_SDK to its folder")
else()
  if(NOT _rasp_android_jars)
    list(APPEND _rasp_loader_dex_missing "a platform's android.jar under ${RASP_ANDROID_SDK}/platforms")
  endif()
  if(NOT _rasp_d8s)
    list(APPEND _rasp_loader_dex_missing "d8 from the build-tools under ${RASP_ANDROID_SDK}/build-tools")
  endif()
endif()

if(_rasp_loader_dex_missing)
  list(JOIN _rasp_loader_dex_missing "; " _rasp_loader_dex_missing)
  if(CMAKE_SYSTEM_NAME STREQUAL "Android")
    message(FATAL_ERROR "The Android library embeds the class loader's dex, compiled from ${RASP_LOADER_DEX_SOURCE}, "
      "and this needs: ${_rasp_loader_dex_missing}")
  endif()
  message(STATUS "The test of the class loader's dex is left out, because compiling it needs: "
    "${_rasp_loader_dex_missing}")
  return()
endif()

list(SORT _rasp_android_jars COMPARE NATURAL ORDER DESCENDING)
list(GET _rasp_android_jars 0 RASP_ANDROID_JAR)
list(SORT _rasp_d8s COMPARE NATURAL ORDER DESCENDING)
list(GET _rasp_d8s 0 RASP_D8)

file(REMOVE_RECURSE ${RASP_LOADER_DEX_DIR})
file(MAKE_DIRECTORY ${RASP_LOADER_DEX_DIR}/classes)
execute_process(
  COMMAND ${RASP_JAVAC} -source 8 -target 8 -bootclasspath ${RASP_ANDROID_JAR} -Xlint:-options -g:none
    -d ${RASP_LOADER_DEX_DIR}/classes ${RASP_LOADER_DEX_SOURCE}
  COMMAND_ERROR_IS_FATAL ANY)
file(GLOB_RECURSE _rasp_loader_classes ${RASP_LOADER_DEX_DIR}/classes/*.class)
execute_process(
  COMMAND ${RASP_D8} --release --min-api 31 --lib ${RASP_ANDROID_JAR} --output ${RASP_LOADER_DEX_DIR}
    ${_rasp_loader_classes}
  COMMAND_ERROR_IS_FATAL ANY)

file(READ ${RASP_LOADER_DEX_DIR}/classes.dex _rasp_loader_dex_hex HEX)
string(LENGTH "${_rasp_loader_dex_hex}" _rasp_loader_dex_hex_length)
math(EXPR _rasp_loader_dex_size "${_rasp_loader_dex_hex_length} / 2")
string(REGEX REPLACE "([0-9a-f][0-9a-f])" "0x\\1, " _rasp_loader_dex_bytes "${_rasp_loader_dex_hex}")
string(REGEX REPLACE ", $" "" _rasp_loader_dex_bytes "${_rasp_loader_dex_bytes}")
file(CONFIGURE OUTPUT ${RASP_LOADER_DEX_INCLUDE_DIR}/loader/loader_dex_bytes.h CONTENT [=[
/// The dex that defines the on-demand class loader, which cmake/loader_dex.cmake compiled from
/// android/src/loader/GeneratingClassLoader.java with javac and d8 when CMake configured this build. Generated: change
/// the Java source, not this file.

#pragma once

#include <array>
#include <cstdint>

namespace rasp::android::loader {

/// The bytes of the dex.
inline constexpr std::array<std::uint8_t, @_rasp_loader_dex_size@> kLoaderDexBytes = {@_rasp_loader_dex_bytes@};

}  // namespace rasp::android::loader
]=] @ONLY)

set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS ${RASP_LOADER_DEX_SOURCE})

add_library(rasp_loader_dex INTERFACE)
target_include_directories(rasp_loader_dex INTERFACE ${RASP_LOADER_DEX_INCLUDE_DIR})
