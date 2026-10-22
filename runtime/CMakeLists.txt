cmake_minimum_required(VERSION 4.4)

project(rasp_runtime VERSION 0.2.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_SCAN_FOR_MODULES OFF)

set(CMAKE_CXX_VISIBILITY_PRESET hidden)
set(CMAKE_VISIBILITY_INLINES_HIDDEN ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

add_library(rasp_warnings INTERFACE)
target_compile_options(rasp_warnings INTERFACE
  -Wall
  -Wextra
  -Werror
  -Wpedantic
  -Wshadow
  -Wconversion
  -Wsign-conversion
  -Wold-style-cast
  -Wnon-virtual-dtor
  -Wunguarded-availability)

add_library(rasp_shipped INTERFACE)
target_compile_options(rasp_shipped INTERFACE
  -Wglobal-constructors
  -Wexit-time-destructors
  -Wframe-larger-than=4096)

add_library(rasp_language INTERFACE)
target_compile_options(rasp_language INTERFACE -fno-exceptions -fno-rtti)

option(RASP_BUILD_TESTS "Build the tests that run on a development machine" OFF)
option(RASP_LOGGING "Write development logs" OFF)

if(RASP_LOGGING)
  get_property(rasp_multi_config GLOBAL PROPERTY GENERATOR_IS_MULTI_CONFIG)
  if(rasp_multi_config OR CMAKE_CONFIGURATION_TYPES)
    message(FATAL_ERROR "RASP_LOGGING needs a single-configuration generator: with a multi-configuration one, the same "
      "build directory can also build a release configuration, which must not write any log")
  endif()
  string(TOLOWER "${CMAKE_BUILD_TYPE}" rasp_build_type)
  if(NOT rasp_build_type STREQUAL "debug")
    message(FATAL_ERROR "RASP_LOGGING is for Debug builds only, and the build type is '${CMAKE_BUILD_TYPE}': "
      "any other build must not write any log")
  endif()
endif()

add_subdirectory(core)

if(CMAKE_SYSTEM_NAME STREQUAL "Android" OR RASP_BUILD_TESTS)
  include(cmake/tf_psa_crypto.cmake)
endif()

if(CMAKE_SYSTEM_NAME STREQUAL "iOS")
  include(cmake/libcxx.cmake)
  add_subdirectory(ios)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Android")
  add_subdirectory(android)
endif()

if(RASP_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()
