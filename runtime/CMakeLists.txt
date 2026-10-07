cmake_minimum_required(VERSION 4.4)

project(rasp_runtime VERSION 0.1.0 LANGUAGES CXX)

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

if(RASP_LOGGING AND CMAKE_BUILD_TYPE STREQUAL "Release")
  message(FATAL_ERROR "RASP_LOGGING is for development builds only: a Release build must not write any log")
endif()

add_subdirectory(core)
add_subdirectory(checks)

if(CMAKE_SYSTEM_NAME STREQUAL "iOS")
  include(cmake/libcxx.cmake)
  add_subdirectory(ios)
endif()

if(RASP_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()
