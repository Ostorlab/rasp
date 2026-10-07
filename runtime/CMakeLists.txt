cmake_minimum_required(VERSION 3.28)

project(rasp_runtime VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# The runtime is loaded into someone else's app: export nothing that is not asked for.
set(CMAKE_CXX_VISIBILITY_PRESET hidden)
set(CMAKE_VISIBILITY_INLINES_HIDDEN ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

add_compile_options(-Wall -Wextra -Werror)

option(RASP_BUILD_TESTS "Build the tests that run on a development machine" OFF)

add_subdirectory(core)

if(CMAKE_SYSTEM_NAME STREQUAL "iOS")
  add_subdirectory(ios)
endif()

if(RASP_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()
