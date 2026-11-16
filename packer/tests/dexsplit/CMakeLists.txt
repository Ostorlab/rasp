cmake_minimum_required(VERSION 3.24)
project(dexsplit_tests LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release)
endif()

# The native core of dexsplit, built on its own, without the Python extension.
set(DEXSPLIT_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../dexsplit/src)
file(GLOB_RECURSE DEXSPLIT_SOURCES CONFIGURE_DEPENDS ${DEXSPLIT_SOURCE_DIR}/*.cpp)
add_library(dexsplit_core STATIC ${DEXSPLIT_SOURCES})
target_include_directories(dexsplit_core PUBLIC ${DEXSPLIT_SOURCE_DIR})

include(FetchContent)
FetchContent_Declare(googletest
    URL https://github.com/google/googletest/releases/download/v1.17.0/googletest-1.17.0.tar.gz
    URL_HASH SHA256=65fab701d9829d38cb77c14acdc431d2108bfdbf8979e40eb8ae567edf10b27c
    DOWNLOAD_EXTRACT_TIMESTAMP ON
    SYSTEM)
set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
set(BUILD_GMOCK OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

include(GoogleTest)
enable_testing()

# One test file per source file, at the same path: src/raw/digest.cpp is tested
# by raw/digest_test.cpp.
file(GLOB_RECURSE DEXSPLIT_TESTS CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/*_test.cpp)
add_executable(dexsplit_tests ${DEXSPLIT_TESTS})
target_include_directories(dexsplit_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_definitions(dexsplit_tests
    PRIVATE DEXSPLIT_FIXTURES="${CMAKE_CURRENT_SOURCE_DIR}/fixtures")
target_link_libraries(dexsplit_tests PRIVATE dexsplit_core GTest::gtest_main)
gtest_discover_tests(dexsplit_tests)
