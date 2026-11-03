cmake_minimum_required(VERSION 3.18)
project(dexsplit LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release)
endif()

find_package(pybind11 CONFIG REQUIRED)

# The native core: DEX reading/writing, the class model, and the small analysis
# the splitter reads (superclass, interfaces, and each method's calls, field
# accesses and type uses).
file(GLOB_RECURSE DEXSPLIT_SOURCES CONFIGURE_DEPENDS
     ${CMAKE_CURRENT_SOURCE_DIR}/dexsplit/src/*.cpp)

pybind11_add_module(_dex
    ${CMAKE_CURRENT_SOURCE_DIR}/dexsplit/bindings/dexsplit_bind.cpp
    ${DEXSPLIT_SOURCES})
target_include_directories(_dex PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/dexsplit/src)

# The extension installs next to the pure-Python dexsplit package, so it imports
# as dexsplit._dex.
install(TARGETS _dex DESTINATION dexsplit)
