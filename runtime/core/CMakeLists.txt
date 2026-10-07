# Code shared by every platform. It uses no platform API.
configure_file(include/rasp/version.h.in ${CMAKE_CURRENT_BINARY_DIR}/include/rasp/version.h @ONLY)

add_library(rasp_core INTERFACE)
target_include_directories(rasp_core INTERFACE
  ${CMAKE_CURRENT_SOURCE_DIR}/include
  ${CMAKE_CURRENT_BINARY_DIR}/include)
