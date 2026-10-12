include(${PROJECT_SOURCE_DIR}/cmake/trust_anchors.cmake)
rasp_write_trust_anchors(${CMAKE_CURRENT_BINARY_DIR}/generated/reporting/trust_anchors.h)

add_library(rasp SHARED
  src/entry.cpp
  src/checks/example.cpp
  src/payload/cipher.cpp
  src/payload/payload.cpp
  src/reporting/socket.cpp
  src/reporting/thread.cpp
  src/reporting/tls_transport.cpp)
target_include_directories(rasp PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src ${CMAKE_CURRENT_BINARY_DIR}/generated)
target_link_libraries(rasp PRIVATE rasp_core rasp_mbedtls rasp_warnings rasp_language rasp_shipped)
target_link_options(rasp PRIVATE -Wl,--exclude-libs,ALL)

if(RASP_LOGGING)
  target_sources(rasp PRIVATE src/util/logging.cpp)
  target_link_libraries(rasp PRIVATE log)
endif()
