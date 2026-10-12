set(RASP_MBEDTLS_VERSION 3.6.7)
set(RASP_MBEDTLS_ARCHIVE
  ${CMAKE_CURRENT_LIST_DIR}/../third_party/mbedtls/mbedtls-${RASP_MBEDTLS_VERSION}-source.tar.xz)
set(RASP_MBEDTLS_SHA256 3c9fdfd101d8813d6b0db4dc3fdb4c28a3e20174eb5951e14e84117259e4efd1)
set(RASP_MBEDTLS_DIR ${CMAKE_BINARY_DIR}/mbedtls/mbedtls-${RASP_MBEDTLS_VERSION})

file(SHA256 ${RASP_MBEDTLS_ARCHIVE} _rasp_mbedtls_actual)
if(NOT _rasp_mbedtls_actual STREQUAL RASP_MBEDTLS_SHA256)
  message(FATAL_ERROR
    "vendored Mbed TLS ${RASP_MBEDTLS_ARCHIVE} has sha256 ${_rasp_mbedtls_actual}, expected ${RASP_MBEDTLS_SHA256}")
endif()

if(NOT EXISTS ${RASP_MBEDTLS_DIR}/library/CMakeLists.txt)
  file(MAKE_DIRECTORY ${CMAKE_BINARY_DIR}/mbedtls)
  file(ARCHIVE_EXTRACT INPUT ${RASP_MBEDTLS_ARCHIVE} DESTINATION ${CMAKE_BINARY_DIR}/mbedtls)
endif()

include(GNUInstallDirs)
set(MBEDTLS_DIR ${RASP_MBEDTLS_DIR})
set(MBEDTLS_TARGET_PREFIX rasp_)
set(MBEDTLS_CONFIG_FILE ${CMAKE_CURRENT_LIST_DIR}/../third_party/mbedtls/mbedtls_config.h)
set(USE_STATIC_MBEDTLS_LIBRARY ON)
set(USE_SHARED_MBEDTLS_LIBRARY OFF)
set(GEN_FILES OFF)
add_subdirectory(${RASP_MBEDTLS_DIR}/library ${CMAKE_BINARY_DIR}/mbedtls-build EXCLUDE_FROM_ALL SYSTEM)
set_target_properties(rasp_mbedcrypto rasp_mbedx509 rasp_mbedtls PROPERTIES C_VISIBILITY_PRESET hidden)
