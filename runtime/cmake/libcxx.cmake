set(RASP_LIBCXX_ARCHIVE
  ${CMAKE_CURRENT_LIST_DIR}/../third_party/libcxx/libcxx-ios-arm64-iphoneos12.0-llvm23.1.3.tar.xz)
set(RASP_LIBCXX_SHA256 593c401e0bdbba59f233c6e549393b6d4bb72910e0279e8ef4307acbaf02276b)
set(RASP_LIBCXX_DIR ${CMAKE_BINARY_DIR}/libcxx)

file(SHA256 ${RASP_LIBCXX_ARCHIVE} _rasp_libcxx_actual)
if(NOT _rasp_libcxx_actual STREQUAL RASP_LIBCXX_SHA256)
  message(FATAL_ERROR
    "vendored libc++ ${RASP_LIBCXX_ARCHIVE} has sha256 ${_rasp_libcxx_actual}, expected ${RASP_LIBCXX_SHA256}")
endif()

if(NOT EXISTS ${RASP_LIBCXX_DIR}/libc++.a)
  file(MAKE_DIRECTORY ${RASP_LIBCXX_DIR})
  file(ARCHIVE_EXTRACT INPUT ${RASP_LIBCXX_ARCHIVE} DESTINATION ${RASP_LIBCXX_DIR})
endif()

target_compile_options(rasp_language INTERFACE -nostdinc++)
target_include_directories(rasp_language SYSTEM INTERFACE ${RASP_LIBCXX_DIR}/include/c++/v1)
target_link_options(rasp_language INTERFACE -nostdlib++)
target_link_libraries(rasp_language INTERFACE ${RASP_LIBCXX_DIR}/libc++.a)
