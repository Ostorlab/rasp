# Companion is opt-in and is never a dependency of an injected runtime target.
add_library(rasp_scoped_keys STATIC src/encoding.cpp src/manifest.cpp src/service.cpp src/jobs.cpp src/facade.cpp)
target_include_directories(rasp_scoped_keys PUBLIC include ${PROJECT_SOURCE_DIR}/core/include PRIVATE src)
# The pinned stateless SHA primitive avoids PSA wrapper input/output heap copies and key/RNG state.
target_compile_definitions(rasp_scoped_keys PRIVATE MBEDTLS_DECLARE_PRIVATE_IDENTIFIERS)
target_link_libraries(rasp_scoped_keys PRIVATE rasp_tfpsacrypto rasp_warnings rasp_language rasp_shipped)
install(TARGETS rasp_scoped_keys ARCHIVE DESTINATION lib COMPONENT key_companion)
install(FILES $<TARGET_FILE:rasp_tfpsacrypto> DESTINATION lib COMPONENT key_companion)
if(CMAKE_SYSTEM_NAME STREQUAL "iOS" AND NOT RASP_IOS_SYSTEM_LIBCXX)
  install(FILES ${RASP_LIBCXX_DIR}/libc++.a DESTINATION lib COMPONENT key_companion)
endif()
install(FILES include/module.modulemap DESTINATION include COMPONENT key_companion)
install(FILES include/rasp/scoped_key.h ${PROJECT_SOURCE_DIR}/core/include/rasp/local_policy_host.h
  DESTINATION include/rasp COMPONENT key_companion)

if(RASP_BUILD_TESTS)
  include(FetchContent)
  FetchContent_Declare(googletest
    URL https://github.com/google/googletest/releases/download/v1.17.0/googletest-1.17.0.tar.gz
    URL_HASH SHA256=65fab701d9829d38cb77c14acdc431d2108bfdbf8979e40eb8ae567edf10b27c SYSTEM)
  # Apply the shared test-only policy before this first GoogleTest consumer.
  set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
  set(BUILD_GMOCK OFF CACHE BOOL "" FORCE)
  FetchContent_MakeAvailable(googletest)
  # Match the shipped no-RTTI fixtures; mixed RTTI vtables fail UBSan during gtest discovery.
  target_link_libraries(gtest PRIVATE rasp_language)
  target_link_libraries(gtest_main PRIVATE rasp_language)
  find_package(OpenSSL REQUIRED)
  add_executable(rasp_keys_test tests/service_test.cpp tests/support.cpp tests/abi_test.cpp
    tests/encoding_test.cpp tests/manifest_test.cpp tests/adapter_test.cpp
    ${PROJECT_SOURCE_DIR}/core/src/local_policy_host.cpp)
  target_include_directories(rasp_keys_test PRIVATE src tests ${PROJECT_SOURCE_DIR}/core/src)
  target_link_libraries(rasp_keys_test PRIVATE rasp_scoped_keys rasp_core rasp_tfpsacrypto GTest::gtest_main OpenSSL::Crypto rasp_warnings rasp_language)
  include(GoogleTest)
  gtest_discover_tests(rasp_keys_test)
  if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_sources(rasp_keys_test PRIVATE tests/contention.cpp)
    target_link_options(rasp_keys_test PRIVATE "LINKER:--wrap=pthread_mutex_trylock,--wrap=pthread_mutex_lock")
  endif()
  if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_executable(rasp_keys_history_test tests/history_test.cpp tests/support.cpp
      ${PROJECT_SOURCE_DIR}/core/src/local_policy_host.cpp)
    target_include_directories(rasp_keys_history_test PRIVATE src tests ${PROJECT_SOURCE_DIR}/core/src)
    target_link_libraries(rasp_keys_history_test PRIVATE rasp_scoped_keys rasp_core rasp_tfpsacrypto GTest::gtest_main
      OpenSSL::Crypto rasp_warnings rasp_language)
    gtest_discover_tests(rasp_keys_history_test TEST_PREFIX "ScopedHistory." PROPERTIES RUN_SERIAL TRUE TIMEOUT 60)
  endif()
  add_executable(rasp_keys_report_test tests/adapter_test.cpp tests/support.cpp
    ${PROJECT_SOURCE_DIR}/core/src/local_policy_host.cpp)
  target_compile_definitions(rasp_keys_report_test PRIVATE RASP_KEYS_TEST_REPORT_ONLY)
  target_include_directories(rasp_keys_report_test PRIVATE src tests ${PROJECT_SOURCE_DIR}/core/src)
  target_link_libraries(rasp_keys_report_test PRIVATE rasp_scoped_keys rasp_core rasp_tfpsacrypto GTest::gtest_main
    OpenSSL::Crypto rasp_warnings rasp_language)
  gtest_discover_tests(rasp_keys_report_test TEST_PREFIX "ScopedAdvisory."
    TEST_FILTER "AdapterSeams.r2_whenQueuedMainStartStillValid_signsOnce")
  add_executable(rasp_keys_c_consumer tests/unavailable.c ${PROJECT_SOURCE_DIR}/core/src/local_policy_host.cpp)
  target_link_libraries(rasp_keys_c_consumer PRIVATE rasp_scoped_keys rasp_core rasp_language)
  target_compile_options(rasp_keys_c_consumer PRIVATE -Wall -Wextra -Werror)
  add_test(NAME ScopedKeys.unavailableCConsumer COMMAND rasp_keys_c_consumer)
  if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_executable(rasp_keys_hash_allocation_probe tests/hash_allocation_probe.cpp)
    target_include_directories(rasp_keys_hash_allocation_probe PRIVATE src)
    target_link_libraries(rasp_keys_hash_allocation_probe PRIVATE rasp_scoped_keys rasp_warnings rasp_language)
    target_link_options(rasp_keys_hash_allocation_probe PRIVATE
      "LINKER:--wrap=calloc,--wrap=malloc,--wrap=realloc")
    add_test(NAME ScopedKeys.zeroDigestHeapCopies COMMAND rasp_keys_hash_allocation_probe)
  endif()
endif()
