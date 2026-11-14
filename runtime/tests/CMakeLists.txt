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

add_executable(rasp_core_test core/version_test.cpp)
target_link_libraries(rasp_core_test PRIVATE rasp_core rasp_warnings rasp_language GTest::gtest_main)
target_compile_definitions(rasp_core_test PRIVATE RASP_EXPECTED_VERSION="${PROJECT_VERSION}")
gtest_discover_tests(rasp_core_test)

foreach(test config context embedded_config heartbeat install_id observation panic parse_config plugins/init_plugins plugins/plugin plugins/registry
    plugins/run_plugins schedule)
  cmake_path(GET test FILENAME name)
  add_executable(rasp_core_${name}_test core/${test}_test.cpp)
  target_link_libraries(rasp_core_${name}_test PRIVATE rasp_core rasp_warnings rasp_language GTest::gtest_main)
  gtest_discover_tests(rasp_core_${name}_test)
endforeach()
# The development build of panic_on_detection logs instead of ending the process. This test compiles it as a
# development build does, with its own log function, so it doesn't link rasp_core, which is built without logs.
add_executable(rasp_core_panic_development_test core/panic_development_test.cpp
  ${PROJECT_SOURCE_DIR}/core/src/observation.cpp
  ${PROJECT_SOURCE_DIR}/core/src/panic.cpp)
target_include_directories(rasp_core_panic_development_test PRIVATE ${PROJECT_SOURCE_DIR}/core/include)
target_compile_definitions(rasp_core_panic_development_test PRIVATE RASP_LOGGING_ENABLED=true)
target_link_libraries(rasp_core_panic_development_test PRIVATE rasp_warnings rasp_language GTest::gtest_main)
gtest_discover_tests(rasp_core_panic_development_test)
target_include_directories(rasp_core_install_id_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
list(LENGTH rasp_compiled_plugins rasp_expected_plugin_count)
target_link_libraries(rasp_core_registry_test PRIVATE rasp_plugins)
target_compile_definitions(rasp_core_registry_test PRIVATE RASP_EXPECTED_PLUGIN_COUNT=${rasp_expected_plugin_count})

if(NOT TARGET rasp_plugin_example)
  add_subdirectory(${PROJECT_SOURCE_DIR}/plugins/example ${CMAKE_CURRENT_BINARY_DIR}/plugins/example)
endif()
rasp_plugin_registry(rasp_test_plugins example)
add_executable(rasp_plugins_example_test plugins/example_test.cpp)
target_link_libraries(rasp_plugins_example_test PRIVATE rasp_test_plugins rasp_core rasp_warnings rasp_language
  GTest::gtest_main)
gtest_discover_tests(rasp_plugins_example_test)

foreach(check codesign debugger emulator hooks identity jailbreak mitm virtualizer)
  add_executable(rasp_ios_${check}_test ios/checks/${check}_test.cpp
    ${PROJECT_SOURCE_DIR}/ios/src/checks/${check}.cpp)
  target_include_directories(rasp_ios_${check}_test PRIVATE ${PROJECT_SOURCE_DIR}/ios/src
    ${CMAKE_CURRENT_SOURCE_DIR})
  target_link_libraries(rasp_ios_${check}_test PRIVATE rasp_core rasp_warnings rasp_language GTest::gtest_main)
  gtest_discover_tests(rasp_ios_${check}_test)
endforeach()

foreach(check identity)
  target_sources(rasp_ios_${check}_test PRIVATE ${PROJECT_SOURCE_DIR}/ios/src/util/macho.cpp
    ${PROJECT_SOURCE_DIR}/ios/src/util/sha256.cpp)
  target_link_libraries(rasp_ios_${check}_test PRIVATE rasp_tfpsacrypto)
endforeach()
target_compile_definitions(rasp_ios_identity_test PRIVATE
  RASP_TEST_SIGNATURE_PATH="${CMAKE_CURRENT_SOURCE_DIR}/ios/checks/data/arm64_app_signed.superblob")

if(APPLE)
  target_link_libraries(rasp_ios_identity_test PRIVATE "$<LINK_LIBRARY:FRAMEWORK,CoreFoundation>")
  target_link_libraries(rasp_ios_virtualizer_test PRIVATE "$<LINK_LIBRARY:FRAMEWORK,CoreFoundation>")
  target_link_libraries(rasp_ios_mitm_test PRIVATE
    "$<LINK_LIBRARY:FRAMEWORK,CFNetwork>" "$<LINK_LIBRARY:FRAMEWORK,CoreFoundation>")
endif()

foreach(check debugger hooks mitm)
  add_executable(rasp_android_${check}_test android/checks/${check}_test.cpp
    ${PROJECT_SOURCE_DIR}/android/src/checks/${check}.cpp)
  target_include_directories(rasp_android_${check}_test PRIVATE ${PROJECT_SOURCE_DIR}/android/src
    ${CMAKE_CURRENT_SOURCE_DIR})
  target_link_libraries(rasp_android_${check}_test PRIVATE rasp_core rasp_warnings rasp_language GTest::gtest_main)
  gtest_discover_tests(rasp_android_${check}_test)
endforeach()

# The emulator and root checks read system properties through the shared util/system_property helper, so their tests
# link it too.
foreach(check emulator root)
  add_executable(rasp_android_${check}_test android/checks/${check}_test.cpp
    ${PROJECT_SOURCE_DIR}/android/src/checks/${check}.cpp
    ${PROJECT_SOURCE_DIR}/android/src/util/system_property.cpp)
  target_include_directories(rasp_android_${check}_test PRIVATE ${PROJECT_SOURCE_DIR}/android/src
    ${CMAKE_CURRENT_SOURCE_DIR})
  target_link_libraries(rasp_android_${check}_test PRIVATE rasp_core rasp_warnings rasp_language GTest::gtest_main)
  gtest_discover_tests(rasp_android_${check}_test)
endforeach()

add_executable(rasp_android_integrity_test android/checks/integrity_test.cpp
  ${PROJECT_SOURCE_DIR}/android/src/checks/integrity.cpp
  ${PROJECT_SOURCE_DIR}/android/src/util/apk_file.cpp)
target_include_directories(rasp_android_integrity_test PRIVATE ${PROJECT_SOURCE_DIR}/android/src
  ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(rasp_android_integrity_test PRIVATE rasp_core rasp_tfpsacrypto rasp_warnings rasp_language
  GTest::gtest_main)
gtest_discover_tests(rasp_android_integrity_test)

# The identity check hashes the signer's certificate with the integrity check's sha256_hex, so its test links it too.
add_executable(rasp_android_identity_test android/checks/identity_test.cpp
  ${PROJECT_SOURCE_DIR}/android/src/checks/identity.cpp ${PROJECT_SOURCE_DIR}/android/src/util/app_storage.cpp
  ${PROJECT_SOURCE_DIR}/android/src/checks/integrity.cpp ${PROJECT_SOURCE_DIR}/android/src/util/apk_file.cpp)
target_include_directories(rasp_android_identity_test PRIVATE ${PROJECT_SOURCE_DIR}/android/src
  ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(rasp_android_identity_test PRIVATE rasp_core rasp_tfpsacrypto rasp_warnings rasp_language
  GTest::gtest_main)
gtest_discover_tests(rasp_android_identity_test)

# end_process makes the Linux exit_group system call directly, so its test runs only on a Linux host.
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  add_executable(rasp_android_end_process_test android/panic/end_process_test.cpp
    ${PROJECT_SOURCE_DIR}/android/src/panic/end_process.cpp)
  target_include_directories(rasp_android_end_process_test PRIVATE ${PROJECT_SOURCE_DIR}/android/src)
  target_link_libraries(rasp_android_end_process_test PRIVATE rasp_warnings rasp_language GTest::gtest_main)
  gtest_discover_tests(rasp_android_end_process_test)
endif()

add_executable(rasp_android_app_storage_test android/util/app_storage_test.cpp
  ${PROJECT_SOURCE_DIR}/android/src/util/app_storage.cpp)
target_include_directories(rasp_android_app_storage_test PRIVATE ${PROJECT_SOURCE_DIR}/android/src)
target_link_libraries(rasp_android_app_storage_test PRIVATE rasp_core rasp_warnings rasp_language GTest::gtest_main)
gtest_discover_tests(rasp_android_app_storage_test)

add_executable(rasp_android_archive_test android/apk/archive_test.cpp ${PROJECT_SOURCE_DIR}/android/src/apk/archive.cpp
  ${PROJECT_SOURCE_DIR}/android/src/checks/integrity.cpp ${PROJECT_SOURCE_DIR}/android/src/apk/location.cpp
  ${PROJECT_SOURCE_DIR}/android/src/util/apk_file.cpp)
target_include_directories(rasp_android_archive_test PRIVATE ${PROJECT_SOURCE_DIR}/android/src
  ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(rasp_android_archive_test PRIVATE rasp_core rasp_tfpsacrypto rasp_warnings rasp_language GTest::gtest_main)
gtest_discover_tests(rasp_android_archive_test)

add_executable(rasp_android_apk_file_test android/util/apk_file_test.cpp
  ${PROJECT_SOURCE_DIR}/android/src/util/apk_file.cpp)
target_include_directories(rasp_android_apk_file_test PRIVATE ${PROJECT_SOURCE_DIR}/android/src
  ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(rasp_android_apk_file_test PRIVATE rasp_core rasp_warnings rasp_language GTest::gtest_main)
gtest_discover_tests(rasp_android_apk_file_test)

if(TARGET rasp_loader_dex)
  add_executable(rasp_android_loader_dex_test android/loader/loader_dex_test.cpp
    ${PROJECT_SOURCE_DIR}/android/src/loader/loader_dex.cpp)
  target_include_directories(rasp_android_loader_dex_test PRIVATE ${PROJECT_SOURCE_DIR}/android/src)
  target_link_libraries(rasp_android_loader_dex_test PRIVATE rasp_core rasp_loader_dex rasp_warnings rasp_language
    GTest::gtest_main)
  gtest_discover_tests(rasp_android_loader_dex_test)
endif()

add_executable(rasp_android_dex_store_test android/payload/dex_store_test.cpp
  ${PROJECT_SOURCE_DIR}/android/src/payload/dex_store.cpp
  ${PROJECT_SOURCE_DIR}/android/src/payload/key_schedule.cpp
  ${PROJECT_SOURCE_DIR}/android/src/payload/cipher.cpp
  ${PROJECT_SOURCE_DIR}/android/src/checks/debugger.cpp
  ${PROJECT_SOURCE_DIR}/android/src/checks/hooks.cpp
  ${PROJECT_SOURCE_DIR}/android/src/checks/integrity.cpp
  ${PROJECT_SOURCE_DIR}/android/src/util/apk_file.cpp
  ${PROJECT_SOURCE_DIR}/android/src/apk/archive.cpp
  ${PROJECT_SOURCE_DIR}/android/src/apk/location.cpp)
target_include_directories(rasp_android_dex_store_test PRIVATE ${PROJECT_SOURCE_DIR}/android/src
  ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(rasp_android_dex_store_test PRIVATE rasp_core rasp_tfpsacrypto rasp_warnings rasp_language
  GTest::gtest_main)
gtest_discover_tests(rasp_android_dex_store_test)

add_executable(rasp_android_cipher_test android/payload/cipher_test.cpp ${PROJECT_SOURCE_DIR}/android/src/payload/cipher.cpp)
target_include_directories(rasp_android_cipher_test PRIVATE ${PROJECT_SOURCE_DIR}/android/src)
target_link_libraries(rasp_android_cipher_test PRIVATE rasp_core rasp_tfpsacrypto rasp_warnings rasp_language
  GTest::gtest_main)
gtest_discover_tests(rasp_android_cipher_test)

# The key schedule's tests check the same fixed vectors as the packer's tests (key_schedule_test.py), and drive the
# recovery with a library and an APK the packer's tools made, so the ELF reader, the digests, the HKDF and the fold are
# exercised end to end without a device.
add_executable(rasp_android_key_schedule_test android/payload/key_schedule_test.cpp
  ${PROJECT_SOURCE_DIR}/android/src/payload/key_schedule.cpp
  ${PROJECT_SOURCE_DIR}/android/src/checks/hooks.cpp
  ${PROJECT_SOURCE_DIR}/android/src/payload/cipher.cpp
  ${PROJECT_SOURCE_DIR}/android/src/checks/debugger.cpp
  ${PROJECT_SOURCE_DIR}/android/src/checks/integrity.cpp
  ${PROJECT_SOURCE_DIR}/android/src/util/apk_file.cpp
  ${PROJECT_SOURCE_DIR}/android/src/apk/archive.cpp
  ${PROJECT_SOURCE_DIR}/android/src/apk/location.cpp)
target_include_directories(rasp_android_key_schedule_test PRIVATE ${PROJECT_SOURCE_DIR}/android/src
  ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(rasp_android_key_schedule_test PRIVATE rasp_core rasp_tfpsacrypto rasp_warnings rasp_language
  GTest::gtest_main)
gtest_discover_tests(rasp_android_key_schedule_test)

