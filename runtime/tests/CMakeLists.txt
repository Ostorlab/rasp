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

foreach(test config context cycle decision embedded_config install_id observation parse_config local_policy plugins/init_plugins plugins/plugin plugins/registry plugins/run_plugins)
  cmake_path(GET test FILENAME name)
  add_executable(rasp_core_${name}_test core/${test}_test.cpp)
  target_link_libraries(rasp_core_${name}_test PRIVATE rasp_core rasp_warnings rasp_language GTest::gtest_main)
  gtest_discover_tests(rasp_core_${name}_test)
endforeach()
target_include_directories(rasp_core_install_id_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_include_directories(rasp_core_local_policy_test PRIVATE ${PROJECT_SOURCE_DIR}/core/src)
# Startup assertions and the process-lifetime installed owner require separate executables.
foreach(test local_policy_host local_policy_host_uninitialized)
  add_executable(rasp_${test}_test core/${test}_test.cpp ${PROJECT_SOURCE_DIR}/core/src/local_policy_host.cpp)
  target_include_directories(rasp_${test}_test PRIVATE ${PROJECT_SOURCE_DIR}/core/src)
  target_link_libraries(rasp_${test}_test PRIVATE rasp_core rasp_warnings rasp_language GTest::gtest_main)
  gtest_discover_tests(rasp_${test}_test)
endforeach()
add_executable(rasp_local_policy_c_host host/local_policy_host.c ${PROJECT_SOURCE_DIR}/core/src/local_policy_host.cpp)
set_property(TARGET rasp_local_policy_c_host PROPERTY C_STANDARD 17)
target_include_directories(rasp_local_policy_c_host PRIVATE ${PROJECT_SOURCE_DIR}/core/src)
target_link_libraries(rasp_local_policy_c_host PRIVATE rasp_core rasp_language)
target_compile_options(rasp_local_policy_c_host PRIVATE -Wall -Wextra -Werror)
add_test(NAME LocalPolicyHost.actualCConsumer COMMAND rasp_local_policy_c_host)
add_executable(rasp_local_policy_probe core/local_policy_probe.cpp)
target_include_directories(rasp_local_policy_probe PRIVATE ${PROJECT_SOURCE_DIR}/core/src)
target_link_libraries(rasp_local_policy_probe PRIVATE rasp_core rasp_warnings rasp_language)
target_link_libraries(rasp_core_decision_test PRIVATE rasp_yyjson)
target_compile_definitions(rasp_core_decision_test PRIVATE
  RASP_ASSESSMENT_VECTORS="${CMAKE_CURRENT_SOURCE_DIR}/core/assessment_vectors.json")
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

foreach(check debugger emulator hooks identity integrity jailbreak mitm virtualizer)
  add_executable(rasp_ios_${check}_test ios/checks/${check}_test.cpp
    ${PROJECT_SOURCE_DIR}/ios/src/checks/${check}.cpp)
  target_include_directories(rasp_ios_${check}_test PRIVATE ${PROJECT_SOURCE_DIR}/ios/src
    ${CMAKE_CURRENT_SOURCE_DIR})
  target_link_libraries(rasp_ios_${check}_test PRIVATE rasp_core rasp_warnings rasp_language GTest::gtest_main)
  gtest_discover_tests(rasp_ios_${check}_test)
endforeach()

foreach(check identity integrity)
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

# The hooks check reads system library files through the shared ELF reader, and its tests read the ELF fixtures.
target_sources(rasp_android_hooks_test PRIVATE ${PROJECT_SOURCE_DIR}/android/src/util/apk_file.cpp
  ${PROJECT_SOURCE_DIR}/android/src/util/elf.cpp)
target_compile_definitions(rasp_android_hooks_test PRIVATE
  RASP_TEST_ELF_DATA="${CMAKE_CURRENT_SOURCE_DIR}/android/util/data")

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

# The debugger, hooks and root checks read a second source through the shared util/direct_syscall helper, so their
# tests link it too.
foreach(check debugger hooks root)
  target_sources(rasp_android_${check}_test PRIVATE ${PROJECT_SOURCE_DIR}/android/src/util/direct_syscall.cpp)
endforeach()

add_executable(rasp_android_integrity_test android/checks/integrity_test.cpp
  ${PROJECT_SOURCE_DIR}/android/src/checks/integrity.cpp
  ${PROJECT_SOURCE_DIR}/android/src/util/apk_file.cpp
  ${PROJECT_SOURCE_DIR}/android/src/util/elf.cpp)
target_include_directories(rasp_android_integrity_test PRIVATE ${PROJECT_SOURCE_DIR}/android/src
  ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(rasp_android_integrity_test PRIVATE rasp_core rasp_tfpsacrypto rasp_warnings rasp_language
  GTest::gtest_main)
gtest_discover_tests(rasp_android_integrity_test)

# The identity check hashes the signer's certificate with the integrity check's sha256_hex, so its test links it too.
add_executable(rasp_android_identity_test android/checks/identity_test.cpp
  ${PROJECT_SOURCE_DIR}/android/src/checks/identity.cpp ${PROJECT_SOURCE_DIR}/android/src/util/signing_certificates.cpp
  ${PROJECT_SOURCE_DIR}/android/src/util/app_storage.cpp
  ${PROJECT_SOURCE_DIR}/android/src/util/elf.cpp
  ${PROJECT_SOURCE_DIR}/android/src/checks/integrity.cpp ${PROJECT_SOURCE_DIR}/android/src/util/apk_file.cpp)
target_include_directories(rasp_android_identity_test PRIVATE ${PROJECT_SOURCE_DIR}/android/src
  ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(rasp_android_identity_test PRIVATE rasp_core rasp_yyjson rasp_tfpsacrypto rasp_warnings rasp_language
  GTest::gtest_main)
target_compile_definitions(rasp_android_identity_test PRIVATE
  RASP_TEST_CERTIFICATE_DIR="${CMAKE_CURRENT_SOURCE_DIR}/android/apk/data"
  RASP_TEST_IDENTITY_FIXTURE="${PROJECT_SOURCE_DIR}/../docs/fixtures/android-signer-observations-v1.json")
gtest_discover_tests(rasp_android_identity_test)

add_executable(rasp_android_app_storage_test android/util/app_storage_test.cpp
  ${PROJECT_SOURCE_DIR}/android/src/util/app_storage.cpp)
target_include_directories(rasp_android_app_storage_test PRIVATE ${PROJECT_SOURCE_DIR}/android/src)
target_link_libraries(rasp_android_app_storage_test PRIVATE rasp_core rasp_warnings rasp_language GTest::gtest_main)
gtest_discover_tests(rasp_android_app_storage_test)

add_executable(rasp_android_archive_test android/apk/archive_test.cpp ${PROJECT_SOURCE_DIR}/android/src/apk/archive.cpp
  ${PROJECT_SOURCE_DIR}/android/src/util/elf.cpp
  ${PROJECT_SOURCE_DIR}/android/src/util/signing_certificates.cpp
  ${PROJECT_SOURCE_DIR}/android/src/checks/integrity.cpp ${PROJECT_SOURCE_DIR}/android/src/util/apk_file.cpp)
target_include_directories(rasp_android_archive_test PRIVATE ${PROJECT_SOURCE_DIR}/android/src
  ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(rasp_android_archive_test PRIVATE rasp_core rasp_tfpsacrypto rasp_warnings rasp_language GTest::gtest_main)
target_compile_definitions(rasp_android_archive_test PRIVATE
  RASP_TEST_CERTIFICATE_DIR="${CMAKE_CURRENT_SOURCE_DIR}/android/apk/data")
gtest_discover_tests(rasp_android_archive_test)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  add_executable(rasp_android_archive_fault_test android/apk/archive_fault_test.cpp
    ${PROJECT_SOURCE_DIR}/android/src/apk/archive.cpp
    ${PROJECT_SOURCE_DIR}/android/src/util/signing_certificates.cpp
    ${PROJECT_SOURCE_DIR}/android/src/util/elf.cpp
    ${PROJECT_SOURCE_DIR}/android/src/checks/integrity.cpp
    ${PROJECT_SOURCE_DIR}/android/src/util/apk_file.cpp)
  target_include_directories(rasp_android_archive_fault_test PRIVATE ${PROJECT_SOURCE_DIR}/android/src
    ${CMAKE_CURRENT_SOURCE_DIR})
  target_link_libraries(rasp_android_archive_fault_test PRIVATE rasp_core rasp_tfpsacrypto rasp_warnings rasp_language
    GTest::gtest_main)
  target_compile_definitions(rasp_android_archive_fault_test PRIVATE
    RASP_TEST_CERTIFICATE_DIR="${CMAKE_CURRENT_SOURCE_DIR}/android/apk/data")
  target_link_options(rasp_android_archive_fault_test PRIVATE
    -Wl,--wrap=pread -Wl,--wrap=fstat -Wl,--wrap=stat -Wl,--wrap=close)
  gtest_discover_tests(rasp_android_archive_fault_test)
endif()

add_executable(rasp_android_apk_file_test android/util/apk_file_test.cpp
  ${PROJECT_SOURCE_DIR}/android/src/util/apk_file.cpp)
target_include_directories(rasp_android_apk_file_test PRIVATE ${PROJECT_SOURCE_DIR}/android/src
  ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(rasp_android_apk_file_test PRIVATE rasp_core rasp_warnings rasp_language GTest::gtest_main)
gtest_discover_tests(rasp_android_apk_file_test)

add_executable(rasp_android_elf_test android/util/elf_test.cpp ${PROJECT_SOURCE_DIR}/android/src/util/elf.cpp)
target_include_directories(rasp_android_elf_test PRIVATE ${PROJECT_SOURCE_DIR}/android/src
  ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(rasp_android_elf_test PRIVATE rasp_core rasp_warnings rasp_language GTest::gtest_main)
target_compile_definitions(rasp_android_elf_test PRIVATE
  RASP_TEST_ELF_DATA="${CMAKE_CURRENT_SOURCE_DIR}/android/util/data")
gtest_discover_tests(rasp_android_elf_test)

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
  ${PROJECT_SOURCE_DIR}/android/src/util/elf.cpp
  ${PROJECT_SOURCE_DIR}/android/src/util/signing_certificates.cpp
  ${PROJECT_SOURCE_DIR}/android/src/checks/integrity.cpp ${PROJECT_SOURCE_DIR}/android/src/util/apk_file.cpp
  ${PROJECT_SOURCE_DIR}/android/src/apk/archive.cpp
  ${PROJECT_SOURCE_DIR}/android/src/payload/cipher.cpp)
target_include_directories(rasp_android_dex_store_test PRIVATE ${PROJECT_SOURCE_DIR}/android/src
  ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(rasp_android_dex_store_test PRIVATE rasp_core rasp_tfpsacrypto rasp_warnings rasp_language
  GTest::gtest_main)
gtest_discover_tests(rasp_android_dex_store_test)

add_executable(rasp_android_archive_probe android/apk/archive_probe.cpp
  ${PROJECT_SOURCE_DIR}/android/src/payload/dex_store.cpp
  ${PROJECT_SOURCE_DIR}/android/src/payload/cipher.cpp
  ${PROJECT_SOURCE_DIR}/android/src/apk/archive.cpp
  ${PROJECT_SOURCE_DIR}/android/src/util/signing_certificates.cpp
  ${PROJECT_SOURCE_DIR}/android/src/util/elf.cpp
  ${PROJECT_SOURCE_DIR}/android/src/checks/integrity.cpp
  ${PROJECT_SOURCE_DIR}/android/src/util/apk_file.cpp)
target_include_directories(rasp_android_archive_probe PRIVATE ${PROJECT_SOURCE_DIR}/android/src
  ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(rasp_android_archive_probe PRIVATE rasp_core rasp_tfpsacrypto rasp_warnings rasp_language)

add_executable(rasp_android_cipher_test android/payload/cipher_test.cpp ${PROJECT_SOURCE_DIR}/android/src/payload/cipher.cpp)
target_include_directories(rasp_android_cipher_test PRIVATE ${PROJECT_SOURCE_DIR}/android/src)
target_link_libraries(rasp_android_cipher_test PRIVATE rasp_core rasp_tfpsacrypto rasp_warnings rasp_language
  GTest::gtest_main)
gtest_discover_tests(rasp_android_cipher_test)

target_compile_definitions(rasp_ios_integrity_test PRIVATE
  RASP_TEST_EXECUTABLE_PATH="${PROJECT_SOURCE_DIR}/../packer/tests/rasp_packer/ios/data/arm64_app"
  RASP_TEST_SIGNED_EXECUTABLE_PATH="${PROJECT_SOURCE_DIR}/../packer/tests/rasp_packer/ios/data/arm64_app_signed")

add_executable(rasp_ios_builtin_test ios/builtin_test.cpp ${PROJECT_SOURCE_DIR}/ios/src/builtin.cpp
  ${PROJECT_SOURCE_DIR}/ios/src/checks/debugger.cpp ${PROJECT_SOURCE_DIR}/ios/src/checks/emulator.cpp
  ${PROJECT_SOURCE_DIR}/ios/src/checks/hooks.cpp ${PROJECT_SOURCE_DIR}/ios/src/checks/identity.cpp
  ${PROJECT_SOURCE_DIR}/ios/src/checks/integrity.cpp ${PROJECT_SOURCE_DIR}/ios/src/checks/jailbreak.cpp
  ${PROJECT_SOURCE_DIR}/ios/src/checks/mitm.cpp ${PROJECT_SOURCE_DIR}/ios/src/checks/virtualizer.cpp
  ${PROJECT_SOURCE_DIR}/ios/src/util/macho.cpp ${PROJECT_SOURCE_DIR}/ios/src/util/sha256.cpp)
target_include_directories(rasp_ios_builtin_test PRIVATE ${PROJECT_SOURCE_DIR}/ios/src)
target_link_libraries(rasp_ios_builtin_test PRIVATE rasp_core rasp_tfpsacrypto rasp_warnings rasp_language
  GTest::gtest_main)
if(APPLE)
  target_link_libraries(rasp_ios_builtin_test PRIVATE
    "$<LINK_LIBRARY:FRAMEWORK,CFNetwork>" "$<LINK_LIBRARY:FRAMEWORK,CoreFoundation>")
endif()
gtest_discover_tests(rasp_ios_builtin_test)

find_package(Python3 REQUIRED COMPONENTS Interpreter)
# Tidy consumes the compilation database after configure, without building any targets.
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
  ${PROJECT_SOURCE_DIR}/tools/capability_header.py
  ${PROJECT_SOURCE_DIR}/../packer/src/rasp_packer/capabilities.py
  ${PROJECT_SOURCE_DIR}/../packer/src/rasp_packer/checks_manifest.json)
foreach(platform android ios)
  set(expectations_dir ${CMAKE_CURRENT_BINARY_DIR}/capabilities/${platform})
  file(MAKE_DIRECTORY ${expectations_dir})
  execute_process(
    COMMAND ${Python3_EXECUTABLE} ${PROJECT_SOURCE_DIR}/tools/capability_header.py
      ${expectations_dir}/capability_expectations.h ${platform}
    COMMAND_ERROR_IS_FATAL ANY)
  if(platform STREQUAL "android")
    set(capability_checks debugger emulator hooks identity integrity mitm root service_exposure overlay context_exposure root_namespace capture)
    set(capability_util events/window_events.cpp util/signing_certificates.cpp util/system_property.cpp util/app_storage.cpp util/apk_file.cpp util/direct_syscall.cpp
      util/elf.cpp util/service_components.cpp)
  else()
    set(capability_checks debugger emulator hooks identity integrity jailbreak mitm virtualizer capture)
    set(capability_util util/macho.cpp util/sha256.cpp util/process_query.cpp capture/capture_events.cpp)
  endif()
  set(capability_sources ${PROJECT_SOURCE_DIR}/${platform}/src/builtin.cpp)
  foreach(check IN LISTS capability_checks)
    list(APPEND capability_sources ${PROJECT_SOURCE_DIR}/${platform}/src/checks/${check}.cpp)
  endforeach()
  foreach(source IN LISTS capability_util)
    list(APPEND capability_sources ${PROJECT_SOURCE_DIR}/${platform}/src/${source})
  endforeach()
  add_executable(rasp_${platform}_capabilities_test capabilities_test.cpp ${capability_sources}
    ${expectations_dir}/capability_expectations.h)
  target_include_directories(rasp_${platform}_capabilities_test PRIVATE ${PROJECT_SOURCE_DIR}/${platform}/src
    ${expectations_dir})
  target_link_libraries(rasp_${platform}_capabilities_test PRIVATE rasp_core rasp_tfpsacrypto
    rasp_warnings rasp_language GTest::gtest_main)
  if(platform STREQUAL "android")
    target_compile_definitions(rasp_${platform}_capabilities_test PRIVATE RASP_CAPABILITY_ANDROID)
  elseif(APPLE)
    target_link_libraries(rasp_ios_capabilities_test PRIVATE
      "$<LINK_LIBRARY:FRAMEWORK,CFNetwork>" "$<LINK_LIBRARY:FRAMEWORK,CoreFoundation>")
  endif()
  gtest_discover_tests(rasp_${platform}_capabilities_test TEST_PREFIX "${platform}.")
endforeach()

# Run the shipped Java bridge and JNI consumer on a real JVM, with Android services replaced at the Java boundary.
find_package(Java QUIET COMPONENTS Runtime Development)
find_package(JNI QUIET COMPONENTS JVM)
if(Java_FOUND AND JNI_FOUND)
  find_package(Threads REQUIRED)
  add_executable(rasp_android_application_context_test android/util/application_context_test.cpp
    ${PROJECT_SOURCE_DIR}/android/src/util/application_context.cpp
    ${PROJECT_SOURCE_DIR}/android/src/util/jni.cpp)
  target_include_directories(rasp_android_application_context_test PRIVATE ${JNI_INCLUDE_DIRS}
    ${PROJECT_SOURCE_DIR}/android/src)
  target_link_libraries(rasp_android_application_context_test PRIVATE rasp_warnings rasp_language
    JNI::JVM Threads::Threads GTest::gtest_main)
  gtest_discover_tests(rasp_android_application_context_test)
  add_executable(rasp_android_private_storage_test android/util/private_storage_test.cpp
    ${PROJECT_SOURCE_DIR}/android/src/util/private_storage.cpp
    ${PROJECT_SOURCE_DIR}/android/src/util/application_context.cpp
    ${PROJECT_SOURCE_DIR}/android/src/util/jni.cpp)
  target_include_directories(rasp_android_private_storage_test PRIVATE ${JNI_INCLUDE_DIRS}
    ${PROJECT_SOURCE_DIR}/android/src ${PROJECT_SOURCE_DIR}/posix/include)
  target_link_libraries(rasp_android_private_storage_test PRIVATE rasp_core rasp_warnings rasp_language GTest::gtest_main)
  gtest_discover_tests(rasp_android_private_storage_test PROPERTIES TIMEOUT 30)
  if(CMAKE_CXX_FLAGS MATCHES "fsanitize=")
    message(STATUS "Real-JVM integration runs in the host preset; native Application Context tests run with sanitizers")
  else()
    add_library(rasp_android_identity_dispatch OBJECT ${PROJECT_SOURCE_DIR}/android/src/checks/identity.cpp)
    target_compile_definitions(rasp_android_identity_dispatch PRIVATE __ANDROID__)
    target_include_directories(rasp_android_identity_dispatch PRIVATE ${JNI_INCLUDE_DIRS}
      ${CMAKE_CURRENT_SOURCE_DIR}/android/context_bridge/include ${PROJECT_SOURCE_DIR}/android/src)
    target_link_libraries(rasp_android_identity_dispatch PRIVATE rasp_core rasp_warnings rasp_language)
    add_library(rasp_android_context_bridge_jni SHARED android/context_bridge/driver.cpp android/events/driver.cpp
      android/context_bridge/policy_driver.cpp
      ${PROJECT_SOURCE_DIR}/core/src/local_policy_host.cpp
      ${PROJECT_SOURCE_DIR}/android/src/local_policy_bridge.cpp
      android/events/capture_driver.cpp
      ${PROJECT_SOURCE_DIR}/android/src/events/capture_bridge.cpp
      ${PROJECT_SOURCE_DIR}/android/src/events/capture_events.cpp
      ${PROJECT_SOURCE_DIR}/android/src/events/window_bridge.cpp
      ${PROJECT_SOURCE_DIR}/android/src/events/window_events.cpp
      ${PROJECT_SOURCE_DIR}/android/src/util/application_context.cpp
      ${PROJECT_SOURCE_DIR}/android/src/util/package_manager.cpp
      ${PROJECT_SOURCE_DIR}/android/src/util/package_identity.cpp
      ${PROJECT_SOURCE_DIR}/android/src/util/signing_certificates.cpp
      ${PROJECT_SOURCE_DIR}/android/src/apk/archive.cpp ${PROJECT_SOURCE_DIR}/android/src/apk/location.cpp
      ${PROJECT_SOURCE_DIR}/android/src/util/elf.cpp
      ${PROJECT_SOURCE_DIR}/android/src/checks/service_exposure.cpp
      ${PROJECT_SOURCE_DIR}/android/src/checks/context_exposure.cpp
      ${PROJECT_SOURCE_DIR}/android/src/checks/root_namespace.cpp
      ${PROJECT_SOURCE_DIR}/android/src/util/service_components.cpp
      ${PROJECT_SOURCE_DIR}/android/src/builtin.cpp
      ${PROJECT_SOURCE_DIR}/android/src/checks/debugger.cpp ${PROJECT_SOURCE_DIR}/android/src/checks/emulator.cpp
      ${PROJECT_SOURCE_DIR}/android/src/checks/hooks.cpp ${PROJECT_SOURCE_DIR}/android/src/checks/integrity.cpp
      ${PROJECT_SOURCE_DIR}/android/src/checks/mitm.cpp ${PROJECT_SOURCE_DIR}/android/src/checks/root.cpp
      ${PROJECT_SOURCE_DIR}/android/src/util/system_property.cpp ${PROJECT_SOURCE_DIR}/android/src/util/direct_syscall.cpp
      ${PROJECT_SOURCE_DIR}/android/src/util/app_storage.cpp ${PROJECT_SOURCE_DIR}/android/src/util/apk_file.cpp
      $<TARGET_OBJECTS:rasp_android_identity_dispatch>
      ${PROJECT_SOURCE_DIR}/android/src/util/jni.cpp)
    target_include_directories(rasp_android_context_bridge_jni PRIVATE ${JNI_INCLUDE_DIRS}
      ${PROJECT_SOURCE_DIR}/android/src ${CMAKE_CURRENT_SOURCE_DIR} ${PROJECT_SOURCE_DIR}/core/src)
    add_library(rasp_android_overlay_dispatch OBJECT ${PROJECT_SOURCE_DIR}/android/src/checks/overlay.cpp)
    target_compile_definitions(rasp_android_overlay_dispatch PRIVATE __ANDROID__)
    target_include_directories(rasp_android_overlay_dispatch PRIVATE ${PROJECT_SOURCE_DIR}/android/src)
    target_link_libraries(rasp_android_overlay_dispatch PRIVATE rasp_core rasp_warnings rasp_language)
    target_sources(rasp_android_context_bridge_jni PRIVATE $<TARGET_OBJECTS:rasp_android_overlay_dispatch>)
    add_library(rasp_android_capture_dispatch OBJECT ${PROJECT_SOURCE_DIR}/android/src/checks/capture.cpp)
    target_compile_definitions(rasp_android_capture_dispatch PRIVATE __ANDROID__)
    target_include_directories(rasp_android_capture_dispatch PRIVATE ${PROJECT_SOURCE_DIR}/android/src
      ${CMAKE_CURRENT_SOURCE_DIR}/android/context_bridge/include)
    target_link_libraries(rasp_android_capture_dispatch PRIVATE rasp_core rasp_warnings rasp_language)
    target_sources(rasp_android_context_bridge_jni PRIVATE $<TARGET_OBJECTS:rasp_android_capture_dispatch>)
    target_link_libraries(rasp_android_context_bridge_jni PRIVATE rasp_core rasp_tfpsacrypto rasp_warnings rasp_language JNI::JVM Threads::Threads ${CMAKE_DL_LIBS})
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
      target_link_options(rasp_android_context_bridge_jni PRIVATE -Wl,--no-undefined)
    endif()
    file(GLOB_RECURSE bridge_test_java CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/android/context_bridge/java/*.java)
    set(bridge_java ${PROJECT_SOURCE_DIR}/android/stub/co/ostorlab/rasp/RuntimeBridge.java)
    list(APPEND bridge_java ${PROJECT_SOURCE_DIR}/host_context/android/co/ostorlab/rasp/host/HostOperationContext.java)
    list(APPEND bridge_java ${CMAKE_CURRENT_SOURCE_DIR}/host_context/android/device/src/fixture/hostcontext/MainActivity.java)
    list(APPEND bridge_java ${PROJECT_SOURCE_DIR}/entrypoint_validation/android/co/ostorlab/rasp/entry/EntryPointValidation.java)
    file(GLOB entry_host_java CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/entrypoint_validation/android/device/src/fixture/entrypoints/*.java)
    list(APPEND bridge_java ${entry_host_java} ${CMAKE_CURRENT_SOURCE_DIR}/entrypoint_validation/android/java/EntryParserTest.java)
    set(bridge_test_classes ${CMAKE_CURRENT_BINARY_DIR}/context-bridge-classes)
    add_custom_command(OUTPUT ${bridge_test_classes}/co/ostorlab/rasp/BridgeTest.class
      COMMAND ${Java_JAVAC_EXECUTABLE} -d ${bridge_test_classes} ${bridge_java} ${bridge_test_java}
      DEPENDS ${bridge_java} ${bridge_test_java} VERBATIM)
    add_custom_target(rasp_android_context_bridge_java ALL
      DEPENDS ${bridge_test_classes}/co/ostorlab/rasp/BridgeTest.class)
    add_test(NAME AndroidLocalPolicy.operationGate
      COMMAND ${Java_JAVA_EXECUTABLE} -Xcheck:jni -cp ${bridge_test_classes} co.ostorlab.rasp.PolicyTest
        $<TARGET_FILE:rasp_android_context_bridge_jni> 5685df69e0340b2a8472c2929cd9be01db0444191abb8c5fdf366a51b0262c81)
    set_tests_properties(AndroidLocalPolicy.operationGate PROPERTIES TIMEOUT 30)
    add_test(NAME AndroidLocalPolicy.uint32MaxVersion
      COMMAND ${Java_JAVA_EXECUTABLE} -Xcheck:jni -cp ${bridge_test_classes} co.ostorlab.rasp.PolicyTest
        $<TARGET_FILE:rasp_android_context_bridge_jni> 2a7a8bb45ec84bf9d23a6998b2f631505fa32a192fa771aae676df626a004ce4 4294967295)
    set_tests_properties(AndroidLocalPolicy.uint32MaxVersion PROPERTIES TIMEOUT 30)
    add_test(NAME AndroidLocalPolicy.reportOnlyAdmission
      COMMAND ${Java_JAVA_EXECUTABLE} -Xcheck:jni -cp ${bridge_test_classes} co.ostorlab.rasp.PolicyTest
        $<TARGET_FILE:rasp_android_context_bridge_jni> cd463047b2990133678d5afdd887eca134a46a1063c6d3c39b637472a4341fee 1 report_only)
    set_tests_properties(AndroidLocalPolicy.reportOnlyAdmission PROPERTIES TIMEOUT 30)
    add_test(NAME AndroidHostContext.sharedVectors
      COMMAND ${Java_JAVA_EXECUTABLE} -Xcheck:jni -cp ${bridge_test_classes} co.ostorlab.rasp.HostContextTest
        $<TARGET_FILE:rasp_android_context_bridge_jni> ${CMAKE_CURRENT_SOURCE_DIR}/host_context/vectors.tsv)
    set_tests_properties(AndroidHostContext.sharedVectors PROPERTIES TIMEOUT 30)
    add_test(NAME AndroidHostContext.reportOnlyAdmission
      COMMAND ${Java_JAVA_EXECUTABLE} -Xcheck:jni -cp ${bridge_test_classes} co.ostorlab.rasp.HostContextTest
        $<TARGET_FILE:rasp_android_context_bridge_jni> ${CMAKE_CURRENT_SOURCE_DIR}/host_context/vectors.tsv report_only)
    set_tests_properties(AndroidHostContext.reportOnlyAdmission PROPERTIES TIMEOUT 30)
    foreach(scenario start_clock begin_clock input_expiry input_clock retry_expiry retry_action_age
        retry_clock gate_clock end_clock cancel_expiry cancel_ok benign deny_retry deny_limit pause recovery)
      add_test(NAME AndroidHostContext.activity_${scenario}
        COMMAND ${Java_JAVA_EXECUTABLE} -Xcheck:jni -cp ${bridge_test_classes} co.ostorlab.rasp.HostActivityTest
          $<TARGET_FILE:rasp_android_context_bridge_jni> ${scenario})
      set_tests_properties(AndroidHostContext.activity_${scenario} PROPERTIES TIMEOUT 30)
    endforeach()
    add_test(NAME AndroidWindowBridge.lifecycle
      COMMAND ${Java_JAVA_EXECUTABLE} -Xcheck:jni -cp ${bridge_test_classes} co.ostorlab.rasp.WindowTest
        $<TARGET_FILE:rasp_android_context_bridge_jni>)
    set_tests_properties(AndroidWindowBridge.lifecycle PROPERTIES TIMEOUT 30)
    foreach(api 31 33 34 35)
      add_test(NAME AndroidCaptureBridge.api${api}
        COMMAND ${Java_JAVA_EXECUTABLE} -Xcheck:jni -cp ${bridge_test_classes} co.ostorlab.rasp.CaptureTest
          $<TARGET_FILE:rasp_android_context_bridge_jni> ${api})
      set_tests_properties(AndroidCaptureBridge.api${api} PROPERTIES TIMEOUT 30)
    endforeach()
    set(identity_java_command ${Java_JAVA_EXECUTABLE})
    set(identity_process_alias "")
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
      set(identity_java_command /bin/bash ${CMAKE_CURRENT_SOURCE_DIR}/android/context_bridge/identity_process.sh
        ${Java_JAVA_EXECUTABLE})
      set(identity_process_alias fixture.global.worker)
    endif()
    add_test(NAME AndroidIdentity.productionDispatch
      COMMAND ${identity_java_command} -Xcheck:jni -cp ${bridge_test_classes} co.ostorlab.rasp.IdentityTest
        $<TARGET_FILE:rasp_android_context_bridge_jni> ${CMAKE_CURRENT_SOURCE_DIR}/android/apk/data ${identity_process_alias})
    set_tests_properties(AndroidIdentity.productionDispatch PROPERTIES TIMEOUT 60)
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
      add_test(NAME AndroidIdentity.legacyArchiveFileTypes
        COMMAND ${Java_JAVA_EXECUTABLE} -Xcheck:jni -cp ${bridge_test_classes} co.ostorlab.rasp.LegacyArchiveTest
          $<TARGET_FILE:rasp_android_context_bridge_jni>)
      set_tests_properties(AndroidIdentity.legacyArchiveFileTypes PROPERTIES TIMEOUT 30)
    endif()
    add_library(rasp_android_service_collectors OBJECT ${PROJECT_SOURCE_DIR}/android/src/checks/service_exposure.cpp
      ${PROJECT_SOURCE_DIR}/android/src/checks/context_exposure.cpp
      ${PROJECT_SOURCE_DIR}/android/src/checks/root_namespace.cpp)
    target_compile_definitions(rasp_android_service_collectors PRIVATE __ANDROID__)
    target_include_directories(rasp_android_service_collectors PRIVATE ${JNI_INCLUDE_DIRS} ${PROJECT_SOURCE_DIR}/android/src)
    target_link_libraries(rasp_android_service_collectors PRIVATE rasp_core rasp_warnings rasp_language)
    add_library(rasp_android_service_jni SHARED android/context_bridge/service_driver.cpp
      $<TARGET_OBJECTS:rasp_android_service_collectors>
      ${PROJECT_SOURCE_DIR}/android/src/util/service_components.cpp
      ${PROJECT_SOURCE_DIR}/android/src/util/application_context.cpp
      ${PROJECT_SOURCE_DIR}/android/src/util/jni.cpp)
    target_include_directories(rasp_android_service_jni PRIVATE ${JNI_INCLUDE_DIRS}
      ${PROJECT_SOURCE_DIR}/android/src)
    target_link_libraries(rasp_android_service_jni PRIVATE rasp_core rasp_warnings rasp_language JNI::JVM Threads::Threads)
    add_test(NAME AndroidServiceExposure.publicMetadata
      COMMAND ${Java_JAVA_EXECUTABLE} -Xcheck:jni -cp ${bridge_test_classes} co.ostorlab.rasp.ServiceTest
        $<TARGET_FILE:rasp_android_service_jni>)
    set_tests_properties(AndroidServiceExposure.publicMetadata PROPERTIES TIMEOUT 60)
    add_library(rasp_android_storage_jni SHARED android/context_bridge/storage_driver.cpp
      ${PROJECT_SOURCE_DIR}/android/src/util/private_storage.cpp
      ${PROJECT_SOURCE_DIR}/android/src/util/application_context.cpp
      ${PROJECT_SOURCE_DIR}/android/src/util/jni.cpp)
    target_include_directories(rasp_android_storage_jni PRIVATE ${JNI_INCLUDE_DIRS}
      ${PROJECT_SOURCE_DIR}/android/src ${PROJECT_SOURCE_DIR}/posix/include)
    target_link_libraries(rasp_android_storage_jni PRIVATE rasp_core rasp_warnings rasp_language JNI::JVM Threads::Threads)
    add_test(NAME AndroidPrivateStorage.publicApplication
      COMMAND ${Java_JAVA_EXECUTABLE} -Xcheck:jni -cp ${bridge_test_classes} co.ostorlab.rasp.StorageTest
        $<TARGET_FILE:rasp_android_storage_jni>)
    set_tests_properties(AndroidPrivateStorage.publicApplication PROPERTIES TIMEOUT 60)
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
      add_test(NAME AndroidPrivateStorage.globalProcessAlias
        COMMAND bash -c "exec -a unrelated.global.process \"$@\"" storage-alias ${Java_JAVA_EXECUTABLE}
          -Xcheck:jni -cp ${bridge_test_classes} co.ostorlab.rasp.StorageTest $<TARGET_FILE:rasp_android_storage_jni> global-alias)
      set_tests_properties(AndroidPrivateStorage.globalProcessAlias PROPERTIES TIMEOUT 60)
    endif()
    foreach(mode late early concurrent lifetime unavailable)
      add_test(NAME AndroidContextBridge.${mode}
        COMMAND ${Java_JAVA_EXECUTABLE} -Xcheck:jni -cp ${bridge_test_classes} co.ostorlab.rasp.BridgeTest
          $<TARGET_FILE:rasp_android_context_bridge_jni> ${mode})
      set_tests_properties(AndroidContextBridge.${mode} PROPERTIES TIMEOUT 30)
    endforeach()
  endif()
else()
  message(STATUS "Android bridge JVM integration tests unavailable: install a JDK and set JAVA_HOME")
endif()

# Exercise hooks()' Android dispatch against Linux's real own-process procfs, without an Android device claim.
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  foreach(library libc libdl)
    add_library(rasp_watched_${library} SHARED support/watched_library.cpp)
    set_target_properties(rasp_watched_${library} PROPERTIES PREFIX "" OUTPUT_NAME ${library}
      LIBRARY_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/watched")
    target_link_options(rasp_watched_${library} PRIVATE -nostdlib)
    target_link_libraries(rasp_watched_${library} PRIVATE rasp_warnings rasp_language)
  endforeach()
  add_library(rasp_android_hooks_dispatch OBJECT ${PROJECT_SOURCE_DIR}/android/src/checks/hooks.cpp
    ${PROJECT_SOURCE_DIR}/android/src/util/direct_syscall.cpp
    ${PROJECT_SOURCE_DIR}/android/src/util/elf.cpp
    ${PROJECT_SOURCE_DIR}/android/src/util/apk_file.cpp)
  target_compile_definitions(rasp_android_hooks_dispatch PRIVATE __ANDROID__)
  target_include_directories(rasp_android_hooks_dispatch PRIVATE ${PROJECT_SOURCE_DIR}/android/src)
  target_link_libraries(rasp_android_hooks_dispatch PRIVATE rasp_core rasp_warnings rasp_language)
  add_executable(rasp_android_hooks_dispatch_test android/checks/hooks_test.cpp
    $<TARGET_OBJECTS:rasp_android_hooks_dispatch>)
  target_compile_definitions(rasp_android_hooks_dispatch_test PRIVATE RASP_TEST_ANDROID_HOOKS
    RASP_TEST_WATCHED_LIBC="$<TARGET_FILE:rasp_watched_libc>"
    RASP_TEST_WATCHED_LIBDL="$<TARGET_FILE:rasp_watched_libdl>"
    RASP_TEST_ELF_DATA="${CMAKE_CURRENT_SOURCE_DIR}/android/util/data")
  target_include_directories(rasp_android_hooks_dispatch_test PRIVATE ${PROJECT_SOURCE_DIR}/android/src
    ${CMAKE_CURRENT_SOURCE_DIR})
  target_link_libraries(rasp_android_hooks_dispatch_test PRIVATE rasp_core rasp_warnings rasp_language GTest::gtest_main)
  add_dependencies(rasp_android_hooks_dispatch_test rasp_watched_libc rasp_watched_libdl)
  gtest_discover_tests(rasp_android_hooks_dispatch_test TEST_PREFIX "AndroidDispatch.")
endif()

add_executable(rasp_android_direct_syscall_test android/util/direct_syscall_test.cpp
  ${PROJECT_SOURCE_DIR}/android/src/util/direct_syscall.cpp)
target_include_directories(rasp_android_direct_syscall_test PRIVATE ${PROJECT_SOURCE_DIR}/android/src
  ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(rasp_android_direct_syscall_test PRIVATE rasp_core rasp_warnings rasp_language GTest::gtest_main)
gtest_discover_tests(rasp_android_direct_syscall_test)

target_sources(rasp_ios_debugger_test PRIVATE ${PROJECT_SOURCE_DIR}/ios/src/util/process_query.cpp)
target_sources(rasp_ios_builtin_test PRIVATE ${PROJECT_SOURCE_DIR}/ios/src/util/process_query.cpp)
add_executable(rasp_ios_process_query_test ios/util/process_query_test.cpp
  ${PROJECT_SOURCE_DIR}/ios/src/util/process_query.cpp)
target_include_directories(rasp_ios_process_query_test PRIVATE ${PROJECT_SOURCE_DIR}/ios/src)
target_link_libraries(rasp_ios_process_query_test PRIVATE rasp_core rasp_warnings rasp_language GTest::gtest_main)
gtest_discover_tests(rasp_ios_process_query_test)

# Both platform adapters use this checked POSIX implementation, with failures injected at the syscall boundary.
add_executable(rasp_posix_cycle_clock_test posix/cycle_clock_test.cpp)
target_include_directories(rasp_posix_cycle_clock_test PRIVATE ${PROJECT_SOURCE_DIR}/posix/include)
target_link_libraries(rasp_posix_cycle_clock_test PRIVATE rasp_core rasp_warnings rasp_language GTest::gtest_main)
gtest_discover_tests(rasp_posix_cycle_clock_test)
add_executable(rasp_android_service_components_test android/util/service_components_test.cpp
  ${PROJECT_SOURCE_DIR}/android/src/util/service_components.cpp)
target_include_directories(rasp_android_service_components_test PRIVATE ${PROJECT_SOURCE_DIR}/android/src)
target_link_libraries(rasp_android_service_components_test PRIVATE rasp_core rasp_warnings rasp_language GTest::gtest_main)
gtest_discover_tests(rasp_android_service_components_test)

add_library(rasp_android_builtin_support OBJECT ${PROJECT_SOURCE_DIR}/android/src/builtin.cpp
  ${PROJECT_SOURCE_DIR}/android/src/checks/capture.cpp
  ${PROJECT_SOURCE_DIR}/android/src/checks/overlay.cpp
  ${PROJECT_SOURCE_DIR}/android/src/checks/debugger.cpp ${PROJECT_SOURCE_DIR}/android/src/checks/emulator.cpp
  ${PROJECT_SOURCE_DIR}/android/src/checks/hooks.cpp ${PROJECT_SOURCE_DIR}/android/src/checks/identity.cpp
  ${PROJECT_SOURCE_DIR}/android/src/checks/integrity.cpp ${PROJECT_SOURCE_DIR}/android/src/checks/mitm.cpp
  ${PROJECT_SOURCE_DIR}/android/src/checks/root.cpp ${PROJECT_SOURCE_DIR}/android/src/util/app_storage.cpp
  ${PROJECT_SOURCE_DIR}/android/src/util/apk_file.cpp ${PROJECT_SOURCE_DIR}/android/src/util/system_property.cpp
  ${PROJECT_SOURCE_DIR}/android/src/util/direct_syscall.cpp ${PROJECT_SOURCE_DIR}/android/src/util/elf.cpp
  ${PROJECT_SOURCE_DIR}/android/src/util/signing_certificates.cpp)
target_include_directories(rasp_android_builtin_support PRIVATE ${PROJECT_SOURCE_DIR}/android/src)
target_link_libraries(rasp_android_builtin_support PRIVATE rasp_core rasp_tfpsacrypto rasp_warnings rasp_language)
add_executable(rasp_android_builtin_test android/builtin_test.cpp
  ${PROJECT_SOURCE_DIR}/android/src/checks/service_exposure.cpp
  ${PROJECT_SOURCE_DIR}/android/src/checks/context_exposure.cpp
  ${PROJECT_SOURCE_DIR}/android/src/checks/root_namespace.cpp $<TARGET_OBJECTS:rasp_android_builtin_support>)
target_include_directories(rasp_android_builtin_test PRIVATE ${PROJECT_SOURCE_DIR}/android/src)
target_link_libraries(rasp_android_builtin_test PRIVATE rasp_core rasp_tfpsacrypto rasp_warnings rasp_language GTest::gtest_main)
gtest_discover_tests(rasp_android_builtin_test TEST_PREFIX "android.")
if(TARGET rasp_android_service_jni)
  target_sources(rasp_android_service_jni PRIVATE $<TARGET_OBJECTS:rasp_android_builtin_support>)
  target_link_libraries(rasp_android_service_jni PRIVATE rasp_tfpsacrypto)
endif()

add_executable(rasp_private_storage_probe core/private_storage_probe.cpp)
target_include_directories(rasp_private_storage_probe PRIVATE ${PROJECT_SOURCE_DIR}/posix/include)
target_link_libraries(rasp_private_storage_probe PRIVATE rasp_core rasp_warnings rasp_language)
add_executable(rasp_core_private_storage_test core/private_storage_test.cpp)
target_compile_definitions(rasp_core_private_storage_test PRIVATE RASP_STORAGE_PROBE="$<TARGET_FILE:rasp_private_storage_probe>")
add_dependencies(rasp_core_private_storage_test rasp_private_storage_probe)
add_dependencies(rasp_core_install_id_test rasp_private_storage_probe)
target_compile_definitions(rasp_core_install_id_test PRIVATE RASP_STORAGE_PROBE="$<TARGET_FILE:rasp_private_storage_probe>")
target_include_directories(rasp_core_private_storage_test PRIVATE ${PROJECT_SOURCE_DIR}/posix/include ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(rasp_core_private_storage_test PRIVATE rasp_core rasp_warnings rasp_language GTest::gtest_main)
gtest_discover_tests(rasp_core_private_storage_test PROPERTIES TIMEOUT 30)
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  add_executable(rasp_core_private_storage_fault_test core/private_storage_fault_test.cpp)
  target_include_directories(rasp_core_private_storage_fault_test PRIVATE ${PROJECT_SOURCE_DIR}/posix/include ${CMAKE_CURRENT_SOURCE_DIR})
  target_link_libraries(rasp_core_private_storage_fault_test PRIVATE rasp_core rasp_warnings rasp_language GTest::gtest_main)
  foreach(storage_call getentropy write read fsync linkat close fstat fstatat flock unlinkat)
    target_link_options(rasp_core_private_storage_fault_test PRIVATE "-Wl,--wrap=${storage_call}")
  endforeach()
  gtest_discover_tests(rasp_core_private_storage_fault_test PROPERTIES TIMEOUT 30)
endif()
if(APPLE)
  enable_language(OBJCXX)
  set(CMAKE_OBJCXX_STANDARD 23)
  set(CMAKE_OBJCXX_STANDARD_REQUIRED ON)
  set(CMAKE_OBJCXX_EXTENSIONS OFF)
  add_executable(rasp_ios_private_storage_test ios/util/private_storage_test.mm
    ${PROJECT_SOURCE_DIR}/ios/src/util/private_storage.mm)
  target_include_directories(rasp_ios_private_storage_test PRIVATE ${PROJECT_SOURCE_DIR}/posix/include ${CMAKE_CURRENT_SOURCE_DIR})
  target_compile_options(rasp_ios_private_storage_test PRIVATE -fobjc-arc -fno-objc-exceptions)
  target_link_libraries(rasp_ios_private_storage_test PRIVATE rasp_core rasp_warnings rasp_language
    GTest::gtest_main "$<LINK_LIBRARY:FRAMEWORK,Foundation>")
  gtest_discover_tests(rasp_ios_private_storage_test PROPERTIES TIMEOUT 30)
  add_executable(rasp_ios_private_entropy_test ios/util/private_entropy_test.cpp)
  target_include_directories(rasp_ios_private_entropy_test PRIVATE ${PROJECT_SOURCE_DIR}/posix/include
    ${CMAKE_CURRENT_SOURCE_DIR})
  target_link_libraries(rasp_ios_private_entropy_test PRIVATE rasp_core rasp_warnings rasp_language GTest::gtest_main)
  gtest_discover_tests(rasp_ios_private_entropy_test PROPERTIES TIMEOUT 30)
endif()

add_executable(rasp_android_window_events_test android/events/window_events_test.cpp
  ${PROJECT_SOURCE_DIR}/android/src/events/window_events.cpp)
target_include_directories(rasp_android_window_events_test PRIVATE ${PROJECT_SOURCE_DIR}/android/src)
target_link_libraries(rasp_android_window_events_test PRIVATE rasp_warnings rasp_language GTest::gtest_main)
gtest_discover_tests(rasp_android_window_events_test)

add_executable(rasp_android_capture_events_test android/events/capture_events_test.cpp
  ${PROJECT_SOURCE_DIR}/android/src/events/capture_events.cpp)
target_include_directories(rasp_android_capture_events_test PRIVATE ${PROJECT_SOURCE_DIR}/android/src)
target_link_libraries(rasp_android_capture_events_test PRIVATE rasp_core rasp_warnings rasp_language GTest::gtest_main)
gtest_discover_tests(rasp_android_capture_events_test)
add_executable(rasp_android_root_namespace_test android/checks/root_namespace_test.cpp
  ${PROJECT_SOURCE_DIR}/android/src/checks/root_namespace.cpp)
target_include_directories(rasp_android_root_namespace_test PRIVATE ${PROJECT_SOURCE_DIR}/android/src ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(rasp_android_root_namespace_test PRIVATE rasp_core rasp_warnings rasp_language GTest::gtest_main)
gtest_discover_tests(rasp_android_root_namespace_test)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  target_compile_definitions(rasp_android_root_namespace_test PRIVATE RASP_TEST_WRAP_FSTAT)
  target_link_options(rasp_android_root_namespace_test PRIVATE -Wl,--wrap=fstat)
endif()

add_executable(rasp_ios_capture_events_test ios/capture/capture_events_test.cpp
  ${PROJECT_SOURCE_DIR}/ios/src/capture/capture_events.cpp)
target_include_directories(rasp_ios_capture_events_test PRIVATE ${PROJECT_SOURCE_DIR}/ios/src)
target_link_libraries(rasp_ios_capture_events_test PRIVATE rasp_core rasp_warnings rasp_language GTest::gtest_main)
gtest_discover_tests(rasp_ios_capture_events_test)

target_sources(rasp_ios_builtin_test PRIVATE ${PROJECT_SOURCE_DIR}/ios/src/checks/capture.cpp
  ${PROJECT_SOURCE_DIR}/ios/src/capture/capture_events.cpp)

# Optional host source compiles only into consumers/tests, never the injected runtime.
add_subdirectory(${PROJECT_SOURCE_DIR}/host_context ${CMAKE_CURRENT_BINARY_DIR}/host-context)
add_executable(rasp_host_context_test host_context/host_context_test.cpp
  ${PROJECT_SOURCE_DIR}/core/src/local_policy_host.cpp)
target_include_directories(rasp_host_context_test PRIVATE ${PROJECT_SOURCE_DIR}/core/src ${PROJECT_SOURCE_DIR}/host_context/src)
target_compile_definitions(rasp_host_context_test PRIVATE RASP_HOST_VECTORS="${CMAKE_CURRENT_SOURCE_DIR}/host_context/vectors.tsv")
target_link_libraries(rasp_host_context_test PRIVATE rasp_host_context rasp_core rasp_warnings rasp_language GTest::gtest_main)
gtest_discover_tests(rasp_host_context_test)
add_executable(rasp_host_context_c_host host_context/c_host.c host_context/clock_fixture.c
  ${PROJECT_SOURCE_DIR}/core/src/local_policy_host.cpp)
target_link_libraries(rasp_host_context_c_host PRIVATE rasp_host_context rasp_core rasp_language)
target_compile_options(rasp_host_context_c_host PRIVATE -Wall -Wextra -Werror -Wpedantic -Wconversion)
add_test(NAME HostContextConsumer.actualC COMMAND rasp_host_context_c_host)

# The entry-point classifier is host source; no shipping runtime consumes this target.
add_subdirectory(${PROJECT_SOURCE_DIR}/entrypoint_validation ${CMAKE_CURRENT_BINARY_DIR}/entrypoint-validation)
add_executable(rasp_entrypoint_classify_test entrypoint_validation/classify_test.c)
target_link_libraries(rasp_entrypoint_classify_test PRIVATE rasp_entrypoint_validation rasp_language)
add_test(NAME EntryPoint.classify COMMAND rasp_entrypoint_classify_test ${CMAKE_CURRENT_SOURCE_DIR}/entrypoint_validation/vectors.tsv)
if(TARGET rasp_android_context_bridge_java)
  add_test(NAME EntryPoint.missingBridge COMMAND ${Java_JAVA_EXECUTABLE} -cp ${bridge_test_classes}
    co.ostorlab.rasp.EntryMissingBridgeTest ${bridge_test_classes})
  set_tests_properties(EntryPoint.missingBridge PROPERTIES TIMEOUT 30)
  add_test(NAME EntryPoint.androidBoundaries COMMAND ${Java_JAVA_EXECUTABLE} -Xcheck:jni -cp ${bridge_test_classes}
    co.ostorlab.rasp.EntryBoundaryTest $<TARGET_FILE:rasp_android_context_bridge_jni>)
  set_tests_properties(EntryPoint.androidBoundaries PROPERTIES TIMEOUT 30)
  add_test(NAME EntryPoint.javaVectors COMMAND ${Java_JAVA_EXECUTABLE} -cp ${bridge_test_classes}
    EntryParserTest ${CMAKE_CURRENT_SOURCE_DIR}/entrypoint_validation/vectors.tsv)
  set_tests_properties(EntryPoint.javaVectors PROPERTIES TIMEOUT 30)
endif()
add_executable(rasp_entrypoint_gate_test entrypoint_validation/gate_test.cpp entrypoint_validation/c_host.c
  ${PROJECT_SOURCE_DIR}/core/src/local_policy_host.cpp)
target_include_directories(rasp_entrypoint_gate_test PRIVATE ${PROJECT_SOURCE_DIR}/core/src ${PROJECT_SOURCE_DIR}/core/include/rasp ${CMAKE_CURRENT_SOURCE_DIR}/entrypoint_validation)
target_link_libraries(rasp_entrypoint_gate_test PRIVATE rasp_entrypoint_validation rasp_core rasp_warnings rasp_language)
add_test(NAME EntryPoint.realCGate COMMAND rasp_entrypoint_gate_test)
add_test(NAME EntryPoint.realCReportOnly COMMAND rasp_entrypoint_gate_test report_only)
