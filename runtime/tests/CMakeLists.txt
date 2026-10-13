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

foreach(test observation reporting/reporter reporting/submit_observations util/http util/json util/uuid)
  cmake_path(GET test FILENAME name)
  add_executable(rasp_core_${name}_test core/${test}_test.cpp)
  target_link_libraries(rasp_core_${name}_test PRIVATE rasp_core rasp_warnings rasp_language GTest::gtest_main)
  gtest_discover_tests(rasp_core_${name}_test)
endforeach()

add_executable(rasp_ios_jailbreak_test ios/checks/jailbreak_test.cpp ${PROJECT_SOURCE_DIR}/ios/src/checks/jailbreak.cpp)
target_include_directories(rasp_ios_jailbreak_test PRIVATE ${PROJECT_SOURCE_DIR}/ios/src)
target_link_libraries(rasp_ios_jailbreak_test PRIVATE rasp_core rasp_warnings rasp_language GTest::gtest_main)
gtest_discover_tests(rasp_ios_jailbreak_test)

add_executable(rasp_ios_install_id_test ios/reporting/install_id_test.cpp ${PROJECT_SOURCE_DIR}/ios/src/reporting/install_id.cpp)
target_include_directories(rasp_ios_install_id_test PRIVATE ${PROJECT_SOURCE_DIR}/ios/src)
target_link_libraries(rasp_ios_install_id_test PRIVATE rasp_core rasp_warnings rasp_language GTest::gtest_main)
gtest_discover_tests(rasp_ios_install_id_test)

add_executable(rasp_android_example_test android/checks/example_test.cpp ${PROJECT_SOURCE_DIR}/android/src/checks/example.cpp)
target_include_directories(rasp_android_example_test PRIVATE ${PROJECT_SOURCE_DIR}/android/src)
target_link_libraries(rasp_android_example_test PRIVATE rasp_core rasp_warnings rasp_language GTest::gtest_main)
gtest_discover_tests(rasp_android_example_test)
