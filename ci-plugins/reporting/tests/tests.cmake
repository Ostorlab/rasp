# The reporting plugin's tests, which run on a development machine. The plugin's CMakeLists.txt includes this file at
# the end of the build's top directory, once the build has fetched GoogleTest and enabled the tests.

include(GoogleTest)

foreach(test http json mailbox sender)
  add_executable(rasp_reporting_${test}_test ${CMAKE_CURRENT_LIST_DIR}/${test}_test.cpp)
  target_include_directories(rasp_reporting_${test}_test PRIVATE ${CMAKE_CURRENT_LIST_DIR}/../src)
  target_link_libraries(rasp_reporting_${test}_test PRIVATE rasp_plugin_reporting rasp_core rasp_warnings
    rasp_language GTest::gtest_main)
  gtest_discover_tests(rasp_reporting_${test}_test)
endforeach()

# reporting_test.cpp defines the transport's `post` itself, so the plugin posts to the test, and the linker leaves the
# development transport, src/dev/transport.cpp, out of the plugin's static library.
add_executable(rasp_reporting_test ${CMAKE_CURRENT_LIST_DIR}/reporting_test.cpp)
target_include_directories(rasp_reporting_test PRIVATE ${CMAKE_CURRENT_LIST_DIR}/../src)
target_link_libraries(rasp_reporting_test PRIVATE rasp_plugin_reporting rasp_core rasp_warnings rasp_language
  GTest::gtest_main)
target_compile_definitions(rasp_reporting_test PRIVATE
  RASP_REPORTING_ENDPOINT="${RASP_REPORTING_ENDPOINT}")
gtest_discover_tests(rasp_reporting_test)
