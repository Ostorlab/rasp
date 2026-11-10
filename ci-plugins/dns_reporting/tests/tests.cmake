# The DNS reporting plugin's tests, which run on a development machine. The plugin's CMakeLists.txt includes this file
# at the end of the runtime's top directory, once the runtime's tests have fetched GoogleTest and enabled the tests.

include(GoogleTest)

foreach(test base32hex cbor dns_frame dns_report dns_reporting mailbox sender)
  add_executable(rasp_dns_reporting_${test}_test ${CMAKE_CURRENT_LIST_DIR}/${test}_test.cpp)
  target_include_directories(rasp_dns_reporting_${test}_test PRIVATE ${CMAKE_CURRENT_LIST_DIR}/../src
    ${CMAKE_CURRENT_LIST_DIR}/../../reporting/include)
  target_link_libraries(rasp_dns_reporting_${test}_test PRIVATE rasp_plugin_dns_reporting rasp_core rasp_warnings
    rasp_language GTest::gtest_main)
  gtest_discover_tests(rasp_dns_reporting_${test}_test)
endforeach()
