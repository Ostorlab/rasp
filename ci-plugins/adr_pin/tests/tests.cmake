# The pin plugin's tests, which run on a development machine. The plugin's CMakeLists.txt includes this file at the end
# of the build's top directory, once the build has fetched GoogleTest and enabled the tests.

include(GoogleTest)

foreach(test adr_pin base64 der pins)
  add_executable(rasp_adr_pin_${test}_test ${CMAKE_CURRENT_LIST_DIR}/${test}_test.cpp)
  target_include_directories(rasp_adr_pin_${test}_test PRIVATE ${CMAKE_CURRENT_LIST_DIR}/../src
    ${CMAKE_CURRENT_LIST_DIR})
  target_compile_definitions(rasp_adr_pin_${test}_test PRIVATE RASP_ADR_PIN_TEST_DATA="${CMAKE_CURRENT_LIST_DIR}/data")
  target_link_libraries(rasp_adr_pin_${test}_test PRIVATE rasp_plugin_adr_pin rasp_core rasp_warnings rasp_language
    GTest::gtest_main)
  gtest_discover_tests(rasp_adr_pin_${test}_test)
endforeach()
