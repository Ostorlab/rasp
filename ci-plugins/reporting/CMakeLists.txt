# The reporting plugin: it posts all the observations of every run of the checks, as one JSON document, to the endpoint
# compiled in with RASP_REPORTING_ENDPOINT. It leaves each run it does not deliver in the context the plugins share,
# under the key that include/reporting/undelivered_run.h declares. Another plugin reads that key by adding this
# directory's include/ to its include directories.
#
# It supports Android and iOS. A development machine builds it only for the tests, with RASP_BUILD_TESTS, and with a
# transport that never sends.

set(RASP_REPORTING_ENDPOINT "" CACHE STRING
  "The http:// or https:// URL the reporting plugin posts the observations to. Required.")

if(CMAKE_SYSTEM_NAME STREQUAL "Android")
  set(rasp_reporting_transport src/android/transport.cpp)
elseif(CMAKE_SYSTEM_NAME STREQUAL "iOS")
  set(rasp_reporting_transport src/ios/transport.cpp)
elseif(RASP_BUILD_TESTS)
  set(rasp_reporting_transport src/dev/transport.cpp)
else()
  message(FATAL_ERROR "The reporting plugin supports Android and iOS, and this runtime is for ${CMAKE_SYSTEM_NAME}. "
    "On a development machine, it builds only for the tests, with RASP_BUILD_TESTS.")
endif()

string(LENGTH "${RASP_REPORTING_ENDPOINT}" rasp_reporting_endpoint_size)
if(RASP_REPORTING_ENDPOINT STREQUAL "")
  message(FATAL_ERROR "The reporting plugin needs RASP_REPORTING_ENDPOINT: set it to the http:// or https:// URL it "
    "posts the observations to, such as -DRASP_REPORTING_ENDPOINT=https://reports.example.com/rasp.")
elseif(NOT RASP_REPORTING_ENDPOINT MATCHES "^https?://[^/?#]+" OR NOT RASP_REPORTING_ENDPOINT MATCHES "^[!-~]+$"
    OR RASP_REPORTING_ENDPOINT MATCHES "[\"\\]" OR rasp_reporting_endpoint_size GREATER 2048)
  message(FATAL_ERROR "RASP_REPORTING_ENDPOINT is '${RASP_REPORTING_ENDPOINT}', which is not an http:// or https:// "
    "URL with a host, of at most 2048 printable ASCII characters, without a space, a quote or a backslash.")
endif()

rasp_plugin(reporting SOURCES src/reporting.cpp src/http.cpp src/json.cpp src/mailbox.cpp src/sender.cpp
  ${rasp_reporting_transport})
target_include_directories(rasp_plugin_reporting PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include
  PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_compile_definitions(rasp_plugin_reporting PRIVATE
  RASP_REPORTING_ENDPOINT="${RASP_REPORTING_ENDPOINT}")

if(CMAKE_SYSTEM_NAME STREQUAL "Android")
  include(cmake/curl.cmake)
  target_include_directories(rasp_plugin_reporting SYSTEM PRIVATE ${RASP_REPORTING_CURL_INCLUDE_DIR})
  target_compile_definitions(rasp_plugin_reporting PRIVATE CURL_STATICLIB)
  target_sources(rasp_plugin_reporting PRIVATE ${RASP_REPORTING_TLS_OBJECT})
  set_source_files_properties(${RASP_REPORTING_TLS_OBJECT} PROPERTIES EXTERNAL_OBJECT TRUE GENERATED TRUE)
elseif(CMAKE_SYSTEM_NAME STREQUAL "iOS")
  target_link_libraries(rasp_plugin_reporting PUBLIC "$<LINK_LIBRARY:FRAMEWORK,Network>"
    "$<LINK_LIBRARY:FRAMEWORK,Security>")
endif()

# The runtime fetches GoogleTest and enables the tests after it adds the plugins, so the tests are added at the end of
# the runtime's top directory.
if(RASP_BUILD_TESTS)
  cmake_language(EVAL CODE "cmake_language(DEFER DIRECTORY [[${PROJECT_SOURCE_DIR}]]
    CALL include [[${CMAKE_CURRENT_SOURCE_DIR}/tests/tests.cmake]])")
endif()
