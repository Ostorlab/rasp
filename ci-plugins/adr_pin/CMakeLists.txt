# The pin plugin: on every run of the checks, it opens a TLS connection to the host compiled in with RASP_ADR_PIN_HOST
# and reports the public keys the host presented, as SPKI pins, and whether the system trusted them.
#
# It probes only on an iPhone for now. Everywhere else it reports both signals as unsupported.

set(RASP_ADR_PIN_HOST "" CACHE STRING
  "The host the pin plugin opens a TLS connection to, on port 443, such as rasp.example.com. Required.")

string(LENGTH "${RASP_ADR_PIN_HOST}" rasp_adr_pin_host_size)
if(RASP_ADR_PIN_HOST STREQUAL "")
  message(FATAL_ERROR "The pin plugin needs RASP_ADR_PIN_HOST: set it to the host whose keys it reports, such as "
    "-DRASP_ADR_PIN_HOST=rasp.example.com.")
elseif(NOT RASP_ADR_PIN_HOST MATCHES "^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)*$"
    OR rasp_adr_pin_host_size GREATER 253)
  message(FATAL_ERROR "RASP_ADR_PIN_HOST is '${RASP_ADR_PIN_HOST}', which is not a host name: dot-separated labels of "
    "letters, digits and inner hyphens, of at most 253 characters, without a scheme, a port or a path.")
endif()

if(CMAKE_SYSTEM_NAME STREQUAL "iOS")
  set(rasp_adr_pin_handshake src/ios/handshake.cpp)
else()
  set(rasp_adr_pin_handshake src/host/handshake.cpp)
endif()

rasp_plugin(adr_pin SOURCES src/adr_pin.cpp src/base64.cpp src/der.cpp src/pins.cpp src/sha256.cpp
  ${rasp_adr_pin_handshake})
target_include_directories(rasp_plugin_adr_pin PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)
target_compile_definitions(rasp_plugin_adr_pin PRIVATE RASP_ADR_PIN_HOST="${RASP_ADR_PIN_HOST}")
if(CMAKE_SYSTEM_NAME STREQUAL "iOS")
  target_link_libraries(rasp_plugin_adr_pin PUBLIC "$<LINK_LIBRARY:FRAMEWORK,Network>"
    "$<LINK_LIBRARY:FRAMEWORK,Security>" "$<LINK_LIBRARY:FRAMEWORK,CoreFoundation>")
endif()

# The runtime fetches GoogleTest and enables the tests after it adds the plugins, so the tests are added at the end of
# the runtime's top directory.
if(RASP_BUILD_TESTS)
  cmake_language(EVAL CODE "cmake_language(DEFER DIRECTORY [[${PROJECT_SOURCE_DIR}]]
    CALL include [[${CMAKE_CURRENT_SOURCE_DIR}/tests/tests.cmake]])")
endif()
