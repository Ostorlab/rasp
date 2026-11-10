# The DNS reporting plugin: encodes observations as DNS A-record query names and resolves them against a collector.
# It is the fallback of the reporting plugin: it sends only the run that plugin did not deliver, which it reads under
# the key that ../reporting/include/reporting/undelivered_run.h declares. Without the reporting plugin, it sends nothing.
#
# It contains its own base32hex, CBOR and DNS frame encoders, and sends each chunk as one DNS A-record query with
# getaddrinfo. It supports Android and iOS. A development machine builds it only for the tests, with RASP_BUILD_TESTS,
# and with a transport that never sends.

set(RASP_DNS_REPORTING_ZONE "" CACHE STRING
  "The DNS zone the collector listens on, e.g. rsp.example.com. Required.")

# Android and iOS both resolve with getaddrinfo, so their transports call the shared resolver and only the file that
# names the platform differs. A development machine builds the stub instead, and never the resolver.
if(CMAKE_SYSTEM_NAME STREQUAL "Android")
  set(rasp_dns_reporting_transport src/android/transport.cpp src/resolver.cpp)
elseif(CMAKE_SYSTEM_NAME STREQUAL "iOS")
  set(rasp_dns_reporting_transport src/ios/transport.cpp src/resolver.cpp)
elseif(RASP_BUILD_TESTS)
  set(rasp_dns_reporting_transport src/host/transport.cpp)
else()
  message(FATAL_ERROR "The DNS reporting plugin supports Android and iOS, and this runtime is for "
    "${CMAKE_SYSTEM_NAME}. On a development machine, it builds only for the tests, with RASP_BUILD_TESTS.")
endif()

# In a test-only build the config values are optional: provide deterministic defaults so the plugin compiles without
# requiring the caller to pass -DRASP_DNS_REPORTING_ZONE=... on every cmake invocation.
if(RASP_BUILD_TESTS)
  if(RASP_DNS_REPORTING_ZONE STREQUAL "")
    set(RASP_DNS_REPORTING_ZONE "test.example.com")
  endif()
endif()

# Validate the zone. A non-test build requires the caller to set it; a test build falls through with the default above.
if(RASP_DNS_REPORTING_ZONE STREQUAL "")
  message(FATAL_ERROR "The DNS reporting plugin needs RASP_DNS_REPORTING_ZONE: set it to the DNS zone the collector "
    "listens on, such as -DRASP_DNS_REPORTING_ZONE=rsp.example.com.")
elseif(NOT RASP_DNS_REPORTING_ZONE MATCHES "^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*$")
  message(FATAL_ERROR "RASP_DNS_REPORTING_ZONE '${RASP_DNS_REPORTING_ZONE}' is not a valid DNS zone.")
endif()

# Validate label lengths (max 63 bytes each) and total wire-format size (max kMaxZoneBytes = 48 bytes).
# Wire format matches valid_zone() in dns_frame.cpp: wire_bytes = Σ(1 + label_len), no trailing root byte.
set(rasp_zone_wire_size 0)
string(REPLACE "." ";" rasp_zone_labels "${RASP_DNS_REPORTING_ZONE}")
foreach(rasp_label IN LISTS rasp_zone_labels)
  string(LENGTH "${rasp_label}" rasp_label_len)
  if(rasp_label_len GREATER 63)
    message(FATAL_ERROR "RASP_DNS_REPORTING_ZONE label '${rasp_label}' exceeds 63 bytes.")
  endif()
  math(EXPR rasp_zone_wire_size "${rasp_zone_wire_size} + 1 + ${rasp_label_len}")
endforeach()
if(rasp_zone_wire_size GREATER 48)
  message(FATAL_ERROR "RASP_DNS_REPORTING_ZONE '${RASP_DNS_REPORTING_ZONE}' wire-format size "
    "(${rasp_zone_wire_size} bytes) exceeds the 48-byte limit (kMaxZoneBytes).")
endif()

rasp_plugin(dns_reporting SOURCES
  src/base32hex.cpp
  src/cbor.cpp
  src/dns_frame.cpp
  src/dns_report.cpp
  src/dns_reporting.cpp
  src/mailbox.cpp
  src/random.cpp
  src/sender.cpp
  ${rasp_dns_reporting_transport})
target_include_directories(rasp_plugin_dns_reporting PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src
  ${CMAKE_CURRENT_SOURCE_DIR}/../reporting/include)
target_compile_definitions(rasp_plugin_dns_reporting PRIVATE
  "RASP_DNS_REPORTING_ZONE=\"${RASP_DNS_REPORTING_ZONE}\"")

# The runtime fetches GoogleTest and enables the tests after it adds the plugins, so the tests are added at the end of
# the runtime's top directory.
if(RASP_BUILD_TESTS)
  cmake_language(EVAL CODE "cmake_language(DEFER DIRECTORY [[${PROJECT_SOURCE_DIR}]]
    CALL include [[${CMAKE_CURRENT_SOURCE_DIR}/tests/tests.cmake]])")
endif()
