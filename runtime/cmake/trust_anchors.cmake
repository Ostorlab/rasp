set(RASP_TLS_TRUST_ANCHORS "" CACHE FILEPATH
  "PEM file of the CA certificates the Android transport trusts. A release must set it: without it, nothing is sent.")

function(rasp_base64_to_bytes text out_var)
  set(alphabet "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
  string(REGEX REPLACE "[ \t\r\n]" "" text "${text}")
  string(REGEX REPLACE "=?=$" "" text "${text}")
  if(NOT text MATCHES "^[A-Za-z0-9+/]+$")
    message(FATAL_ERROR "RASP_TLS_TRUST_ANCHORS: a certificate in ${RASP_TLS_TRUST_ANCHORS} isn't valid base64")
  endif()
  string(REGEX MATCHALL "." characters "${text}")
  set(bytes "")
  set(buffer 0)
  set(bits 0)
  foreach(character IN LISTS characters)
    string(FIND "${alphabet}" "${character}" value)
    math(EXPR buffer "((${buffer} << 6) | ${value}) & 0xFFFF")
    math(EXPR bits "${bits} + 6")
    if(bits GREATER_EQUAL 8)
      math(EXPR bits "${bits} - 8")
      math(EXPR byte "(${buffer} >> ${bits}) & 0xFF" OUTPUT_FORMAT HEXADECIMAL)
      list(APPEND bytes ${byte})
    endif()
  endforeach()
  set(${out_var} "${bytes}" PARENT_SCOPE)
endfunction()

function(rasp_write_trust_anchors header)
  set(arrays "")
  set(names "")
  set(count 0)
  if(RASP_TLS_TRUST_ANCHORS)
    if(NOT EXISTS ${RASP_TLS_TRUST_ANCHORS})
      message(FATAL_ERROR "RASP_TLS_TRUST_ANCHORS: ${RASP_TLS_TRUST_ANCHORS} doesn't exist")
    endif()
    set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS ${RASP_TLS_TRUST_ANCHORS})
    file(READ ${RASP_TLS_TRUST_ANCHORS} pem)
    string(REGEX MATCHALL "-----BEGIN CERTIFICATE-----[^-]+-----END CERTIFICATE-----" blocks "${pem}")
    if(NOT blocks)
      message(FATAL_ERROR "RASP_TLS_TRUST_ANCHORS: ${RASP_TLS_TRUST_ANCHORS} holds no PEM certificate")
    endif()
    set(name_list "")
    foreach(block IN LISTS blocks)
      string(REGEX REPLACE "-----(BEGIN|END) CERTIFICATE-----" "" base64 "${block}")
      rasp_base64_to_bytes("${base64}" bytes)
      list(LENGTH bytes size)
      list(JOIN bytes ", " initializer)
      string(APPEND arrays
        "/// The DER bytes of certificate ${count} of the PEM file.\n"
        "inline constexpr std::array<std::uint8_t, ${size}> kTrustAnchor${count}{${initializer}};\n\n")
      list(APPEND name_list kTrustAnchor${count})
      math(EXPR count "${count} + 1")
    endforeach()
    list(JOIN name_list ", " names)
    message(STATUS "Trust anchors: ${count} certificates from ${RASP_TLS_TRUST_ANCHORS}")
  else()
    message(STATUS "Trust anchors: none, so the Android transport sends nothing (set RASP_TLS_TRUST_ANCHORS)")
  endif()
  file(CONFIGURE OUTPUT ${header} @ONLY CONTENT [=[
/// kTrustAnchors: the certificates the Android transport trusts, built in from the PEM file that the
/// RASP_TLS_TRUST_ANCHORS cache variable names. CMake writes this file when it configures the build, with
/// cmake/trust_anchors.cmake.

#pragma once

#include <array>
#include <cstdint>
#include <span>

namespace rasp::android {

@arrays@/// The DER bytes of each certificate of the PEM file, in the file's order. Empty when the build has no trust anchors.
inline constexpr std::array<std::span<const std::uint8_t>, @count@> kTrustAnchors{@names@};

}  // namespace rasp::android
]=])
endfunction()
