# Builds libcurl with Mbed TLS as its TLS backend, for the reporting plugin's HTTPS on Android, and links both into one
# object file, ${RASP_REPORTING_TLS_OBJECT}, for the plugin's library. RASP_REPORTING_CURL_INCLUDE_DIR is the folder of
# libcurl's headers.
#
# Both are built from source archives committed in plugins/reporting/third_party, so the build downloads nothing. Each
# archive holds the part of an official release that the build needs, and is checked against its SHA-256; the pack.sh
# next to it makes it from the release. They are static libraries compiled with every symbol hidden, so the runtime
# still exports nothing of theirs.
#
# libcurl keeps only what an HTTP(S) POST needs: HTTP/1.1, TLS through Mbed TLS, the threaded resolver and IPv6. Every
# other protocol is left out, and so are cookies, proxies, HTTP authentication, alt-svc, HSTS, netrc, compression, IDN,
# HTTP/2, HTTP/3, and a default CA bundle or path. It never touches signals: the checks for alarm, sigaction,
# siginterrupt, signal and sigsetjmp are answered "not found", so the library doesn't import them.
#
# Mbed TLS keeps its default config, with two changes:
# - Its random generator reads its seed from /dev/urandom. On Android it reads a device file rather than calling
#   getrandom, and its default, /dev/random, can block for a long time on Linux kernels older than 5.6, which some
#   Android 12 devices run. /dev/urandom never blocks.
# - Its debug messages are left out (MBEDTLS_DEBUG_C). libcurl never turns them on, and their code would put the
#   absolute path of each source file, on the machine that built it, into the runtime.
#
# Mbed TLS brings its own TF-PSA-Crypto, which is not the version the runtime vendors and has another config, and the
# two define the same functions. So libcurl, Mbed TLS and its TF-PSA-Crypto are linked into one relocatable object, in
# which every symbol is made local except the libcurl functions the plugin calls (rasp_reporting_curl_functions). The
# runtime's code then never calls Mbed TLS's crypto, and libcurl never calls the runtime's. The build fails when the
# object still needs an Mbed TLS or PSA function from outside.
#
# Their options are normal variables of this directory, not cache entries, so they don't change how the runtime builds
# its own TF-PSA-Crypto, and the runtime's cache entries for that one don't change this one. Only names that libcurl
# alone reads are cache entries: CURL_CA_BUNDLE and CURL_CA_PATH, which libcurl turns off only when their cache entry
# is `none`, the Mbed TLS paths its FindMbedTLS reads, and the answers to its signal checks.

include(FetchContent)

set(rasp_reporting_third_party ${CMAKE_CURRENT_LIST_DIR}/../third_party)
FetchContent_Declare(mbedtls
  URL ${rasp_reporting_third_party}/mbedtls/mbedtls-4.2.0-source.tar.xz
  URL_HASH SHA256=bf1617db5acee501bb20813cb24e9627d9977b262436407e74986e89c877abc6
  DOWNLOAD_EXTRACT_TIMESTAMP ON
  SYSTEM
  EXCLUDE_FROM_ALL)
FetchContent_Declare(curl
  URL ${rasp_reporting_third_party}/curl/curl-8.23.0-source.tar.xz
  URL_HASH SHA256=9ef543efdba8d13fe830545cd30413b5969f9d3245ef98352596a8d6edd79be1
  DOWNLOAD_EXTRACT_TIMESTAMP ON
  SYSTEM
  EXCLUDE_FROM_ALL)

set(CMAKE_POLICY_DEFAULT_CMP0077 NEW)
set(CMAKE_POLICY_DEFAULT_CMP0126 NEW)
set(CMAKE_C_VISIBILITY_PRESET hidden)

foreach(name IN ITEMS ENABLE_PROGRAMS ENABLE_TESTING GEN_FILES MBEDTLS_FATAL_WARNINGS TF_PSA_CRYPTO_FATAL_WARNINGS
    USE_SHARED_MBEDTLS_LIBRARY)
  set(${name} OFF)
endforeach()
foreach(name IN ITEMS DISABLE_PACKAGE_CONFIG_AND_INSTALL USE_STATIC_MBEDTLS_LIBRARY)
  set(${name} ON)
endforeach()
set(TF_PSA_CRYPTO_CONFIG_FILE "")
set(TF_PSA_CRYPTO_USER_CONFIG_FILE ${CMAKE_CURRENT_BINARY_DIR}/tf_psa_crypto_user_config.h)
file(CONFIGURE OUTPUT ${TF_PSA_CRYPTO_USER_CONFIG_FILE} CONTENT [=[
#define MBEDTLS_PLATFORM_DEV_RANDOM "/dev/urandom"
]=])
set(MBEDTLS_USER_CONFIG_FILE ${CMAKE_CURRENT_BINARY_DIR}/mbedtls_user_config.h)
file(CONFIGURE OUTPUT ${MBEDTLS_USER_CONFIG_FILE} CONTENT [=[
#undef MBEDTLS_DEBUG_C
]=])
FetchContent_MakeAvailable(mbedtls)

set(MBEDTLS_INCLUDE_DIR ${mbedtls_SOURCE_DIR}/include CACHE PATH "" FORCE)
set(MBEDTLS_LIBRARY mbedtls CACHE STRING "" FORCE)
set(MBEDX509_LIBRARY mbedx509 CACHE STRING "" FORCE)
set(MBEDCRYPTO_LIBRARY tfpsacrypto CACHE STRING "" FORCE)

foreach(name IN ITEMS
    BUILD_CURL_EXE BUILD_EXAMPLES BUILD_LIBCURL_DOCS BUILD_MISC_DOCS BUILD_SHARED_LIBS BUILD_TESTING CURL_BROTLI
    CURL_CA_NATIVE CURL_ENABLE_EXPORT_TARGET CURL_ENABLE_NTLM CURL_HIDDEN_SYMBOLS CURL_USE_CMAKECONFIG CURL_USE_GNUTLS
    CURL_USE_GSASL CURL_USE_GSSAPI CURL_USE_LIBPSL CURL_USE_LIBSSH CURL_USE_LIBSSH2 CURL_USE_OPENSSL CURL_USE_PKGCONFIG
    CURL_USE_RUSTLS CURL_USE_WOLFSSL CURL_ZLIB CURL_ZSTD ENABLE_ARES ENABLE_CURL_MANUAL ENABLE_UNIX_SOCKETS
    PICKY_COMPILER USE_ECH USE_HTTPSRR USE_LIBIDN2 USE_NGHTTP2 USE_NGTCP2 USE_QUICHE)
  set(${name} OFF)
endforeach()
foreach(name IN ITEMS
    BUILD_STATIC_LIBS CURL_DISABLE_ALTSVC CURL_DISABLE_AWS CURL_DISABLE_BASIC_AUTH CURL_DISABLE_BEARER_AUTH
    CURL_DISABLE_BINDLOCAL CURL_DISABLE_COOKIES CURL_DISABLE_DICT CURL_DISABLE_DIGEST_AUTH CURL_DISABLE_DOH
    CURL_DISABLE_FILE CURL_DISABLE_FORM_API CURL_DISABLE_FTP CURL_DISABLE_GETOPTIONS CURL_DISABLE_GOPHER
    CURL_DISABLE_HEADERS_API CURL_DISABLE_HSTS CURL_DISABLE_HTTP_AUTH CURL_DISABLE_HTTPSIG CURL_DISABLE_IMAP
    CURL_DISABLE_INSTALL CURL_DISABLE_IPFS CURL_DISABLE_KERBEROS_AUTH CURL_DISABLE_LDAP CURL_DISABLE_LDAPS
    CURL_DISABLE_LIBCURL_OPTION CURL_DISABLE_MIME CURL_DISABLE_MQTT CURL_DISABLE_NEGOTIATE_AUTH CURL_DISABLE_NETRC
    CURL_DISABLE_PARSEDATE CURL_DISABLE_POP3 CURL_DISABLE_PROGRESS_METER CURL_DISABLE_PROXY CURL_DISABLE_RTSP
    CURL_DISABLE_SHA512_256 CURL_DISABLE_SHUFFLE_DNS CURL_DISABLE_SMTP CURL_DISABLE_TELNET CURL_DISABLE_TFTP
    CURL_DISABLE_VERBOSE_STRINGS CURL_DISABLE_WEBSOCKETS CURL_ENABLE_SSL CURL_USE_MBEDTLS ENABLE_IPV6
    ENABLE_THREADED_RESOLVER)
  set(${name} ON)
endforeach()
set(CURL_CA_BUNDLE none CACHE STRING "" FORCE)
set(CURL_CA_PATH none CACHE STRING "" FORCE)
foreach(name IN ITEMS HAVE_ALARM HAVE_SIGACTION HAVE_SIGINTERRUPT HAVE_SIGNAL HAVE_SIGSETJMP)
  set(${name} 0 CACHE INTERNAL "")
endforeach()
FetchContent_MakeAvailable(curl)

set(RASP_REPORTING_CURL_INCLUDE_DIR ${curl_SOURCE_DIR}/include)
set(RASP_REPORTING_TLS_OBJECT ${CMAKE_CURRENT_BINARY_DIR}/rasp_reporting_tls.o)
set(rasp_reporting_curl_functions curl_easy_cleanup curl_easy_getinfo curl_easy_init curl_easy_perform curl_easy_setopt
  curl_global_init curl_slist_append curl_slist_free_all)
set(rasp_reporting_tls_archives
  "$<TARGET_FILE:libcurl_static>;$<TARGET_FILE:mbedtls>;$<TARGET_FILE:mbedx509>;$<TARGET_FILE:tfpsacrypto>")
add_custom_command(OUTPUT ${RASP_REPORTING_TLS_OBJECT}
  COMMAND ${CMAKE_COMMAND}
    -DLINKER=${CMAKE_LINKER}
    -DOBJCOPY=${CMAKE_OBJCOPY}
    -DNM=${CMAKE_NM}
    "-DARCHIVES=${rasp_reporting_tls_archives}"
    "-DKEEP=${rasp_reporting_curl_functions}"
    -DOUTPUT=${RASP_REPORTING_TLS_OBJECT}
    -P ${CMAKE_CURRENT_LIST_DIR}/isolate.cmake
  DEPENDS libcurl_static mbedtls mbedx509 tfpsacrypto ${CMAKE_CURRENT_LIST_DIR}/isolate.cmake
  COMMENT "Linking libcurl and Mbed TLS into the reporting plugin's TLS object"
  VERBATIM)
