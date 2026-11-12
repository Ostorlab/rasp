# Add explicitly to the host app/test. No shipping-runtime target links this library.
enable_language(C)
add_library(rasp_host_context STATIC src/host_context.c src/clock_math.c)
set_target_properties(rasp_host_context PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED ON
  C_EXTENSIONS OFF C_VISIBILITY_PRESET hidden)
target_include_directories(rasp_host_context PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include
  ${CMAKE_CURRENT_SOURCE_DIR}/../core/include/rasp)
target_compile_options(rasp_host_context PRIVATE -Wall -Wextra -Werror -Wpedantic -Wconversion
  -Wshadow -Wframe-larger-than=4096)
# Existing sanitizer presets set CXX flags; instrument the actual C reducer too.
if(CMAKE_CXX_FLAGS MATCHES "fsanitize=")
  separate_arguments(host_context_sanitizer_flags NATIVE_COMMAND "${CMAKE_CXX_FLAGS}")
  list(FILTER host_context_sanitizer_flags INCLUDE REGEX
    "^(-fsanitize=|-fsanitize-recover=|-fno-sanitize-recover=|-fno-omit-frame-pointer$)")
  target_compile_options(rasp_host_context PRIVATE ${host_context_sanitizer_flags})
endif()
