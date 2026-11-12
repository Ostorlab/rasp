# Optional source package: only host/test targets link it, never an injected runtime.
enable_language(C)
add_library(rasp_entrypoint_validation STATIC src/link_validation.c)
set_target_properties(rasp_entrypoint_validation PROPERTIES C_STANDARD 11 C_STANDARD_REQUIRED ON
  C_EXTENSIONS OFF C_VISIBILITY_PRESET hidden)
target_include_directories(rasp_entrypoint_validation PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_compile_options(rasp_entrypoint_validation PRIVATE -Wall -Wextra -Werror -Wpedantic -Wconversion
  -Wshadow -Wframe-larger-than=4096)
if(CMAKE_CXX_FLAGS MATCHES "fsanitize=")
  separate_arguments(entry_sanitizer_flags NATIVE_COMMAND "${CMAKE_CXX_FLAGS}")
  list(FILTER entry_sanitizer_flags INCLUDE REGEX
    "^(-fsanitize=|-fsanitize-recover=|-fno-sanitize-recover=|-fno-omit-frame-pointer$)")
  target_compile_options(rasp_entrypoint_validation PRIVATE ${entry_sanitizer_flags})
endif()
