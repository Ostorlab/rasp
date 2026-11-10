# Links static libraries into one relocatable object in which only the given functions stay global, and fails when the
# object still needs an Mbed TLS or PSA function from outside. curl.cmake runs it with `cmake -P`.
#
# -DLINKER=<ld.lld> -DOBJCOPY=<llvm-objcopy> -DNM=<llvm-nm>: the tools.
# -DARCHIVES=<archive;...>: the static libraries.
# -DKEEP=<function;...>: the functions that stay global. Each one is linked in from the archives.
# -DOUTPUT=<object>: the object to write.

foreach(name IN ITEMS LINKER OBJCOPY NM ARCHIVES KEEP OUTPUT)
  if(NOT DEFINED ${name} OR "${${name}}" STREQUAL "")
    message(FATAL_ERROR "isolate.cmake needs -D${name}")
  endif()
endforeach()

set(linked ${OUTPUT}.linked)
set(keep_file ${OUTPUT}.keep)
set(undefined_flags "")
foreach(function IN LISTS KEEP)
  list(APPEND undefined_flags --undefined=${function})
endforeach()
list(JOIN KEEP "\n" keep_lines)
file(WRITE ${keep_file} "${keep_lines}\n")

execute_process(
  COMMAND ${LINKER} --relocatable ${undefined_flags} --start-group ${ARCHIVES} --end-group -o ${linked}
  COMMAND_ERROR_IS_FATAL ANY)
execute_process(
  COMMAND ${OBJCOPY} --keep-global-symbols=${keep_file} ${linked} ${OUTPUT}
  COMMAND_ERROR_IS_FATAL ANY)

execute_process(
  COMMAND ${NM} --undefined-only --format=just-symbols ${OUTPUT}
  OUTPUT_VARIABLE undefined
  COMMAND_ERROR_IS_FATAL ANY)
string(REGEX MATCHALL "(^|\n)(mbedtls|psa|tf_psa)_[^\n]*" foreign "${undefined}")
if(foreign)
  string(STRIP "${foreign}" foreign)
  file(REMOVE ${OUTPUT})
  message(FATAL_ERROR "${OUTPUT} still needs these functions from outside it:\n${foreign}")
endif()

execute_process(
  COMMAND ${NM} --defined-only --extern-only --format=just-symbols ${OUTPUT}
  OUTPUT_VARIABLE global
  COMMAND_ERROR_IS_FATAL ANY)
string(REGEX REPLACE "\n$" "" global "${global}")
string(REPLACE "\n" ";" global "${global}")
list(SORT global)
set(expected ${KEEP})
list(SORT expected)
if(NOT global STREQUAL expected)
  file(REMOVE ${OUTPUT})
  message(FATAL_ERROR "${OUTPUT} defines the global symbols '${global}', expected '${expected}'")
endif()
file(REMOVE ${linked} ${keep_file})
