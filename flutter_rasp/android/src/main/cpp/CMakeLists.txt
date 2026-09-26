cmake_minimum_required(VERSION 3.22.1)
project(rasp_core C)

add_library(rasp_core SHARED
    rasp_jni.c
    detectors.c
    signals.c
)

target_compile_options(rasp_core PRIVATE -Wall -Wextra -Werror -O2 -fvisibility=hidden)
target_link_libraries(rasp_core log)
