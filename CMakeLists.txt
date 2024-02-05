cmake_minimum_required(VERSION 3.25.1)
project(FullCrypto)

include_directories(include)

file (GLOB SOURCES "src/*.c")

add_executable(FullCrypto ${SOURCES})

target_compile_options(FullCrypto PRIVATE
    -Wall -Wextra -Wpedantic
)