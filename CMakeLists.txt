cmake_minimum_required(VERSION 3.16.3)
project(FullCrypto)

include_directories(include)

file (GLOB SOURCES "src/*.c")

add_executable(FullCrypto ${SOURCES})

target_compile_options(FullCrypto PRIVATE
    -Wall -Wextra -Wpedantic
)

target_link_libraries(FullCrypto gmp)