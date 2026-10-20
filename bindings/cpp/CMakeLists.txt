# Builds the C++ SDK example and test against a built sourceorrery-ffi.
#
#   cargo build --release -p sourceorrery-ffi
#   cmake -S bindings/cpp -B build/cpp -DSOURCEORRERY_NATIVE_DIR=$PWD/target/release
#   cmake --build build/cpp
#   build/cpp/get_secret development database-password
#
# The header-only SDK itself is just include/sourceorrery.hpp plus the C
# header from crates/sourceorrery-ffi/include.
cmake_minimum_required(VERSION 3.16)
project(sourceorrery-cpp LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(SOURCEORRERY_NATIVE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../target/release"
    CACHE PATH "Directory holding the sourceorrery_ffi shared library")
set(SOURCEORRERY_C_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../crates/sourceorrery-ffi/include"
    CACHE PATH "Directory holding sourceorrery.h")

add_library(sourceorrery INTERFACE)
target_include_directories(sourceorrery INTERFACE
    "${CMAKE_CURRENT_SOURCE_DIR}/include" "${SOURCEORRERY_C_INCLUDE_DIR}")
if(WIN32)
    target_link_libraries(sourceorrery INTERFACE "${SOURCEORRERY_NATIVE_DIR}/sourceorrery_ffi.dll.lib")
else()
    target_link_directories(sourceorrery INTERFACE "${SOURCEORRERY_NATIVE_DIR}")
    target_link_libraries(sourceorrery INTERFACE sourceorrery_ffi pthread)
endif()

if(MSVC)
    add_compile_options(/W4 /WX)
else()
    add_compile_options(-Wall -Wextra -Werror)
endif()

add_executable(get_secret examples/get_secret.cpp)
target_link_libraries(get_secret PRIVATE sourceorrery)

add_executable(reader_test tests/reader_test.cpp)
target_link_libraries(reader_test PRIVATE sourceorrery)

enable_testing()
add_test(NAME reader_test COMMAND reader_test)
