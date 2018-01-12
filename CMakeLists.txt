cmake_minimum_required(VERSION 3.7)
project(orderedhash LANGUAGES C)

set(CMAKE_SKIP_INSTALL_ALL_DEPENDENCY true)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c11 -pedantic -Wall -Wextra -Wno-missing-field-initializers")

add_library(orderedhash_shared SHARED orderedhash.c)
set_target_properties(orderedhash_shared PROPERTIES OUTPUT_NAME orderedhash)
set_target_properties(orderedhash_shared PROPERTIES PUBLIC_HEADER "orderedhash.h")
target_link_libraries(orderedhash_shared sodium)

add_library(orderedhash_static STATIC orderedhash.c)
set_target_properties(orderedhash_static PROPERTIES OUTPUT_NAME orderedhash)
set_target_properties(orderedhash_static PROPERTIES PUBLIC_HEADER "orderedhash.h")
target_link_libraries(orderedhash_static sodium)

install(
    TARGETS orderedhash_shared orderedhash_static
    OPTIONAL
    LIBRARY DESTINATION "lib"
    ARCHIVE DESTINATION "lib"
    PUBLIC_HEADER DESTINATION "include"
)
