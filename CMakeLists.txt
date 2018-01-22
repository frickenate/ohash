cmake_minimum_required(VERSION 3.7) # TODO can we support lower 3.x?
project(ohash LANGUAGES C)

set(CMAKE_SKIP_INSTALL_ALL_DEPENDENCY true)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c11 -pedantic -Wall -Wextra -Wno-missing-field-initializers")

add_library(ohash_shared SHARED ohash.c)
set_target_properties(ohash_shared PROPERTIES OUTPUT_NAME ohash)
set_target_properties(ohash_shared PROPERTIES PUBLIC_HEADER "ohash.h")
target_link_libraries(ohash_shared sodium)

add_library(ohash_static STATIC ohash.c)
set_target_properties(ohash_static PROPERTIES OUTPUT_NAME ohash)
set_target_properties(ohash_static PROPERTIES PUBLIC_HEADER "ohash.h")
target_link_libraries(ohash_static sodium)

install(
    TARGETS ohash_shared ohash_static
    OPTIONAL
    LIBRARY DESTINATION "lib"
    ARCHIVE DESTINATION "lib"
    PUBLIC_HEADER DESTINATION "include"
)
