cmake_minimum_required(VERSION 3.5)

# create plugin and app
set(PROJECT_NAME elf2var)

project(${PROJECT_NAME} LANGUAGES C)

set(BUILD_SHARED_LIBS OFF)
add_subdirectory(dwarves)

add_library(${PROJECT_NAME} STATIC
    elf2var.h
    elf2var.c
    varcommon/varcommon.c
    varcommon/varcommon.h
)

target_include_directories(${PROJECT_NAME} PRIVATE dwarves)
target_link_libraries(${PROJECT_NAME} PRIVATE dwarves)




