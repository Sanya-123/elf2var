cmake_minimum_required(VERSION 3.5)

# create plugin and app
set(PROJECT_NAME elf2var)

project(${PROJECT_NAME} LANGUAGES C)

set(CMAKE_INCLUDE_CURRENT_DIR ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
# set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/dwarves/cmake/modules/)

set(BUILD_SHARED_LIBS OFF)
add_subdirectory(dwarves)

add_library(${PROJECT_NAME} STATIC
    elf2var.h
    elf2var.c
    varcommon/varcommon.c
)

target_include_directories(${PROJECT_NAME} PRIVATE dwarves varcommon)
target_link_libraries(${PROJECT_NAME} PRIVATE dwarves)




