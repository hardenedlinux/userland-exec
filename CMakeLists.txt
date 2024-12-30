cmake_minimum_required (VERSION 3.3)

project ("userland-exec" C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED True)

set(WARNING_FLAGS
    "-Wall"
    "-Wextra"
    "-Wpedantic"
    "-Wshadow"
    "-Wconversion"
    "-Wsign-conversion"
    "-Wnull-dereference"
    "-Wdouble-promotion"
    "-Wformat=2"
    "-Wuninitialized"
)

string(REPLACE ";" " " WARNING_FLAGS_STR "${WARNING_FLAGS}")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${WARNING_FLAGS_STR}")

# Define build types if not specified
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Release" CACHE STRING "Build type (Debug or Release)" FORCE)
endif()

# Debug configuration
set(CMAKE_C_FLAGS_DEBUG "-g -O2 -DDEBUG -DLOG_ERROR")
set(CMAKE_EXE_LINKER_FLAGS_DEBUG "-g")

# Release configuration
set(CMAKE_C_FLAGS_RELEASE "-O3 -DLOG_ERROR")
set(CMAKE_EXE_LINKER_FLAGS_RELEASE "")

file(GLOB LIB_SOURCES src/userland_exec.c)
file(GLOB LIB_HEADERS src/userland_exec.h)
add_library(userland-exec ${LIB_SOURCES} ${LIB_HEADERS})

file(GLOB TEST_SOURCES examples/*.c)
foreach(testsourcefile ${TEST_SOURCES})
    get_filename_component(testname ${testsourcefile} NAME_WE)
    add_executable(${testname} ${testsourcefile})
endforeach(testsourcefile ${TEST_SOURCES})

file(GLOB APP_SOURCES src/*.c)
add_executable(uexec ${APP_SOURCES})

install(TARGETS uexec RUNTIME DESTINATION)
