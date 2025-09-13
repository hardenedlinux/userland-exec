cmake_minimum_required (VERSION 3.3)

project ("userland-exec")

#find_package(libelf REQUIRED)

file( GLOB LIB_SOURCES src/userland_exec.c )
file( GLOB LIB_HEADERS src/userland_exec.h )
add_library( userland-exec ${LIB_SOURCES} ${LIB_HEADERS} )

file( GLOB TEST_SOURCES examples/*.c )
foreach( testsourcefile ${TEST_SOURCES} )
    get_filename_component( testname ${testsourcefile} NAME_WE )
    add_executable( ${testname} ${testsourcefile} )
endforeach( testsourcefile ${TEST_SOURCES} )

file( GLOB APP_SOURCES src/*.c )
add_executable(uexec ${APP_SOURCES})

install(TARGETS uexec RUNTIME DESTINATION)
