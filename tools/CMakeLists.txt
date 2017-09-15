cmake_minimum_required(VERSION 3.7)
project(hermit_tools)

include(../cmake/HermitCore-Paths.cmake)

# Switched from c99 to GNU99 to enable inline assembly
add_compile_options(-std=gnu99 -g)

add_executable(proxy proxy.c uhyve.c)
target_compile_options(proxy PUBLIC -pthread)
target_link_libraries(proxy -pthread)

install(TARGETS proxy
	DESTINATION bin)

install(FILES init.sh
	DESTINATION tools)

# Show include files in IDE
file(GLOB_RECURSE TOOLS_INCLUDES "*.h")
add_custom_target(tools_includes_ide SOURCES ${TOOLS_INCLUDES})
