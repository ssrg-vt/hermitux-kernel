cmake_minimum_required(VERSION 3.7)
project(hermit_tools)

include(../cmake/HermitCore-Paths.cmake)

add_compile_options(-std=c99)

add_executable(proxy proxy.c utils.c uhyve.c uhyve-net.c uhyve-elf.c mini_gzip.c miniz.c uhyve-gdb.c uhyve-seccomp.c)
target_compile_options(proxy PUBLIC -pthread)
target_compile_options(proxy PUBLIC -DMAX_ARGC_ENVC=${MAX_ARGC_ENVC})
target_link_libraries(proxy -pthread -lseccomp)

install(TARGETS proxy
	DESTINATION bin)

install(FILES init.sh
	DESTINATION tools)

# Show include files in IDE
file(GLOB_RECURSE TOOLS_INCLUDES "*.h")
add_custom_target(tools_includes_ide SOURCES ${TOOLS_INCLUDES})
