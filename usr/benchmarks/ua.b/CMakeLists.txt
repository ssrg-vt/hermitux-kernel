file(GLOB srcs *.c)
add_executable(ua.b ${srcs})

target_compile_options(ua.b PRIVATE -O3 -mcmodel=medium)
target_link_libraries(ua.b -lm)

install_local_targets(extra/benchmarks/npb)

