file(GLOB srcs *.c)
add_executable(is.b ${srcs})

target_compile_options(is.b PRIVATE -O3 -mcmodel=medium)
target_link_libraries(is.b -lm)

install_local_targets(extra/benchmarks/npb)

