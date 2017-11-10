file(GLOB srcs *.c)
add_executable(sp.b ${srcs})

target_compile_options(sp.b PRIVATE -O3 -mcmodel=medium)
target_link_libraries(sp.b -lm)

install_local_targets(extra/benchmarks/npb)

