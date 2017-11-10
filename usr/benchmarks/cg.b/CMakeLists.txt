file(GLOB srcs *.c)
add_executable(cg.b ${srcs})

target_compile_options(cg.b PRIVATE -O3 -mcmodel=medium)
target_link_libraries(cg.b -lm)

install_local_targets(extra/benchmarks/npb)

