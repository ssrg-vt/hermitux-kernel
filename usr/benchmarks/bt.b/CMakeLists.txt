file(GLOB srcs *.c)
add_executable(bt.b ${srcs})

target_compile_options(bt.b PRIVATE -O3 -mcmodel=medium)
target_link_libraries(bt.b -lm)

install_local_targets(extra/benchmarks/npb)
