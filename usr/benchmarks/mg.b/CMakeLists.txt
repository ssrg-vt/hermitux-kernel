file(GLOB srcs *.c)
add_executable(mg.b ${srcs})

target_compile_options(mg.b PRIVATE -O3 -mcmodel=medium)
target_link_libraries(mg.b -lm)

install_local_targets(extra/benchmarks/npb)

