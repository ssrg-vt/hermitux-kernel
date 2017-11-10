file(GLOB srcs *.c)
add_executable(ep.b ${srcs})

target_compile_options(ep.b PRIVATE -O3 -mcmodel=medium)
target_link_libraries(ep.b -lm)

install_local_targets(extra/benchmarks/npb)

