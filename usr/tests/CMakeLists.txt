cmake_minimum_required(VERSION 3.7)
include(../../cmake/HermitCore-Application.cmake)

project(hermit_tests C CXX Fortran Go)

#add_executable(hello hello.c)
#add_executable(hello-minimal hello-minimal.c)
#add_executable(argv_envp argv_envp.c)
#add_executable(timing timing.c)
#add_executable(jacobi jacobi.c)
#add_executable(hello++ hello++.cpp)
# add_executable(hellof hellof.f90)
# add_executable(pi pi.go)

add_executable(hermitux hermitux.c linker.ld)
set_target_properties(hermitux PROPERTIES LINK_DEPENDS ${CMAKE_SOURCE_DIR}/linker.ld)
set_target_properties(hermitux PROPERTIES LINK_DEPENDS ${LOCAL_PREFIX_ARCH_LIB_DIR}/libhermit.a)
target_link_libraries(hermitux -Wl,-T,${CMAKE_SOURCE_DIR}/linker.ld)

#add_executable(test-malloc test-malloc.c)
#add_executable(test-malloc-mt test-malloc-mt.c)
#target_compile_options(test-malloc-mt PRIVATE -pthread)
#target_link_libraries(test-malloc-mt pthread)

# add_executable(server server.go)
# target_link_libraries(server netgo)

#if(NOT ${NO_IRCCE})
#add_executable(RCCE_minimum RCCE_minimum.c)
#target_link_libraries(RCCE_minimum ircce)
#endif(NOT ${NO_IRCCE})

#add_executable(thr_hello thr_hello.c)
#target_compile_options(thr_hello PRIVATE -pthread)
#target_link_libraries(thr_hello pthread)

#add_executable(signals signals.c)
#target_compile_options(signals PRIVATE -pthread)
#target_link_libraries(signals pthread)

add_executable(syscall_tester syscall_tester.c)

# deployment
install_local_targets(extra/tests)
