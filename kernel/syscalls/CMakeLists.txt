cmake_minimum_required(VERSION 3.7)
include(../../cmake/HermitCore.cmake)

#project (HermitCore)

set(_KERNEL_MODULES "" PARENT_SCOPE)
set(_KERNEL_SOURCES_syscalls "" PARENT_SCOPE)
# set_parent(_KERNEL_MODULES "")
# set_parent(_KERNEL_SOURCES_syscalls "")

# No executable given as input argument. Add all files and return.
if(NOT EXEC)
  # TODO: CMake stores the previous value in the cache, so we need to find some way to make it discard that
  message(STATUS "No input executable provided")
  message(STATUS "Compiling HermiTux with all system calls.")
  add_kernel_module_sources("syscalls"	"${CMAKE_CURRENT_LIST_DIR}/*.c")
  # TODO: configure_file
  return()
endif()

set(SC_FILE_NAME "${CMAKE_CURRENT_LIST_DIR}/supported_syscalls.csv")
set(HEADER_IP_FILE "${CMAKE_SOURCE_DIR}/include/hermit/syscall_disabler.h.in")
set(HEADER_OP_FILE "${CMAKE_SOURCE_DIR}/include/hermit/syscall_disabler.h")

# Get all the syscalls being made by the executable.
# The output of identify_syscalls is already in the CMake list format
set(sc_id_cmd "${CMAKE_CURRENT_LIST_DIR}/../../../syscall-identification/identify_syscalls")
execute_process(COMMAND ${sc_id_cmd} ${EXEC} WORKING_DIRECTORY
  ${CMAKE_SOURCE_DIR}/build OUTPUT_VARIABLE required_syscalls RESULT_VARIABLE id_res)

# Not all system calls could be identified. Add all files and return.
if(id_res)
  message(STATUS "Could not identify all system calls being made by the binary.")
  message(STATUS "Compiling HermiTux with all system calls and hoping for the best.")
  add_kernel_module_sources("syscalls"	"./*.c")
  # TODO: configure_file
  return()
endif()

list(LENGTH required_syscalls sc_len)
message(STATUS "${sc_len} unique syscalls are being made by the application.")

# Convert the supported_syscalls.csv file into a CMake list.
file(READ ${SC_FILE_NAME} supported_syscalls_csv)
string(REGEX REPLACE "\n" ";" supported_syscalls_list ${supported_syscalls_csv})

# Remove the trailing semicolon from the list.
string(LENGTH "${supported_syscalls_list}" len)
MATH(EXPR newlen "${len} - 1")
string(SUBSTRING "${supported_syscalls_list}" 0 ${newlen} supported_syscalls_list)

# Split the input CSV file into 3 different lists.
# Initialise all 3 lists to empty strings.
set(supported_sc_nos "")
set(sc_file_names "")
set(sc_disable_macros "")

# We convert each line of the list into a new (temporary) list. Then get the element
# at the desired index (column number) from this temporary list and add it to the new list.
foreach(syscall ${supported_syscalls_list})
  string(REGEX REPLACE "," ";" scl ${syscall})
  list(GET scl 0 scno)
  list(GET scl 1 fname)
  list(GET scl 2 dmac)
  list(APPEND supported_sc_nos ${scno})
  list(APPEND sc_file_names ${fname})
  list(APPEND sc_disable_macros ${dmac})
endforeach(syscall)


# For each required system call, search for it in supported_sc_nos.
foreach(reqsc ${required_syscalls})
  list(FIND supported_sc_nos reqsc sc_index)

  # Abort if not found.
  if(NOT sc_index)
    message(FATAL_ERROR "Application requires an unsupported system call and will not work with HermiTux.")
  endif()

  # Add syscall source file.
  list(GET sc_file_names ${sc_index} fname)
  add_kernel_module_sources("syscalls" "${fname}")

endforeach(reqsc)

# For each macro set its value depending on whether the corresponding syscall is required or not.
list(LENGTH sc_disable_macros len)
MATH(EXPR supported_len "${len} - 1")
foreach(ind RANGE ${supported_len})
  list(GET sc_disable_macros ${ind} macro_name)
  list(GET supported_sc_nos ${ind} sc_num)

  list(FIND required_syscalls ${sc_num} found)
  if (found EQUAL -1)
    set("${macro_name}" "TRUE")
  else()
    set("${macro_name}" "FALSE")
  endif()
endforeach(ind)

configure_file(${HEADER_IP_FILE} ${HEADER_OP_FILE})
