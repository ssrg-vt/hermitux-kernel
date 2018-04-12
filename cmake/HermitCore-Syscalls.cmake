include_guard()

set(SC_FILE_NAME "${CMAKE_CURRENT_LIST_DIR}/../kernel/syscalls/supported_syscalls.csv")
set(HEADER_IP_FILE "${CMAKE_CURRENT_LIST_DIR}/../include/hermit/syscall_disabler.h.in")
set(HEADER_OP_FILE "${CMAKE_CURRENT_LIST_DIR}/../include/hermit/syscall_disabler.h")


function(split_csv_file supported_sc_nos sc_file_names sc_disable_macros)
  # Convert the supported_syscalls.csv file into a CMake list.
  file(READ ${SC_FILE_NAME} supported_syscalls_csv)
  string(REGEX REPLACE "\n" ";" supported_syscalls_list ${supported_syscalls_csv})

  # Remove the trailing semicolon from the list.
  string(LENGTH "${supported_syscalls_list}" len)
  MATH(EXPR newlen "${len} - 1")
  string(SUBSTRING "${supported_syscalls_list}" 0 ${newlen} supported_syscalls_list)

  # Split the input CSV file into 3 different lists.
  # Initialise all 3 lists to empty strings.
  set(supported_sc_nos_loc "")
  set(sc_file_names_loc "")
  set(sc_disable_macros_loc "")

  # We convert each line of the list into a new (temporary) list. Then get the element
  # at the desired index (column number) from this temporary list and add it to the new list.
  foreach(syscall ${supported_syscalls_list})
    string(REGEX REPLACE "," ";" scl ${syscall})
    list(GET scl 0 scno)
    list(GET scl 1 fname)
    list(GET scl 2 dmac)
    list(APPEND supported_sc_nos_loc ${scno})
    list(APPEND sc_file_names_loc ${fname})
    list(APPEND sc_disable_macros_loc ${dmac})
  endforeach(syscall)

  set(${supported_sc_nos} ${supported_sc_nos_loc} PARENT_SCOPE)
  set(${sc_file_names} ${sc_file_names_loc} PARENT_SCOPE)
  set(${sc_disable_macros} ${sc_disable_macros_loc} PARENT_SCOPE)
  
endfunction(split_csv_file)


macro(enable_all_syscalls)
  # Add all files to sources
  add_kernel_module_sources("syscalls" "${CMAKE_CURRENT_LIST_DIR}/../kernel/syscalls/*.c")

  split_csv_file(supported_sc_nos sc_file_names sc_disable_macros)

  # Set all macro values to false
  list(LENGTH sc_disable_macros len)
  MATH(EXPR supported_len "${len} - 1")
  foreach(ind RANGE ${supported_len})
    list(GET sc_disable_macros ${ind} macro_name)
    set("${macro_name}" "FALSE")
  endforeach(ind)

  configure_file(${HEADER_IP_FILE} ${HEADER_OP_FILE})
endmacro(enable_all_syscalls)


macro(select_system_calls)
  # No executable given as input argument. Add all files and return.
  if(NOT EXEC)
    message(STATUS "No input executable provided")
    message(STATUS "Compiling HermiTux with all system calls.")

    enable_all_syscalls()
    return()
  endif()

  # Get all the syscalls being made by the executable.
  # The output of identify_syscalls is already in the CMake list format
  set(sc_id_cmd "${CMAKE_CURRENT_LIST_DIR}/../../syscall-identification/identify_syscalls")
  execute_process(COMMAND ${sc_id_cmd} ${EXEC} WORKING_DIRECTORY
    ${CMAKE_CURRENT_LIST_DIR}/../build OUTPUT_VARIABLE required_syscalls RESULT_VARIABLE id_res)

  # Not all system calls could be identified. Add all files and return.
  if(id_res)
    message(STATUS "Could not identify all system calls being made by the binary.")
    message(STATUS "Compiling HermiTux with all system calls and hoping for the best.")

    enable_all_syscalls()
    return()
  endif()

  list(LENGTH required_syscalls sc_len)
  message(STATUS "${sc_len} unique syscalls are being made by the application.")

  # Append certain system calls to the required list regardless, because they are
  # called elsewhere in the kernel
  list(APPEND required_syscalls "39")
  list(REMOVE_DUPLICATES required_syscalls)
  list(SORT required_syscalls)

  split_csv_file(supported_sc_nos sc_file_names sc_disable_macros)

  # For each required system call, search for it in supported_sc_nos.
  foreach(reqsc ${required_syscalls})
    list(FIND supported_sc_nos ${reqsc} sc_index)

    if(${sc_index} EQUAL -1)
      continue()
    endif()

    # Add syscall source file.
    list(GET sc_file_names ${sc_index} fname)
    add_kernel_module_sources("syscalls" "${CMAKE_CURRENT_LIST_DIR}/../kernel/syscalls/${fname}")

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
endmacro(select_system_calls)

#message("EXEC = ${EXEC}")
select_system_calls()
