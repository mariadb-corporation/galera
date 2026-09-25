#
# Copyright (C) 2020-2026 Codership Oy <info@codership.com>
#
# OS specific tweaks and libraries.
#

find_library(PTHREAD_LIB pthread)
set(GALERA_SYSTEM_LIBS ${PTHREAD_LIB})

if (${CMAKE_SYSTEM_NAME} STREQUAL "Linux")
  # Check if linkage with atomic library is needed for 8 byte atomics
  set(ATOMIC_8_TEST_C_SOURCE
  "int main()
  {
    long long s = 1;
    s = __atomic_add_fetch(&s, 1, __ATOMIC_SEQ_CST);
    return (int)__atomic_load_n(&s, __ATOMIC_SEQ_CST);
  }")
  CHECK_CXX_SOURCE_COMPILES("${ATOMIC_8_TEST_C_SOURCE}" GALERA_HAVE_ATOMIC)
  if (NOT GALERA_HAVE_ATOMIC)
    find_library(ATOMIC_LIB NAMES atomic atomic.so.1 libatomic.so.1 libatomic.dylib libatomic.1.dylib libatomic.a
                 HINTS
                   $ENV{HOME}/local/lib64
                   $ENV{HOME}/local/lib
                   /usr/local/lib64
                   /usr/local/lib
                   /opt/local/lib64
                   /opt/local/lib
                   /usr/lib64
                   /usr/lib
                   /lib64
                   /lib
                   /usr/lib/arm-linux-gnueabihf)
    message(STATUS ${ATOMIC_LIB})
    set(CMAKE_REQUIRED_LIBRARIES ${ATOMIC_LIB})
    CHECK_CXX_SOURCE_COMPILES("${ATOMIC_8_TEST_C_SOURCE}" GALERA_HAVE_ATOMIC_LIB)
    if (NOT GALERA_HAVE_ATOMIC_LIB)
      message(FATAL_ERROR "Could not find support for 64 bit atomic operations")
    endif()
    unset(CMAKE_REQUIRED_LIBRARIES)
    list(APPEND GALERA_SYSTEM_LIBS ${ATOMIC_LIB})
  endif()
endif()

message(STATUS "Galera system libs: ${GALERA_SYSTEM_LIBS}")
