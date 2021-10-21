cmake_minimum_required(VERSION 3.10)
SET(CMAKE_C_STANDARD 11)

project(cudt_simulator C)

set(CUDT_LOCK_DIR ${PROJECT_SOURCE_DIR}/../..)
set(CUDT_LOCK_C_DIR ${PROJECT_SOURCE_DIR}/../../c)
set(CUDT_LOCK_DEPS ${CUDT_LOCK_DIR}/deps)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall")

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Werror")

add_definitions(-DCKB_SIMULATOR)
add_definitions(-D__SHARED_LIBRARY__)
add_definitions(-DCKB_DECLARATION_ONLY)
add_definitions(-DCKB_USE_SIM)
#add_definitions(-DCKB_STDLIB_NO_SYSCALL_IMPL)

if (${CMAKE_BUILD_TYPE}_ STREQUAL "Debug_")
    add_definitions(-DDEBUG_CKB)
endif()

set(CMAKE_INCLUDE_DIRECTORIES_BEFORE ON)

include_directories(before ${PROJECT_SOURCE_DIR})
include_directories(before ${CUDT_LOCK_DIR}/deps/ckb-c-stdlib-20210713)
include_directories(before ${CUDT_LOCK_DIR}/deps/ckb-c-stdlib-20210713/simulator)
include_directories(before ${CUDT_LOCK_DIR}/deps/ckb-c-stdlib-20210713/molecule)
include_directories(before ${CUDT_LOCK_DEPS}/sparse-merkle-tree/c)

add_executable(cudt_simulator
    ${PROJECT_SOURCE_DIR}/test_compact_udt_lock.c
    ${PROJECT_SOURCE_DIR}/util/ckb_syscall_cudt_sim.c
    ${PROJECT_SOURCE_DIR}/util/util.c
)
