
set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)

project(cudt_simulator CXX C)

set(CUDT_LOCK_DIR ${PROJECT_SOURCE_DIR}/../..)
set(CUDT_LOCK_C_DIR ${PROJECT_SOURCE_DIR}/../../c)
set(CUDT_LOCK_DEPS ${CUDT_LOCK_DIR}/deps)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
message(${CUDT_LOCK_C_DIR})

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
    ${PROJECT_SOURCE_DIR}/test_compact_udt_lock.cpp
    ${PROJECT_SOURCE_DIR}/compact_udt_virtual_data.cpp
	
	${PROJECT_SOURCE_DIR}/simulator/ckb_syscall_cudt_sim.c
	${PROJECT_SOURCE_DIR}/simulator/compact_udt_lock_inc.c
	${PROJECT_SOURCE_DIR}/simulator/compact_udt_cc.cpp
	
	${PROJECT_SOURCE_DIR}/util/util.cpp
)
#target_link_libraries(cudt_simulator PRIVATE -fsanitize=address -fsanitize=undefined)
