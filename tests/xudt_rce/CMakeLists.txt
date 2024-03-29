cmake_minimum_required(VERSION 3.12)
project(xudt_rce_simulator C)

set(CMAKE_C_STANDARD 11)
# uncomment it for sanitize
#set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=address -fsanitize=undefined")

# uncomment it for coverage test
#set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} --coverage")
#add_definitions(-DCKB_COVERAGE)
#add_definitions(-Wno-incompatible-pointer-types)

#add_definitions(-DCKB_SIMULATOR)
add_definitions(-D__SHARED_LIBRARY__)
add_definitions(-DCKB_DECLARATION_ONLY)
add_definitions(-DCKB_USE_SIM)

include_directories(../../tests/xudt_rce)
include_directories(../../deps/ckb-c-stdlib-20210713)
# include_directories(deps/ckb-c-stdlib/libc)
# on simulator, we don't use own "libc"
include_directories(../../deps)
include_directories(../../deps/ckb-c-stdlib-20210713/molecule)
include_directories(../../c)
include_directories(../../build)
include_directories(../../deps/sparse-merkle-tree/c)


add_executable(xudt_rce_simulator ../../tests/xudt_rce/xudt_rce_sim.c)
target_compile_definitions(xudt_rce_simulator PUBLIC -D_FILE_OFFSET_BITS=64 -DCKB_DECLARATION_ONLY)
target_include_directories(xudt_rce_simulator PUBLIC deps/ckb-c-stdlib-20210713/libc)
target_link_libraries(xudt_rce_simulator dl)

add_executable(xudt_rce_validator_simulator ../../tests/xudt_rce/xudt_rce_validator_sim.c)
target_compile_definitions(xudt_rce_validator_simulator PUBLIC -D_FILE_OFFSET_BITS=64 -DCKB_DECLARATION_ONLY -DCKB_TYPE_ID_DECLARATION_ONLY)
target_include_directories(xudt_rce_validator_simulator PUBLIC deps/ckb-c-stdlib-20210713/libc)
target_link_libraries(xudt_rce_validator_simulator dl)

add_library(extension_script_0 SHARED ../../tests/xudt_rce/extension_script_0.c)
add_library(extension_script_1 SHARED ../../tests/xudt_rce/extension_script_1.c)


add_executable(smt_coverage smt_fuzzer/smt_coverage.c smt_fuzzer/smt_fuzzer.c)
