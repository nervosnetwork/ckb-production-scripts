cmake_minimum_required(VERSION 3.12)
project(cardano_lock_simulator C)

set(CMAKE_C_STANDARD 11)
# uncomment it for sanitize
#set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=address -fsanitize=undefined")

# uncomment it for coverage test
#set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} --coverage")
#add_definitions(-DCKB_COVERAGE)
#add_definitions(-Wno-incompatible-pointer-types)

#add_definitions(-DCKB_SIMULATOR)
#add_definitions(-DCKB_DECLARATION_ONLY)
add_definitions(-DCKB_USE_SIM)

include_directories(../../tests/cardano_lock)
include_directories(../../deps/ckb-c-stdlib-20210713)
include_directories(../../c/nanocbor)
include_directories(../../deps/ed25519/src)
# include_directories(deps/ckb-c-stdlib/libc)
# on simulator, we don't use own "libc"
include_directories(../../deps/ckb-c-stdlib-20210713/molecule)
include_directories(../../c)
include_directories(../../build)

add_executable(cardano_lock_simulator ../../tests/cardano_lock/cardano_lock_sim.c
    ../../c/nanocbor/decoder.c ../../c/nanocbor/encoder.c
    ../../deps/ed25519/src/add_scalar.c
    ../../deps/ed25519/src/fe.c
    ../../deps/ed25519/src/ge.c
    ../../deps/ed25519/src/ge.h
    ../../deps/ed25519/src/key_exchange.c
    ../../deps/ed25519/src/keypair.c
    ../../deps/ed25519/src/sc.c
    ../../deps/ed25519/src/seed.c
    ../../deps/ed25519/src/sha512.c
    ../../deps/ed25519/src/sign.c
    ../../deps/ed25519/src/verify.c
    )

target_compile_definitions(cardano_lock_simulator PUBLIC -DCKB_DECLARATION_ONLY)
