
set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)

project(cudt_simulator CXX C)

set(CUDT_LOCK_DIR ${PROJECT_SOURCE_DIR}/../..)
set(CUDT_LOCK_C_DIR ${PROJECT_SOURCE_DIR}/../../c)
set(CUDT_LOCK_DEPS ${CUDT_LOCK_DIR}/deps)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if (${CMAKE_BUILD_TYPE}_ STREQUAL "Debug_")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Werror")
endif(S)

if (${EnableSanitize}_ STREQUAL "Enable_" )
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=address -fsanitize=undefined")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=address -fsanitize=undefined")
endif()

if (${EnableCoverage}_ STREQUAL "Enable_" )
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} --coverage")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} --coverage")
endif()

add_definitions(-DCKB_SIMULATOR)
add_definitions(-D__SHARED_LIBRARY__)
add_definitions(-DCKB_DECLARATION_ONLY)
add_definitions(-DCKB_USE_SIM)
#add_definitions(-DCKB_STDLIB_NO_SYSCALL_IMPL)

if (${CMAKE_BUILD_TYPE}_ STREQUAL "Debug_")
    add_definitions(-DDEBUG_CKB)
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O0")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O0")
endif()
add_definitions(-DHAVE_CONFIG_H=1)
add_definitions(-DCOMPACT_UDT_UNITTEST_SRC_PATH="\\"${PROJECT_SOURCE_DIR}"\\")

set(CMAKE_INCLUDE_DIRECTORIES_BEFORE ON)

include_directories(before ${PROJECT_SOURCE_DIR})
include_directories(before ${PROJECT_SOURCE_DIR}/simulator/)
include_directories(before ${CUDT_LOCK_C_DIR}/)
include_directories(before ${CUDT_LOCK_DIR}/build/)
include_directories(before ${CUDT_LOCK_DIR}/deps/ckb-c-stdlib-20210713)
include_directories(before ${CUDT_LOCK_DIR}/deps/ckb-c-stdlib-20210713/simulator)
include_directories(before ${CUDT_LOCK_DIR}/deps/ckb-c-stdlib-20210713/molecule)
include_directories(before ${CUDT_LOCK_DEPS}/sparse-merkle-tree/c)
include_directories(before ${CUDT_LOCK_DEPS}/secp256k1/)
include_directories(before ${CUDT_LOCK_DEPS}/secp256k1/include/)
include_directories(before ${CUDT_LOCK_DEPS}/secp256k1/src/)
include_directories(before ${CUDT_LOCK_DEPS}/mbedtls/include/)

add_library(mbedtls
    ../../deps/mbedtls/library/aes.c
    ../../deps/mbedtls/library/aesni.c
    ../../deps/mbedtls/library/arc4.c
    ../../deps/mbedtls/library/aria.c
    ../../deps/mbedtls/library/asn1parse.c
    ../../deps/mbedtls/library/asn1write.c
    ../../deps/mbedtls/library/base64.c
    ../../deps/mbedtls/library/bignum.c
    ../../deps/mbedtls/library/blowfish.c
    ../../deps/mbedtls/library/camellia.c
    ../../deps/mbedtls/library/ccm.c
    ../../deps/mbedtls/library/chacha20.c
    ../../deps/mbedtls/library/chachapoly.c
    ../../deps/mbedtls/library/cipher.c
    ../../deps/mbedtls/library/cipher_wrap.c
    ../../deps/mbedtls/library/cmac.c
    ../../deps/mbedtls/library/ctr_drbg.c
    ../../deps/mbedtls/library/des.c
    ../../deps/mbedtls/library/dhm.c
    ../../deps/mbedtls/library/ecdh.c
    ../../deps/mbedtls/library/ecdsa.c
    ../../deps/mbedtls/library/ecjpake.c
    ../../deps/mbedtls/library/ecp.c
    ../../deps/mbedtls/library/ecp_curves.c
    ../../deps/mbedtls/library/entropy.c
    ../../deps/mbedtls/library/entropy_poll.c
    ../../deps/mbedtls/library/error.c
    ../../deps/mbedtls/library/gcm.c
    ../../deps/mbedtls/library/havege.c
    ../../deps/mbedtls/library/hkdf.c
    ../../deps/mbedtls/library/hmac_drbg.c
    ../../deps/mbedtls/library/md.c
    ../../deps/mbedtls/library/md2.c
    ../../deps/mbedtls/library/md4.c
    ../../deps/mbedtls/library/md5.c
    ../../deps/mbedtls/library/memory_buffer_alloc.c
    ../../deps/mbedtls/library/nist_kw.c
    ../../deps/mbedtls/library/oid.c
    ../../deps/mbedtls/library/padlock.c
    ../../deps/mbedtls/library/pem.c
    ../../deps/mbedtls/library/pk.c
    ../../deps/mbedtls/library/pk_wrap.c
    ../../deps/mbedtls/library/pkcs12.c
    ../../deps/mbedtls/library/pkcs5.c
    ../../deps/mbedtls/library/pkparse.c
    ../../deps/mbedtls/library/pkwrite.c
    ../../deps/mbedtls/library/platform.c
    ../../deps/mbedtls/library/platform_util.c
    ../../deps/mbedtls/library/poly1305.c
    ../../deps/mbedtls/library/psa_crypto.c
    ../../deps/mbedtls/library/psa_crypto_se.c
    ../../deps/mbedtls/library/psa_crypto_slot_management.c
    ../../deps/mbedtls/library/psa_crypto_storage.c
    ../../deps/mbedtls/library/psa_its_file.c
    ../../deps/mbedtls/library/ripemd160.c
    ../../deps/mbedtls/library/rsa.c
    ../../deps/mbedtls/library/rsa_internal.c
    ../../deps/mbedtls/library/sha1.c
    ../../deps/mbedtls/library/sha256.c
    ../../deps/mbedtls/library/sha512.c
    ../../deps/mbedtls/library/threading.c
    ../../deps/mbedtls/library/timing.c
    ../../deps/mbedtls/library/version.c
    ../../deps/mbedtls/library/version_features.c
    ../../deps/mbedtls/library/xtea.c)

add_executable(cudt_simulator
    ${PROJECT_SOURCE_DIR}/test_compact_udt_lock.cpp
    ${PROJECT_SOURCE_DIR}/compact_udt_virtual_data.cpp
	
	${PROJECT_SOURCE_DIR}/simulator/ckb_syscall_auth_sim.c
	${PROJECT_SOURCE_DIR}/simulator/ckb_syscall_cudt_sim.c
	${PROJECT_SOURCE_DIR}/simulator/compact_udt_lock_inc.c
	${PROJECT_SOURCE_DIR}/simulator/compact_udt_cc.cpp
	${PROJECT_SOURCE_DIR}/simulator/dump_data.cpp
	
	${PROJECT_SOURCE_DIR}/util/util.cpp
)
target_link_libraries(cudt_simulator mbedtls)

if (${EnableSanitize}_ STREQUAL "Enable_")
    target_link_libraries(cudt_simulator PRIVATE -fsanitize=address -fsanitize=undefined)
endif()

if (${EnableCoverage}_ STREQUAL "Enable_")
	target_link_libraries(cudt_simulator PRIVATE -fprofile-arcs -ftest-coverage)
endif()