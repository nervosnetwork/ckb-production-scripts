cmake_minimum_required(VERSION 3.12)
project(ckb_production_scripts_simulator C)

set(CMAKE_C_STANDARD 11)
# uncomment it for sanitize
#set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=address -fsanitize=undefined")

# uncomment it for coverage test
#set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} --coverage")
#add_definitions(-DCKB_COVERAGE)
add_definitions(-DCKB_SIMULATOR)
add_definitions(-D__SHARED_LIBRARY__)
add_definitions(-DCKB_DECLARATION_ONLY)
add_definitions(-DCKB_USE_SIM)

include_directories(tests/validate_signature_rsa)
include_directories(deps/ckb-c-stdlib-simulator-only/simulator)
include_directories(deps/ckb-c-stdlib-simulator-only)
# include_directories(deps/ckb-c-stdlib/libc)
# on simulator, we don't use own "libc"
include_directories(deps)
include_directories(deps/ckb-c-stdlib-simulator-only/molecule)
include_directories(c)
include_directories(build)
include_directories(deps/secp256k1/src)
include_directories(deps/secp256k1)
include_directories(deps/mbedtls)
include_directories(deps/mbedtls/include)

add_library(mbedtls
    deps/mbedtls/library/aes.c
    deps/mbedtls/library/aesni.c
    deps/mbedtls/library/arc4.c
    deps/mbedtls/library/aria.c
    deps/mbedtls/library/asn1parse.c
    deps/mbedtls/library/asn1write.c
    deps/mbedtls/library/base64.c
    deps/mbedtls/library/bignum.c
    deps/mbedtls/library/blowfish.c
    deps/mbedtls/library/camellia.c
    deps/mbedtls/library/ccm.c
    deps/mbedtls/library/chacha20.c
    deps/mbedtls/library/chachapoly.c
    deps/mbedtls/library/cipher.c
    deps/mbedtls/library/cipher_wrap.c
    deps/mbedtls/library/cmac.c
    deps/mbedtls/library/ctr_drbg.c
    deps/mbedtls/library/des.c
    deps/mbedtls/library/dhm.c
    deps/mbedtls/library/ecdh.c
    deps/mbedtls/library/ecdsa.c
    deps/mbedtls/library/ecjpake.c
    deps/mbedtls/library/ecp.c
    deps/mbedtls/library/ecp_curves.c
    deps/mbedtls/library/entropy.c
    deps/mbedtls/library/entropy_poll.c
    deps/mbedtls/library/error.c
    deps/mbedtls/library/gcm.c
    deps/mbedtls/library/havege.c
    deps/mbedtls/library/hkdf.c
    deps/mbedtls/library/hmac_drbg.c
    deps/mbedtls/library/md.c
    deps/mbedtls/library/md2.c
    deps/mbedtls/library/md4.c
    deps/mbedtls/library/md5.c
    deps/mbedtls/library/memory_buffer_alloc.c
    deps/mbedtls/library/nist_kw.c
    deps/mbedtls/library/oid.c
    deps/mbedtls/library/padlock.c
    deps/mbedtls/library/pem.c
    deps/mbedtls/library/pk.c
    deps/mbedtls/library/pk_wrap.c
    deps/mbedtls/library/pkcs12.c
    deps/mbedtls/library/pkcs5.c
    deps/mbedtls/library/pkparse.c
    deps/mbedtls/library/pkwrite.c
    deps/mbedtls/library/platform.c
    deps/mbedtls/library/platform_util.c
    deps/mbedtls/library/poly1305.c
    deps/mbedtls/library/psa_crypto.c
    deps/mbedtls/library/psa_crypto_se.c
    deps/mbedtls/library/psa_crypto_slot_management.c
    deps/mbedtls/library/psa_crypto_storage.c
    deps/mbedtls/library/psa_its_file.c
    deps/mbedtls/library/ripemd160.c
    deps/mbedtls/library/rsa.c
    deps/mbedtls/library/rsa_internal.c
    deps/mbedtls/library/sha1.c
    deps/mbedtls/library/sha256.c
    deps/mbedtls/library/sha512.c
    deps/mbedtls/library/threading.c
    deps/mbedtls/library/timing.c
    deps/mbedtls/library/version.c
    deps/mbedtls/library/version_features.c
    deps/mbedtls/library/xtea.c)

add_executable(validate_signature_rsa tests/validate_signature_rsa/validate_signature_rsa_sim.c c/validate_signature_rsa.h)
target_compile_definitions(validate_signature_rsa PUBLIC -D_FILE_OFFSET_BITS=64 -DCKB_DECLARATION_ONLY)
target_include_directories(validate_signature_rsa PUBLIC deps/ckb-c-stdlib-simulator-only/libc)
target_link_libraries(validate_signature_rsa mbedtls)


add_executable(dlopen_sim tests/validate_signature_rsa/dlopen_sim.c)
target_compile_definitions(dlopen_sim PUBLIC -D_FILE_OFFSET_BITS=64 -DCKB_DECLARATION_ONLY)
#target_include_directories(dlopen_sim PUBLIC deps/ckb-c-stdlib-simulator-only/libc)
