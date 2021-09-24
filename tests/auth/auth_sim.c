
// uncomment to enable printf in CKB-VM
//#define CKB_C_STDLIB_PRINTF
//#include <stdio.h>

// clang-format off
#if defined(CKB_COVERAGE) || defined(CKB_RUN_IN_VM)
#define ASSERT(s) (void)0
#else
#include <assert.h>
#define ASSERT assert
#endif

#include <stdint.h>
#include <stdlib.h>

#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/md.h"

#undef CHECK
#undef CHECK2
#define RISCV_PGSIZE 4096
#include "auth.c"
// clang-format on

#define EXPONENT 65537

#define count_of(arr) (sizeof(arr) / sizeof(arr[0]))

#if defined(CKB_RUN_IN_VM)
int rand(void) { return __LINE__; }
#endif

int mbedtls_hardware_poll(void* data, unsigned char* output, size_t len,
                          size_t* olen) {
  return 0;
}

int iso97962_sign(ISO97962Encoding* enc, uint8_t* msg, int msg_len,
                  uint8_t* block, int block_len) {
  int err = 0;
  const mbedtls_md_info_t* digest = mbedtls_md_info_from_type(enc->md);
  int dig_size = digest->size;
  int t = 0;
  int delta = 0;

  if (enc->trailer == TRAILER_IMPLICIT) {
    t = 8;
    delta = block_len - dig_size - 1;
    mbedtls_md(digest, msg, msg_len, block + delta);
    block[block_len - 1] = (uint8_t)TRAILER_IMPLICIT;
  } else {
    t = 16;
    delta = block_len - dig_size - 2;
    mbedtls_md(digest, msg, msg_len, block + delta);
    block[block_len - 2] = (uint8_t)(enc->trailer >> 8);
    block[block_len - 1] = (uint8_t)enc->trailer;
  }

  uint8_t header = 0;
  int x = (dig_size + msg_len) * 8 + t + 4 - enc->key_size;

  if (x > 0) {
    int msg_rem = msg_len - ((x + 7) / 8);
    header = 0x60;
    delta -= msg_rem;
    memcpy(block + delta, msg, msg_rem);
  } else {
    header = 0x40;
    delta -= msg_len;
    memcpy(block + delta, msg, msg_len);
  }

  if ((delta - 1) > 0) {
    for (int i = delta - 1; i != 0; i--) {
      block[i] = (uint8_t)0xbb;
    }
    block[delta - 1] ^= (uint8_t)0x01;
    block[0] = (uint8_t)0x0b;
    block[0] |= header;
  } else {
    block[0] = (uint8_t)0x0a;
    block[0] |= header;
  }
  err = 0;
  return err;
}

void dump_as_carray(uint8_t* ptr, size_t size) {
  for (size_t i = 0; i < size; i++) {
    if (i == (size - 1)) {
      mbedtls_printf("0x%02X\n", ptr[i]);
    } else {
      mbedtls_printf("0x%02X,", ptr[i]);
    }
  }
}

void print_string(uint8_t* ptr, size_t size) {
  for (size_t i = 0; i < size; i++) {
    if (i == (size - 1)) {
      mbedtls_printf("%02X\n", ptr[i]);
    } else {
      mbedtls_printf("%02X", ptr[i]);
    }
  }
}

static unsigned char get_hex(unsigned char c) {
  if (c >= '0' && c <= '9')
    return c - '0';
  else if (c >= 'A' && c <= 'F')
    return c - 'A' + 10;
  else if (c >= 'a' && c <= 'f')
    return c - 'a' + 10;
  else
    return 0;
}

static int scan_hex(const char* s, unsigned char* value) {
  if (s[0] == '\0' || s[1] == '\0') return 0;

  unsigned char high_part = get_hex(s[0]);
  unsigned char low_part = get_hex(s[1]);

  *value = (high_part << 4) + low_part;
  return 1;
}

static uint32_t read_string(const char* str, uint8_t* buf, uint32_t buf_size) {
  size_t sig_len = strlen(str);
  const char* ptr = str;
  const char* end = str + sig_len;

  uint32_t i = 0;
  while (1) {
    unsigned char c = 0;
    int consumed = scan_hex(ptr, &c);
    if (consumed == 0) break;
    if (i >= buf_size) break;
    buf[i++] = (uint8_t)c;
    ptr += consumed * 2;
    if (ptr >= end) break;
  }
  return i;
}

void mbedtls_mpi_dump(const char* prefix, const mbedtls_mpi* X) {
  size_t n;
  char s[1024];
  memset(s, 0, sizeof(s));

  mbedtls_mpi_write_string(X, 16, s, sizeof(s) - 2, &n);
  mbedtls_printf("%s%s\n", prefix, s);
}

void dup_buffer(const unsigned char* src, int src_len, unsigned char* dest,
                int dup_count) {
  for (int i = 0; i < dup_count; i++) {
    for (int j = 0; j < src_len; j++) {
      dest[i * src_len + j] = src[j];
    }
  }
}

typedef struct mbedtls_test_rnd_pseudo_info {
  uint32_t key[16];
  uint32_t v0, v1;
} mbedtls_test_rnd_pseudo_info;

int mbedtls_test_rnd_pseudo_rand(void* rng_state, unsigned char* output,
                                 size_t len) {
  for (size_t i = 0; i < len; i++) {
    output[i] = (unsigned char)rand();
  }
  return 0;
}

void srand(unsigned seed);
long time(long*);

int fake_random_entropy_poll(void* data, unsigned char* output, size_t len,
                             size_t* olen) {
  *output = (unsigned char)rand();
  *olen = len;
  return 0;
}

int gen_rsa_key(uint32_t key_size, mbedtls_rsa_context* rsa, RsaInfo* info) {
  int err = 0;
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;
  const char* pers = "rsa_genkey";

  mbedtls_ctr_drbg_init(&ctr_drbg);
  mbedtls_entropy_init(&entropy);
  int padding = convert_padding(info->padding);
  // The hash_id in the RSA context is the one used for the verification.
  // md_alg in the function call is the type of hash that is verified.
  // According to RFC-3447: Public-Key Cryptography Standards (PKCS) #1 v2.1:
  // RSA Cryptography Specifications it is advised to keep both hashes the same.
  mbedtls_rsa_init(rsa, padding, info->md_type);

  err = mbedtls_entropy_add_source(&entropy, fake_random_entropy_poll, NULL, 32,
                                   MBEDTLS_ENTROPY_SOURCE_STRONG);
  CHECK(err);

  err = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                              (const unsigned char*)pers, strlen(pers));
  CHECK(err);

  err = mbedtls_rsa_gen_key(rsa, mbedtls_ctr_drbg_random, &ctr_drbg, key_size,
                            EXPONENT);
  CHECK(err);

  err = 0;

exit:
  mbedtls_ctr_drbg_free(&ctr_drbg);
  mbedtls_entropy_free(&entropy);
  return err;
}

int rsa_sign(mbedtls_rsa_context* rsa, const uint8_t* msg_buf,
             uint32_t msg_size, uint8_t* sig, RsaInfo* info) {
  int err = 0;
  mbedtls_md_type_t md_type = convert_md_type(info->md_type);
  const mbedtls_md_info_t* md_info = mbedtls_md_info_from_type(md_type);

  uint32_t hash_size = md_info->size;
  uint8_t hash_buf[hash_size];

  mbedtls_test_rnd_pseudo_info rnd_info;

  memset(&rnd_info, 0, sizeof(mbedtls_test_rnd_pseudo_info));
  ASSERT(mbedtls_rsa_check_privkey(rsa) == 0);
  err = md_string(md_info, msg_buf, msg_size, hash_buf);
  CHECK(err);

  err = mbedtls_rsa_pkcs1_sign(rsa, &mbedtls_test_rnd_pseudo_rand, &rnd_info,
                               MBEDTLS_RSA_PRIVATE, md_type, hash_size,
                               hash_buf, sig);
  CHECK(err);
  err = CKB_SUCCESS;
exit:
  return err;
}

void export_public_key(const mbedtls_rsa_context* rsa, RsaInfo* info) {
  uint32_t key_size = get_key_size(info->key_size);
  mbedtls_mpi N, E;
  mbedtls_mpi_init(&N);
  mbedtls_mpi_init(&E);
  int ret = mbedtls_rsa_export(rsa, &N, NULL, NULL, NULL, &E);
  ASSERT(ret == 0);
  mbedtls_mpi_write_binary_le(&N, info->N, key_size / 8);
  mbedtls_mpi_write_binary_le(&E, (unsigned char*)&info->E, sizeof(info->E));
}

bool g_switch_to_exec = false;
int ckb_auth_validate_stub(uint8_t auth_algorithm_id, const uint8_t* signature,
                           uint32_t signature_size, const uint8_t* message,
                           uint32_t message_size, uint8_t* pubkey_hash,
                           uint32_t pubkey_hash_size) {
  int err = 0;
  if (g_switch_to_exec) {
    CkbBinaryArgsType bin = {0};
    ckb_exec_reset(&bin);
    uint8_t code_hash[32] = {0};
    uint8_t hash_type = 0;
    err = ckb_exec_append(&bin, code_hash, sizeof(code_hash));
    CHECK(err);
    err = ckb_exec_append(&bin, &hash_type, 1);
    CHECK(err);
    err = ckb_exec_append(&bin, &auth_algorithm_id, 1);
    CHECK(err);
    err = ckb_exec_append(&bin, (uint8_t*)signature, signature_size);
    CHECK(err);
    err = ckb_exec_append(&bin, (uint8_t*)message, message_size);
    CHECK(err);
    err = ckb_exec_append(&bin, pubkey_hash, pubkey_hash_size);
    CHECK(err);

    CkbHexArgsType hex = {0};
    err = ckb_exec_encode_params(&bin, &hex);

    char* argv[2] = {hex.buff, 0};
    return simulator_main(1, argv);
  } else {
    return ckb_auth_validate(auth_algorithm_id, signature, signature_size,
                             message, message_size, pubkey_hash,
                             pubkey_hash_size);
  }

exit:
  return err;
}

int test_rsa_each(uint8_t key_size_enum, uint8_t md_type, uint8_t padding) {
  int err = 0;

  int alloc_buff_size = 1024 * 1024;
  unsigned char alloc_buff[alloc_buff_size];
  mbedtls_memory_buffer_alloc_init(alloc_buff, alloc_buff_size);

  uint32_t key_size = get_key_size(key_size_enum);
  uint8_t msg[32] = {1, 2, 3, 4};
  uint32_t sig_buff_size = calculate_rsa_info_length(key_size);
  uint8_t sig_buff[sig_buff_size];
  RsaInfo* info = (RsaInfo*)sig_buff;

  mbedtls_rsa_context rsa;

  info->algorithm_id = CKB_VERIFY_RSA;
  info->key_size = key_size_enum;
  info->padding = padding;
  info->md_type = md_type;

  err = gen_rsa_key(key_size, &rsa, info);
  CHECK(err);

  uint8_t* ptr = get_rsa_signature(info);
  err = rsa_sign(&rsa, msg, sizeof(msg), ptr, info);
  CHECK(err);

  export_public_key(&rsa, info);

  uint8_t pubkey_hash[20];
  size_t pubkey_hash_size = 20;

  get_pubkey_hash(info, pubkey_hash);
  err = ckb_auth_validate_stub(AuthAlgorithmIdRsa, sig_buff, sig_buff_size, msg,
                               sizeof(msg), pubkey_hash, pubkey_hash_size);
  CHECK(err);

  err = 0;
exit:
  return err;
}

void reset_rsa_info(RsaInfo* info) {
  info->algorithm_id = CKB_VERIFY_RSA;
  info->key_size = CKB_KEYSIZE_1024;
  info->padding = CKB_PKCS_15;
  info->md_type = CKB_MD_SHA256;
}

// cover all test cases
int test_rsa(void) {
  int err = 0;
  uint8_t md_type_set[] = {CKB_MD_SHA256};
  uint8_t key_size_set[] = {CKB_KEYSIZE_1024, CKB_KEYSIZE_2048};
  uint8_t padding_set[] = {CKB_PKCS_15, CKB_PKCS_21};
  for (int i = 0; i < count_of(key_size_set); i++) {
    for (int j = 0; j < count_of(md_type_set); j++) {
      for (int k = 0; k < count_of(padding_set); k++) {
        err = test_rsa_each(key_size_set[i], md_type_set[j], padding_set[k]);
        CHECK(err);
      }
    }
  }
  err = 0;
exit:
  if (err == 0) {
    printf("test_rsa() passed.\n");
  } else {
    printf("test_rsa() failed.\n");
  }
  return err;
}

int iso9796_2_sign(mbedtls_rsa_context* rsa, uint8_t* msg8, uint8_t* sig) {
  int err = 0;
  ISO97962Encoding enc = {0};
  iso97962_init(&enc, 128, MBEDTLS_MD_SHA1, false);

  uint8_t block[128] = {0};
  err = iso97962_sign(&enc, msg8, 8, block, sizeof(block));
  CHECK(err);

  mbedtls_test_rnd_pseudo_info rnd_info;
  memset(&rnd_info, 0, sizeof(mbedtls_test_rnd_pseudo_info));
  err = mbedtls_rsa_private(rsa, &mbedtls_test_rnd_pseudo_rand, &rnd_info,
                            block, sig);
  CHECK(err);
exit:
  return err;
}

int test_iso9796_2(void) {
  // msg to sign
  uint8_t msg[32] = {1, 2, 3, 4};
  uint32_t sig_len = sizeof(RsaInfo) + 128 * 3;
  // signature
  uint8_t sig[sig_len];

  int err = 0;

  int alloc_buff_size = 1024 * 12;
  unsigned char alloc_buff[alloc_buff_size];
  mbedtls_memory_buffer_alloc_init(alloc_buff, alloc_buff_size);

  RsaInfo* info = (RsaInfo*)sig;

  mbedtls_rsa_context rsa;

  info->algorithm_id = CKB_VERIFY_ISO9796_2_BATCH;
  info->key_size = CKB_KEYSIZE_1024;
  info->padding = CKB_PKCS_15;
  info->md_type = MBEDTLS_MD_SHA1;

  err = gen_rsa_key(1024, &rsa, info);
  CHECK(err);
  export_public_key(&rsa, info);

  for (int i = 0; i < 4; i++) {
    err = iso9796_2_sign(&rsa, msg + i * 8, sig + 8 + 128 + 128 * i);
    CHECK(err);
  }

  uint8_t pubkey_hash[20];
  get_pubkey_hash(info, pubkey_hash);

  err = ckb_auth_validate_stub(AuthAlgorithmIdIso97962, sig, sig_len, msg, 32,
                               pubkey_hash, 20);
  CHECK(err);

exit:
  if (err == 0) {
    printf("test_iso9796_2() passed.\n");
  } else {
    printf("test_iso9796_2() failed.\n");
  }
  return err;
}

int iso97962_sample_test(uint8_t key_size_enum, const char* N_str,
                         const char* E_str, const char* msg_str,
                         const char* sig_str) {
  int err = 0;

  mbedtls_mpi N;
  mbedtls_mpi E;

  uint32_t key_size_byte = 0;
  uint8_t msg[4096];
  uint32_t msg_len = 0;

  uint8_t sig[4096];
  uint32_t sig_len = 0;

  uint8_t new_msg[1024];
  size_t new_msg_len = 1024;

  int alloc_buff_size = 1024 * 1024;
  unsigned char alloc_buff[alloc_buff_size];
  mbedtls_memory_buffer_alloc_init(alloc_buff, alloc_buff_size);

  mbedtls_mpi_init(&N);
  mbedtls_mpi_init(&E);
  mbedtls_mpi_read_string(&N, 16, N_str);
  mbedtls_mpi_read_string(&E, 16, E_str);

  key_size_byte = get_key_size(key_size_enum) / 8;
  ASSERT(key_size_byte > 0);
  sig_len = read_string(sig_str, sig, sizeof(sig));
  ASSERT(sig_len == key_size_byte);
  msg_len = read_string(msg_str, msg, sizeof(msg));
  ASSERT(msg_len > 0 && msg_len < key_size_byte);

  RsaInfo info;
  info.key_size = key_size_enum;
  info.algorithm_id = CKB_VERIFY_ISO9796_2;
  info.md_type = CKB_MD_SHA1;
  mbedtls_mpi_write_binary_le(&N, (uint8_t*)info.N, key_size_byte);
  mbedtls_mpi_write_binary_le(&E, (uint8_t*)&info.E, sizeof(info.E));

  ASSERT(sig_len == key_size_byte);
  memcpy(info.sig, sig, sig_len);

  err = validate_signature(NULL, (uint8_t*)&info, sizeof(info), msg, msg_len,
                           new_msg, &new_msg_len);
  CHECK(err);

  err = 0;
exit:
  return err;
}

uint8_t SECP256k1_SECKEY[32] = {1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11,
                                12, 13, 14, 15, 16, 1,  2,  3,  4,  5,  6,
                                7,  8,  9,  10, 11, 12, 13, 14, 15, 16};
uint8_t SECP256k1_SECKEY2[32] = {2,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11,
                                 12, 13, 14, 15, 16, 1,  2,  3,  4,  5,  6,
                                 7,  8,  9,  10, 11, 12, 13, 14, 15, 16};
uint8_t SECP256k1_SECKEY3[32] = {3,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11,
                                 12, 13, 14, 15, 16, 1,  2,  3,  4,  5,  6,
                                 7,  8,  9,  10, 11, 12, 13, 14, 15, 16};

int secp256k1_sign(const uint8_t* key32, const uint8_t* msg32, uint8_t* raw_sig,
                   int* recid, secp256k1_pubkey* pubkey) {
  int ret = 0;
  int err = 0;

  secp256k1_ecdsa_recoverable_signature sig;

  secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN |
                                                    SECP256K1_CONTEXT_VERIFY);
  ret = secp256k1_ecdsa_sign_recoverable(ctx, &sig, msg32, key32, NULL, NULL);
  CHECK2(ret, -1);

  ret = secp256k1_ecdsa_recoverable_signature_serialize_compact(ctx, raw_sig,
                                                                recid, &sig);
  CHECK2(ret, -1);
  ret = secp256k1_ec_pubkey_create(ctx, pubkey, key32);
  CHECK2(ret, -1);

exit:
  return err;
}

int sign_ckb_msg(uint8_t* sec_key, uint8_t* msg32, uint8_t* sig,
                 uint8_t* pubkey_hash) {
  int err = 0;

  int recid;
  secp256k1_pubkey pubkey;
  err = secp256k1_sign(SECP256k1_SECKEY, msg32, sig, &recid, &pubkey);
  CHECK(err);

  // prepare signature
  sig[64] = (uint8_t)recid;
  secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN |
                                                    SECP256K1_CONTEXT_VERIFY);
  // prepare pubkey hash
  uint8_t serialized_pubkey[33];
  size_t serialized_pubkey_len = 33;
  secp256k1_ec_pubkey_serialize(ctx, serialized_pubkey, &serialized_pubkey_len,
                                &pubkey, SECP256K1_EC_COMPRESSED);

  uint8_t temp[32];
  blake2b_state blake2b_ctx;
  blake2b_init(&blake2b_ctx, 32);
  blake2b_update(&blake2b_ctx, serialized_pubkey, serialized_pubkey_len);
  blake2b_final(&blake2b_ctx, temp, 32);

  memcpy(pubkey_hash, temp, 20);

exit:
  return err;
}

int test_ckb(void) {
  int err = 0;
  uint8_t msg[32] = {1, 2, 3, 4};

  uint8_t new_msg[32];
  convert_copy(msg, sizeof(msg), new_msg, 32);

  uint8_t sig[65];
  uint8_t pubkey_hash[20];
  err = sign_ckb_msg(SECP256k1_SECKEY, new_msg, sig, pubkey_hash);
  CHECK(err);
  err = ckb_auth_validate_stub(AuthAlgorithmIdCkb, sig, 65, new_msg, 32,
                               pubkey_hash, 20);
  CHECK(err);

exit:
  if (err == 0) {
    printf("test_ckb() passed.\n");
  } else {
    printf("test_ckb() failed.\n");
  }
  return err;
}

int test_ckb_multisig(void) {
  int err = 0;
  uint8_t msg[32] = {1, 2, 3, 4};

  uint8_t new_msg[32];
  convert_copy(msg, sizeof(msg), new_msg, 32);

  uint8_t sig[65];
  uint8_t pubkey_hash[20];
  err = sign_ckb_msg(SECP256k1_SECKEY, new_msg, sig, pubkey_hash);
  CHECK(err);

  uint8_t sig2[65];
  uint8_t pubkey_hash2[20];
  err = sign_ckb_msg(SECP256k1_SECKEY2, new_msg, sig2, pubkey_hash2);
  CHECK(err);

  uint8_t sig3[65];
  uint8_t pubkey_hash3[20];
  err = sign_ckb_msg(SECP256k1_SECKEY3, new_msg, sig3, pubkey_hash3);
  CHECK(err);

  // multisig_script | Signature1 | Signature2 | ...
  // multisig_script: S | R | M | N | PubKeyHash1 | PubKeyHash2 | ...
  uint8_t final_signature[4 + 20 * 3 + 65 * 3];
  final_signature[0] = 0;
  final_signature[1] = 0;
  final_signature[2] = 3;
  final_signature[3] = 3;

  memcpy(final_signature + 4, pubkey_hash, 20);
  memcpy(final_signature + 4 + 20, pubkey_hash2, 20);
  memcpy(final_signature + 4 + 20 + 20, pubkey_hash3, 20);

  memcpy(final_signature + 64, sig, 65);
  memcpy(final_signature + 64 + 65, sig, 65);
  memcpy(final_signature + 64 + 65 + 65, sig, 65);

  uint8_t hash[32] = {0};
  blake2b_state ctx;
  blake2b_init(&ctx, BLAKE2B_BLOCK_SIZE);
  blake2b_update(&ctx, final_signature, 4 + 20 * 3);
  blake2b_final(&ctx, hash, BLAKE2B_BLOCK_SIZE);

  err = ckb_auth_validate_stub(AuthAlgorithmIdCkbMultisig, final_signature,
                               sizeof(final_signature), new_msg, 32, hash, 20);
  CHECK(err);

exit:
  if (err == 0) {
    printf("test_ckb_multisig() passed.\n");
  } else {
    printf("test_ckb_multisig() failed: %d\n", err);
  }
  return err;
}

static unsigned char g_alloc_buff[1024];

int test_eth_series(uint8_t auth_algo_id) {
  int err = 0;
  uint8_t msg[32] = {1, 2, 3, 4};

  uint8_t new_msg[32];

  // for md_string
  mbedtls_memory_buffer_alloc_init(g_alloc_buff, sizeof(g_alloc_buff));

  if (auth_algo_id == AuthAlgorithmIdEthereum) {
    convert_eth_message(msg, sizeof(msg), new_msg, 32);
  } else if (auth_algo_id == AuthAlgorithmIdEos) {
    convert_eos_message(msg, sizeof(msg), new_msg, 32);
  } else if (auth_algo_id == AuthAlgorithmIdTron) {
    convert_tron_message(msg, sizeof(msg), new_msg, 32);
  } else {
    return -2;
  }
  uint8_t raw_sig[65];
  int recid;
  secp256k1_pubkey pubkey;
  err = secp256k1_sign(SECP256k1_SECKEY, new_msg, raw_sig, &recid, &pubkey);
  CHECK(err);

  // prepare signature
  raw_sig[64] = (uint8_t)recid;
  secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN |
                                                    SECP256K1_CONTEXT_VERIFY);
  // prepare pubkey hash
  uint8_t serialized_pubkey[65];
  size_t serialized_pubkey_len = 65;
  err = secp256k1_ec_pubkey_serialize(ctx, serialized_pubkey,
                                      &serialized_pubkey_len, &pubkey,
                                      SECP256K1_EC_UNCOMPRESSED);

  uint8_t pubkey_hash[32];

  SHA3_CTX hash_ctx;
  keccak_init(&hash_ctx);
  keccak_update(&hash_ctx, serialized_pubkey + 1, serialized_pubkey_len - 1);
  keccak_final(&hash_ctx, pubkey_hash);

  uint8_t blake160[20];
  memcpy(blake160, pubkey_hash + 12, 20);

  err =
      ckb_auth_validate_stub(auth_algo_id, raw_sig, 65, msg, 32, blake160, 20);
  CHECK(err);

exit:
  if (err == 0) {
    printf("test_eth_series(%d) passed.\n", auth_algo_id);
  } else {
    printf("test_eth_series(%d) failed.\n", auth_algo_id);
  }
  return err;
}

static unsigned char g_alloc_buff[1024];

int test_btc_series(uint8_t auth_algo_id, bool compressed) {
  int err = 0;
  uint8_t msg[32] = {1, 2, 3, 4};

  uint8_t new_msg[32];

  // for md_string
  mbedtls_memory_buffer_alloc_init(g_alloc_buff, sizeof(g_alloc_buff));

  if (auth_algo_id == AuthAlgorithmIdBitcoin) {
    convert_btc_message(msg, sizeof(msg), new_msg, 32);
  } else if (auth_algo_id == AuthAlgorithmIdDogecoin) {
    convert_doge_message(msg, sizeof(msg), new_msg, 32);
  } else {
    return -2;
  }
  uint8_t raw_sig[65];
  int recid;
  secp256k1_pubkey pubkey;
  err = secp256k1_sign(SECP256k1_SECKEY, new_msg, raw_sig + 1, &recid, &pubkey);
  CHECK(err);

  // prepare signature
  raw_sig[0] = (uint8_t)((recid & 3) + (compressed ? 4 : 0) + 27);
  secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN |
                                                    SECP256K1_CONTEXT_VERIFY);
  // prepare pubkey hash
  uint8_t serialized_pubkey[65];
  size_t serialized_pubkey_len = 65;
  err = secp256k1_ec_pubkey_serialize(
      ctx, serialized_pubkey, &serialized_pubkey_len, &pubkey,
      compressed ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED);

  uint8_t pubkey_hash[32];

  const mbedtls_md_info_t* md_info =
      mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  err =
      md_string(md_info, serialized_pubkey, serialized_pubkey_len, pubkey_hash);
  CHECK(err);

  md_info = mbedtls_md_info_from_type(MBEDTLS_MD_RIPEMD160);
  err = md_string(md_info, pubkey_hash, SHA256_SIZE, pubkey_hash);
  CHECK(err);

  uint8_t blake160[20];
  memcpy(blake160, pubkey_hash, 20);

  err =
      ckb_auth_validate_stub(auth_algo_id, raw_sig, 65, msg, 32, blake160, 20);
  CHECK(err);

exit:
  if (err == 0) {
    printf("test_btc_series(%d, compressed = %d) passed.\n", auth_algo_id,
           compressed);
  } else {
    printf("test_btc_series(%d, compressed = %d) failed.\n", auth_algo_id,
           compressed);
  }
  return err;
}

int entry(void) {
  int err = 0;

  err = test_ckb();
  CHECK(err);

  err = test_ckb_multisig();
  CHECK(err);

  err = test_eth_series(AuthAlgorithmIdEthereum);
  CHECK(err);

  err = test_eth_series(AuthAlgorithmIdEos);
  CHECK(err);

  err = test_eth_series(AuthAlgorithmIdTron);
  CHECK(err);

  err = test_btc_series(AuthAlgorithmIdBitcoin, true);
  CHECK(err);

  err = test_btc_series(AuthAlgorithmIdBitcoin, false);
  CHECK(err);

  err = test_btc_series(AuthAlgorithmIdDogecoin, true);
  CHECK(err);

  err = test_btc_series(AuthAlgorithmIdDogecoin, false);
  CHECK(err);

  err = test_rsa();
  CHECK(err);

  err = test_iso9796_2();
  CHECK(err);
exit:
  return err;
}

int main(int argc, const char* argv[]) {
  int err = 0;

  err = entry();
  CHECK(err);

  g_switch_to_exec = true;
  err = entry();
  CHECK(err);

exit:
  return err;
}
