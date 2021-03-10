
// uncomment to enable printf in CKB-VM
//#define CKB_C_STDLIB_PRINTF
//#include <stdio.h>

#if defined(CKB_COVERAGE) || defined(CKB_RUN_IN_VM)
#define ASSERT(s) (void)0
#else
#include <assert.h>
#define ASSERT assert
#endif

#include <stdlib.h>

#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/md.h"
#include "validate_signature_rsa.c"

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

int rsa_verify(mbedtls_rsa_context* rsa, const uint8_t* msg_buf,
               uint32_t msg_size, const uint8_t* sig) {
  int err = 0;
  uint8_t hash_buf[32] = {0};
  uint32_t hash_size = 32;

  ASSERT(mbedtls_rsa_check_pubkey(rsa) == 0);
  err = md_string(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), msg_buf,
                  msg_size, hash_buf);
  CHECK(err);
  err = mbedtls_rsa_pkcs1_verify(rsa, NULL, NULL, MBEDTLS_RSA_PUBLIC,
                                 MBEDTLS_MD_SHA256, hash_size, hash_buf, sig);
  CHECK(err);

  err = 0;
exit:
  return err;
}

int rsa_random(void) {
  int err = 0;

  int alloc_buff_size = 1024 * 1024;
  unsigned char alloc_buff[alloc_buff_size];
  mbedtls_memory_buffer_alloc_init(alloc_buff, alloc_buff_size);

  uint32_t key_size = 1024;
  uint32_t byte_size = key_size / 8;

  uint8_t msg[32] = {1, 2, 3, 4};
  uint8_t sig[byte_size];
  mbedtls_rsa_context rsa;
  RsaInfo info = {0};
  info.algorithm_id = CKB_VERIFY_RSA;
  info.key_size = CKB_KEYSIZE_1024;
  info.padding = CKB_PKCS_15;
  info.md_type = CKB_MD_SHA256;

  err = gen_rsa_key(key_size, &rsa, &info);
  CHECK(err);

  err = rsa_sign(&rsa, msg, sizeof(msg), sig, &info);
  CHECK(err);

  err = rsa_verify(&rsa, msg, sizeof(msg), sig);
  CHECK(err);

  err = 0;
exit:
  if (err == CKB_SUCCESS) {
    mbedtls_printf("rsa_random() passed.\n");
  } else {
    mbedtls_printf("rsa_random() failed.\n");
  }
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

int test_validate_signature(uint8_t key_size_enum, uint8_t md_type,
                            uint8_t padding) {
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

  uint8_t output[20];
  size_t output_len = 20;

#if 0
  printf("sig = ");
  print_string(sig_buff, sig_buff_size);
  printf("msg = ");
  print_string(msg, sizeof(msg));
#endif
  err = validate_signature(NULL, sig_buff, sig_buff_size, msg, sizeof(msg),
                           output, &output_len);
  CHECK(err);

  err = 0;
exit:
  if (err == 0) {
    mbedtls_printf(
        "test_validate_signature() passed: key size = %d, md_type = %d, "
        "padding = "
        "%d\n",
        key_size, md_type, padding);
  } else {
    mbedtls_printf(
        "test_validate_signature() failed: key size = %d, md_type = %d, "
        "padding = "
        "%d\n",
        key_size, md_type, padding);
  }
  return err;
}

void reset_rsa_info(RsaInfo* info) {
  info->algorithm_id = CKB_VERIFY_RSA;
  info->key_size = CKB_KEYSIZE_1024;
  info->padding = CKB_PKCS_15;
  info->md_type = CKB_MD_SHA256;
}

int validate_signature_error_cases_test(void) {
  int err = 0;

  uint8_t padding = CKB_PKCS_15;
  uint8_t key_size_enum = CKB_KEYSIZE_1024;
  uint8_t md_type = CKB_MD_SHA256;
  uint32_t key_size = get_key_size(key_size_enum);
  uint8_t msg[32] = {1, 2, 3, 4};
  uint32_t sig_buff_size = calculate_rsa_info_length(key_size);
  uint8_t sig_buff[sig_buff_size];
  RsaInfo* info = (RsaInfo*)sig_buff;
  info->algorithm_id = CKB_VERIFY_RSA;
  info->key_size = key_size_enum;
  info->padding = padding;
  info->md_type = md_type;

  size_t len = 0;
  load_prefilled_data(NULL, &len);
  mbedtls_hardware_poll(0, 0, 0, 0);

  reset_rsa_info(info);
  err = validate_signature(NULL, sig_buff, sig_buff_size, msg, sizeof(msg),
                           NULL, NULL);
  CHECK2(err == ERROR_RSA_VERIFY_FAILED, -1);

  reset_rsa_info(info);
  info->algorithm_id = 100;
  err = validate_signature(NULL, sig_buff, sig_buff_size, msg, sizeof(msg),
                           NULL, NULL);
  CHECK2(err == ERROR_RSA_INVALID_ID, -1);

  reset_rsa_info(info);
  err = validate_signature(NULL, NULL, sig_buff_size, msg, sizeof(msg), NULL,
                           NULL);
  CHECK2(err == ERROR_RSA_INVALID_PARAM1, -1);

  reset_rsa_info(info);
  info->md_type = 100;
  err = validate_signature(NULL, sig_buff, sig_buff_size, msg, sizeof(msg),
                           NULL, NULL);
  CHECK2(err == ERROR_INVALID_MD_TYPE, -1);

  reset_rsa_info(info);
  info->padding = 100;
  err = validate_signature(NULL, sig_buff, sig_buff_size, msg, sizeof(msg),
                           NULL, NULL);
  CHECK2(err == ERROR_INVALID_PADDING, -1);

  reset_rsa_info(info);
  info->key_size = 100;
  err = validate_signature(NULL, sig_buff, sig_buff_size, msg, sizeof(msg),
                           NULL, NULL);
  CHECK2(err == ERROR_RSA_INVALID_KEY_SIZE, -1);

  reset_rsa_info(info);
  err = validate_signature(NULL, NULL, sig_buff_size, msg, sizeof(msg), NULL,
                           NULL);
  CHECK2(err == ERROR_RSA_INVALID_PARAM1, -1);

  reset_rsa_info(info);
  err = validate_signature(NULL, sig_buff, sig_buff_size, NULL, sizeof(msg),
                           NULL, NULL);
  CHECK2(err == ERROR_RSA_INVALID_PARAM1, -1);

  reset_rsa_info(info);
  err = validate_signature(NULL, sig_buff, 0, msg, sizeof(msg), NULL, NULL);
  CHECK2(err == ERROR_RSA_INVALID_PARAM2, -1);

  err = 0;
exit:
  if (err == 0) {
    mbedtls_printf("validate_signature_error_cases_test() passed.\n");
  } else {
    mbedtls_printf("validate_signature_error_cases_test() failed.\n");
  }
  return err;
}

// cover all test cases
int validate_signature_all_test(void) {
  int err = 0;
  uint8_t md_type_set[] = {CKB_MD_SHA224, CKB_MD_SHA256, CKB_MD_SHA384,
                           CKB_MD_SHA512};
  uint8_t key_size_set[] = {CKB_KEYSIZE_1024, CKB_KEYSIZE_2048,
                            CKB_KEYSIZE_4096};
  //  uint8_t key_size_set[] = {CKB_KEYSIZE_1024};
  uint8_t padding_set[] = {CKB_PKCS_15, CKB_PKCS_21};
  for (int i = 0; i < count_of(key_size_set); i++) {
    for (int j = 0; j < count_of(md_type_set); j++) {
      for (int k = 0; k < count_of(padding_set); k++) {
        err = test_validate_signature(key_size_set[i], md_type_set[j],
                                      padding_set[k]);
        CHECK(err);
      }
    }
  }
  err = 0;
exit:
  if (err == 0) {
    mbedtls_printf("validate_signature_all_test() passed.\n");
  } else {
    mbedtls_printf("validate_signature_all_test() failed.\n");
  }
  return err;
}

int iso97962_test2(void) {
  int err = 0;
  const char* N_str =
      "9cf68418644a5418529373350bafd57ddbf5626527b95e8ea3217d8dac8fbcb7db107eda"
      "5e47979b7e4343ed6441950f7fbd921075579104ba081f1a9af950b4c0ee67c2eef2068d"
      "9fe2d9d0cfdcbb9be7066e19cc945600e9fd41fc50e771f437ce4bdde63e7acf2a828a4b"
      "f38b9f907a252b3dfef550919da1819033f9c619";
  const char* E_str = "10001";
  const char* msg_str = "B30D0D9FA0C8BBDF";
  const char* sig_str =
      "46E52F52599A97B7DBBB8BCDD3A3BE6857F4CEF41B0723BE9FBD404DCF471DFC00D2DBF2"
      "F5DA6A9B8C1A41893A569873CAD2E90EECEC84DEE85DCDE76041390D1E1328751F2832C8"
      "3699986744AF68087EFFB21CD9526317424C136911144AE31B00F1764F1C5CCD974D52F6"
      "278B029197C5746E62F67C544FA5C9B66E2A8AFB";
  const char* plaintext_str =
      "6A51762ED9802385DD5AE676C603778A037FFDCCD2BA92E32DD3AECE0C31AF76CFF88F75"
      "B257930255EA361218BEDCC4B1A96BBC9BCCF77BF6BA4B4A7F847F475F81C1FDD30C74B6"
      "AC97732C32D4B23C4BF8200270F5F15FED198E80AA5089807B9861E374D3871509C9965A"
      "AD886D9FB5A345873A4EB58EEFA5C35A4C3B55BC";

  mbedtls_rsa_context rsa;
  mbedtls_mpi N;
  mbedtls_mpi E;

  uint8_t msg[8];
  uint8_t sig[128];
  uint8_t block[128];
  uint32_t sig_len = 0;
  uint32_t msg_len = 0;
  uint8_t m1[128];
  uint32_t m1_len = 128;
  uint8_t full_msg[1024];
  uint8_t new_msg[1024];
  uint32_t new_msg_len = 1024;

  int alloc_buff_size = 1024 * 1024;
  unsigned char alloc_buff[alloc_buff_size];
  mbedtls_memory_buffer_alloc_init(alloc_buff, alloc_buff_size);

  mbedtls_mpi_init(&N);
  mbedtls_mpi_init(&E);

  mbedtls_mpi_read_string(&N, 16, N_str);
  mbedtls_mpi_read_string(&E, 16, E_str);
  mbedtls_rsa_init(&rsa, MBEDTLS_RSA_PKCS_V15, 0);
  mbedtls_rsa_import(&rsa, &N, NULL, NULL, NULL, &E);

  sig_len = read_string(sig_str, sig, sizeof(sig));
  ASSERT(sig_len == 128);
  msg_len = read_string(msg_str, msg, sizeof(msg));
  ASSERT(msg_len == 8);

  err = mbedtls_rsa_public(&rsa, sig, block);
  CHECK(err);

  ISO97962Encoding enc = {0};
  iso97962_init(&enc, 128, MBEDTLS_MD_SHA1, false);
  err = iso97962_verify(&enc, block, sizeof(block), msg, msg_len, m1, &m1_len);
  CHECK2(err == 0 || err == ERROR_ISO97962_MISMATCH_HASH,
         ERROR_ISO97962_INVALID_ARG9);

  memcpy(full_msg, m1, m1_len);
  memcpy(full_msg + m1_len, msg, sizeof(msg));

  err = iso97962_verify(&enc, block, sizeof(block), full_msg,
                        m1_len + sizeof(msg), new_msg, &new_msg_len);
  CHECK(err);

  err = 0;
exit:
  if (err == 0) {
    mbedtls_printf("iso97962_test2() passed.\n");
  } else {
    mbedtls_printf("iso97962_test2() failed.\n");
  }
  return err;
}

int iso97962_test(void) {
  int err = 0;
  ISO97962Encoding enc = {0};
  iso97962_init(&enc, 128, MBEDTLS_MD_SHA1, false);
  uint8_t msg[] = {1, 2, 3, 4, 5, 6, 7, 8};
  uint32_t msg_len = sizeof(msg);

  uint8_t block[128] = {0};
  err = iso97962_sign(&enc, msg, sizeof(msg), block, sizeof(block));
  CHECK(err);
  uint8_t new_msg[128];
  uint32_t new_msg_len = 128;
  err = iso97962_verify(&enc, block, sizeof(block), NULL, 0, new_msg,
                        &new_msg_len);
  CHECK(err);
  ASSERT(new_msg_len == msg_len);
  ASSERT(memcmp(msg, new_msg, msg_len) == 0);

  err = 0;
exit:
  if (err == 0) {
    mbedtls_printf("iso97962_test() passed.\n");
  } else {
    mbedtls_printf("iso97962_test() failed.\n");
  }
  return err;
}

int iso97962_error_cases_test() {
  int err = 0;
  ISO97962Encoding enc = {0};
  ISO97962Encoding wrong_enc = {0};
  iso97962_init(&enc, 128, MBEDTLS_MD_SHA1, false);

  uint8_t msg[] = {1, 2, 3, 4, 5, 6, 7, 8};
  uint32_t msg_len = sizeof(msg);

  uint8_t block[128] = {0};
  uint8_t wrong_block[128] = {0};
  err = iso97962_sign(&enc, msg, sizeof(msg), block, sizeof(block));
  CHECK(err);
  uint8_t new_msg[128];
  uint32_t new_msg_len = 128;

  memcpy(wrong_block, block, sizeof(block));
  wrong_block[107] -= 1;
  err = iso97962_verify(&enc, wrong_block, sizeof(wrong_block), NULL, 0,
                        new_msg, &new_msg_len);
  CHECK2(err == ERROR_ISO97962_MISMATCH_HASH, -1);

  memcpy(wrong_block, block, sizeof(block));
  new_msg_len = 128;
  wrong_block[sizeof(wrong_block) - 2] -= 1;
  err = iso97962_verify(&enc, wrong_block, sizeof(wrong_block), NULL, 0,
                        new_msg, &new_msg_len);
  CHECK2(err == ERROR_ISO97962_INVALID_ARG4, -1);

  memcpy(wrong_block, block, sizeof(block));
  new_msg_len = 128;
  for (int i = 97; i < 108; i++) {
    wrong_block[i] = (wrong_block[i] & 0xF0) | 0x0B;
  }
  err = iso97962_verify(&enc, wrong_block, sizeof(wrong_block), NULL, 0,
                        new_msg, &new_msg_len);
  CHECK2(err == ERROR_ISO97962_INVALID_ARG5, -1);

  memcpy(wrong_block, block, sizeof(block));
  new_msg_len = 128;
  wrong_block[0] = 0xC0;
  err = iso97962_verify(&enc, wrong_block, sizeof(wrong_block), NULL, 0,
                        new_msg, &new_msg_len);
  CHECK2(err == ERROR_ISO97962_INVALID_ARG2, -1);

  memcpy(wrong_block, block, sizeof(block));
  wrong_block[sizeof(wrong_block) - 1] = 0xFF;
  err = iso97962_verify(&enc, wrong_block, sizeof(wrong_block), NULL, 0,
                        new_msg, &new_msg_len);
  CHECK2(err == ERROR_ISO97962_INVALID_ARG3, -1);

  memcpy(&wrong_enc, &enc, sizeof(enc));
  wrong_enc.md = 100;
  err = iso97962_verify(&wrong_enc, block, sizeof(block), NULL, 0, new_msg,
                        &new_msg_len);

  CHECK2(err == ERROR_ISO97962_INVALID_ARG6, -1);

  err = 0;
exit:
  if (err == 0) {
    mbedtls_printf("iso97962_error_cases_test() passed.\n");
  } else {
    mbedtls_printf("iso97962_error_cases_test() failed.\n");
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

int iso97962_test3(void) {
  int err = 0;

  // RSA public key, N
  const char* N_str =
      "9cf68418644a5418529373350bafd57ddbf5626527b95e8ea3217d8dac8fbcb7db107eda"
      "5e47979b7e4343ed6441950f7fbd921075579104ba081f1a9af950b4c0ee67c2eef2068d"
      "9fe2d9d0cfdcbb9be7066e19cc945600e9fd41fc50e771f437ce4bdde63e7acf2a828a4b"
      "f38b9f907a252b3dfef550919da1819033f9c619";
  // RSA public key, E, 65537
  const char* E_str = "10001";
  // input small message
  const char* msg_str = "B30D0D9FA0C8BBDF";
  // input signature
  const char* sig_str =
      "46E52F52599A97B7DBBB8BCDD3A3BE6857F4CEF41B0723BE9FBD404DCF471DFC00D2DBF2"
      "F5DA6A9B8C1A41893A569873CAD2E90EECEC84DEE85DCDE76041390D1E1328751F2832C8"
      "3699986744AF68087EFFB21CD9526317424C136911144AE31B00F1764F1C5CCD974D52F6"
      "278B029197C5746E62F67C544FA5C9B66E2A8AFB";
  err = iso97962_sample_test(CKB_KEYSIZE_1024, N_str, E_str, msg_str, sig_str);
  CHECK(err);

exit:
  return err;
}

// validate_signature_rsa ckbvm <command> <arg1> <arg2> <arg3>
// validate_signature_rsa ckbvm -iso97962_test2
// validate_signature_rsa ckbvm -iso97962_test3
// validate_signature_rsa ckbvm -rsa sig_buf_in_hex msg_buf_in_hex
// validate_signature_rsa ckbvm -rsa sig_buf_in_hex msg_buf_in_hex
// ...
int ckbvm_main(int argc, const char* argv[]) {
  int err = 0;
  if (argc <= 2) {
    return -1;
  }

  if (strcmp(argv[2], "-iso97962_test2") == 0) {
    err = iso97962_test2();
    CHECK(err);
  }
  if (strcmp(argv[2], "-iso97962_test3") == 0) {
    err = iso97962_test2();
    CHECK(err);
  }
  if (strcmp(argv[2], "-rsa") == 0) {
    if (argc != 5) return -1;
    uint32_t sig_len = 0;
    uint8_t sig_buf[1024 * 2];
    uint32_t msg_len = 0;
    uint8_t msg_buf[1024 * 2];
    sig_len = read_string(argv[3], sig_buf, sizeof(sig_buf));
    msg_len = read_string(argv[4], msg_buf, sizeof(msg_buf));
    err = validate_signature(NULL, sig_buf, sig_len, msg_buf, msg_len, NULL,
                             NULL);
    CHECK(err);
  }

  err = 0;
exit:
  return err;
}

int main(int argc, const char* argv[]) {
  if (argc >= 2) {
    if (strcmp(argv[1], "ckbvm") == 0) {
      return ckbvm_main(argc, argv);
    }
  }

  int err = 0;

  err = rsa_random();
  CHECK(err);

  err = validate_signature_all_test();
  CHECK(err);

#ifdef CKB_COVERAGE
  err = validate_signature_error_cases_test();
  CHECK(err);
#endif

  err = iso97962_test();
  CHECK(err);

#ifdef CKB_COVERAGE
  err = iso97962_error_cases_test();
  CHECK(err);
#endif

  err = iso97962_test2();
  CHECK(err);

  err = iso97962_test3();
  CHECK(err);

  err = 0;
exit:
  return err;
}
