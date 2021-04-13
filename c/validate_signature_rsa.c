
#ifndef ASSERT
#define ASSERT(s) (void)0
#endif

#include "validate_signature_rsa.h"

#include <stdbool.h>
#include <string.h>

#include "mbedtls/md.h"
#include "mbedtls/md_internal.h"
#include "mbedtls/memory_buffer_alloc.h"
#include "mbedtls/rsa.h"

#if defined(CKB_USE_SIM)
#include <stdio.h>
#define mbedtls_printf printf
#else
#define mbedtls_printf(x, ...) (void)0
#endif

enum ErrorCode {
  // 0 is the only success code. We can use 0 directly.
  CKB_SUCCESS = 0,
  // error code is starting from 40, to avoid conflict with
  // common error code in other scripts.
  ERROR_RSA_INVALID_PARAM1 = 40,
  ERROR_RSA_INVALID_PARAM2,
  ERROR_RSA_VERIFY_FAILED,
  ERROR_RSA_ONLY_INIT,
  ERROR_RSA_INVALID_KEY_SIZE,
  ERROR_RSA_INVALID_MD_TYPE2,
  ERROR_RSA_INVALID_ID,
  ERROR_BAD_MEMORY_LAYOUT,
  ERROR_INVALID_MD_TYPE,
  ERROR_INVALID_PADDING,
  ERROR_MD_FAILED,
  ERROR_MBEDTLS_ERROR_1,
  ERROR_ISO97962_MISMATCH_HASH,
  ERROR_ISO97962_INVALID_ARG1,
  ERROR_ISO97962_INVALID_ARG2,
  ERROR_ISO97962_INVALID_ARG3,
  ERROR_ISO97962_INVALID_ARG4,
  ERROR_ISO97962_INVALID_ARG5,
  ERROR_ISO97962_INVALID_ARG6,
  ERROR_ISO97962_INVALID_ARG7,
  ERROR_ISO97962_INVALID_ARG8,
  ERROR_ISO97962_INVALID_ARG9,
  ERROR_ISO97962_INVALID_ARG10,
  ERROR_ISO97962_INVALID_ARG11,
  ERROR_ISO97962_INVALID_ARG12,
  ERROR_ISO97962_INVALID_ARG13,
  ERROR_WRONG_PUBKEY,
};

#define CHECK2(cond, code) \
  do {                     \
    if (!(cond)) {         \
      err = code;          \
      ASSERT(0);           \
      goto exit;           \
    }                      \
  } while (0)

#define CHECK(code)  \
  do {               \
    if (code != 0) { \
      err = code;    \
      ASSERT(0);     \
      goto exit;     \
    }                \
  } while (0)

int md_string(const mbedtls_md_info_t *md_info, const uint8_t *buf, size_t n,
              unsigned char *output);
int validate_signature_iso9796_2(void *, const uint8_t *sig_buf,
                                 size_t sig_size, const uint8_t *msg_buf,
                                 size_t msg_size, uint8_t *out,
                                 size_t *out_len);

bool is_valid_iso97962_md_type(uint8_t md) {
  return md == CKB_MD_SHA1 || md == CKB_MD_SHA224 || md == CKB_MD_SHA256 ||
         md == CKB_MD_SHA384 || md == CKB_MD_SHA512;
}

// remove SHA1 and RIPEMD160 as options for the message digest hash functions.
bool is_valid_rsa_md_type(uint8_t md) {
  return md == CKB_MD_SHA224 || md == CKB_MD_SHA256 || md == CKB_MD_SHA384 ||
         md == CKB_MD_SHA512;
}

bool is_valid_key_size(uint8_t size) {
  return size == CKB_KEYSIZE_1024 || size == CKB_KEYSIZE_2048 ||
         size == CKB_KEYSIZE_4096;
}

bool is_valid_key_size_in_bit(uint32_t size) {
  return size == 1024 || size == 2048 || size == 4096;
}

bool is_valid_padding(uint8_t padding) {
  return padding == CKB_PKCS_15 || padding == CKB_PKCS_21;
}

uint32_t get_key_size(uint8_t key_size_enum) {
  if (key_size_enum == CKB_KEYSIZE_1024) {
    return 1024;
  } else if (key_size_enum == CKB_KEYSIZE_2048) {
    return 2048;
  } else if (key_size_enum == CKB_KEYSIZE_4096) {
    return 4096;
  } else {
    ASSERT(false);
    return 0;
  }
}

int check_pubkey(mbedtls_mpi *N, mbedtls_mpi *E) {
  int err = 0;
  size_t key_size = mbedtls_mpi_size(N) * 8;
  CHECK2(is_valid_key_size_in_bit(key_size), ERROR_WRONG_PUBKEY);

  mbedtls_mpi two;
  mbedtls_mpi_init(&two);
  err = mbedtls_mpi_lset(&two, 2);
  CHECK(err);
  CHECK2(mbedtls_mpi_cmp_mpi(&two, E) < 0 && mbedtls_mpi_cmp_mpi(E, N) < 0,
         ERROR_WRONG_PUBKEY);

  err = 0;
exit:
  return err;
}

mbedtls_md_type_t convert_md_type(uint8_t type) {
  mbedtls_md_type_t result = MBEDTLS_MD_NONE;
  switch (type) {
    case CKB_MD_SHA224:
      result = MBEDTLS_MD_SHA224;
      break;
    case CKB_MD_SHA256:
      result = MBEDTLS_MD_SHA256;
      break;
    case CKB_MD_SHA384:
      result = MBEDTLS_MD_SHA384;
      break;
    case CKB_MD_SHA512:
      result = MBEDTLS_MD_SHA512;
      break;
    case CKB_MD_SHA1:
      result = MBEDTLS_MD_SHA1;
      break;
    default:
      ASSERT(0);
      result = MBEDTLS_MD_NONE;
  }
  return result;
}

int convert_padding(uint8_t padding) {
  if (padding == CKB_PKCS_15) {
    return MBEDTLS_RSA_PKCS_V15;
  } else if (padding == CKB_PKCS_21) {
    return MBEDTLS_RSA_PKCS_V21;
  } else {
    ASSERT(0);
  }
  return -1;
}

__attribute__((visibility("default"))) int load_prefilled_data(void *data,
                                                               size_t *len) {
  (void)data;
  *len = 0;
  return CKB_SUCCESS;
}

uint8_t *get_rsa_signature(RsaInfo *info) {
  int length = get_key_size(info->key_size) / 8;
  // note: sanitizer reports error:
  // Index 256 out of bounds for type 'uint8_t [128]'
  // It's intended. RsaInfo is actually an variable length buffer.
  return (uint8_t *)&info->N[length];
}

uint32_t calculate_rsa_info_length(int key_size) { return 8 + key_size / 4; }

int validate_signature_rsa(void *prefilled_data,
                           const uint8_t *signature_buffer,
                           size_t signature_size, const uint8_t *msg_buf,
                           size_t msg_size, uint8_t *output,
                           size_t *output_len) {
  (void)prefilled_data;
  (void)output;
  (void)output_len;
  int err = ERROR_RSA_ONLY_INIT;
  uint8_t hash_buf[MBEDTLS_MD_MAX_SIZE] = {0};
  uint32_t hash_size = 0;
  uint32_t key_size = 0;
  bool is_rsa_inited = false;
  mbedtls_rsa_context rsa;

  RsaInfo *input_info = (RsaInfo *)signature_buffer;

  // for key size with 1024 and 2048 bits, it uses up to 7K bytes.
  int alloc_buff_size = 1024 * 7;
  // for key size with 4096 bits, it uses 12K bytes at most.
  if (input_info->key_size == CKB_KEYSIZE_4096) alloc_buff_size = 1024 * 12;
  unsigned char alloc_buff[alloc_buff_size];
  mbedtls_memory_buffer_alloc_init(alloc_buff, alloc_buff_size);

  CHECK2(is_valid_rsa_md_type(input_info->md_type), ERROR_INVALID_MD_TYPE);
  CHECK2(is_valid_padding(input_info->padding), ERROR_INVALID_PADDING);
  CHECK2(is_valid_key_size(input_info->key_size), ERROR_RSA_INVALID_KEY_SIZE);
  key_size = get_key_size(input_info->key_size);
  CHECK2(key_size > 0, ERROR_RSA_INVALID_KEY_SIZE);
  CHECK2(signature_buffer != NULL, ERROR_RSA_INVALID_PARAM1);
  CHECK2(msg_buf != NULL, ERROR_RSA_INVALID_PARAM1);
  CHECK2(signature_size == (size_t)calculate_rsa_info_length(key_size),
         ERROR_RSA_INVALID_PARAM2);

  mbedtls_md_type_t md_type = convert_md_type(input_info->md_type);
  const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(md_type);
  CHECK2(md_info != NULL, ERROR_RSA_INVALID_MD_TYPE2);

  hash_size = md_info->size;
  int padding = convert_padding(input_info->padding);

  is_rsa_inited = true;
  mbedtls_rsa_init(&rsa, padding, 0);

  err = mbedtls_mpi_read_binary_le(
      &rsa.E, (const unsigned char *)&input_info->E, sizeof(uint32_t));
  CHECK2(err == 0, ERROR_MBEDTLS_ERROR_1);

  err = mbedtls_mpi_read_binary_le(&rsa.N, input_info->N, key_size / 8);
  CHECK2(err == 0, ERROR_MBEDTLS_ERROR_1);

  CHECK(check_pubkey(&rsa.N, &rsa.E));

  rsa.len = (mbedtls_mpi_bitlen(&rsa.N) + 7) >> 3;
  CHECK2(is_valid_key_size_in_bit(rsa.len * 8), ERROR_WRONG_PUBKEY);

  err = md_string(md_info, msg_buf, msg_size, hash_buf);
  CHECK2(err == 0, ERROR_MD_FAILED);

  err = mbedtls_rsa_pkcs1_verify(&rsa, NULL, NULL, MBEDTLS_RSA_PUBLIC, md_type,
                                 hash_size, hash_buf,
                                 get_rsa_signature(input_info));
  if (err != 0) {
    err = ERROR_RSA_VERIFY_FAILED;
    goto exit;
  }

  err = CKB_SUCCESS;

exit:
  if (is_rsa_inited) mbedtls_rsa_free(&rsa);
  return err;
}

/**
 * entry for different algorithms
 * The fist byte of signature_buffer is the algorithm_id, it can be:
 * #define CKB_VERIFY_RSA 1
 * #define CKB_VERIFY_ISO9796_2 2
s */
__attribute__((visibility("default"))) int validate_signature(
    void *prefilled_data, const uint8_t *sig_buf, size_t sig_len,
    const uint8_t *msg_buf, size_t msg_len, uint8_t *output,
    size_t *output_len) {
  // we have 4 bytes common header at the beginning of RsaInfo,
  // need to make sure they occupy exactly 4 bytes.
  if (sizeof(RsaInfo) != (PLACEHOLDER_SIZE * 2 + 8)) {
    ASSERT(0);
    return ERROR_BAD_MEMORY_LAYOUT;
  }
  if (sig_buf == NULL) {
    ASSERT(0);
    return ERROR_RSA_INVALID_PARAM1;
  }

  uint8_t id = ((RsaInfo *)sig_buf)->algorithm_id;

  if (id == CKB_VERIFY_RSA) {
    return validate_signature_rsa(prefilled_data, sig_buf, sig_len, msg_buf,
                                  msg_len, output, output_len);
  } else if (id == CKB_VERIFY_ISO9796_2) {
    return validate_signature_iso9796_2(prefilled_data, sig_buf, sig_len,
                                        msg_buf, msg_len, output, output_len);
  } else {
    return ERROR_RSA_INVALID_ID;
  }
}

int md_string(const mbedtls_md_info_t *md_info, const uint8_t *buf, size_t n,
              unsigned char *output) {
  int err = 0;
  mbedtls_md_context_t ctx;
  mbedtls_md_init(&ctx);

  CHECK2(md_info != NULL, MBEDTLS_ERR_MD_BAD_INPUT_DATA);
  err = mbedtls_md_setup(&ctx, md_info, 0);
  CHECK(err);
  err = mbedtls_md_starts(&ctx);
  CHECK(err);
  err = mbedtls_md_update(&ctx, (const unsigned char *)buf, n);
  CHECK(err);
  err = mbedtls_md_finish(&ctx, output);
  CHECK(err);
  err = 0;
exit:
  mbedtls_md_free(&ctx);
  return err;
}

// ISO 9796-2, scheme #1
// some hash functions are not implemented but we still list them here according
// to the spec.
enum Trailer {
  TRAILER_IMPLICIT = 0xBC,
  TRAILER_RIPEMD160 = 0x31CC,
  TRAILER_RIPEMD128 = 0x32CC,
  TRAILER_SHA1 = 0x33CC,
  TRAILER_SHA256 = 0x34CC,
  TRAILER_SHA512 = 0x35CC,
  TRAILER_SHA384 = 0x36CC,
  TRAILER_WHIRLPOOL = 0x37CC,
  TRAILER_SHA224 = 0x38CC,
  TRAILER_SHA512_224 = 0x39CC,
  TRAILER_SHA512_256 = 0x3aCC
};

uint16_t get_trailer_by_md(mbedtls_md_type_t md) {
  if (md == MBEDTLS_MD_NONE) {
    return TRAILER_IMPLICIT;
  } else if (md == MBEDTLS_MD_SHA1) {
    return TRAILER_SHA1;
  } else if (md == MBEDTLS_MD_SHA224) {
    return TRAILER_SHA224;
  } else if (md == MBEDTLS_MD_SHA256) {
    return TRAILER_SHA256;
  } else if (md == MBEDTLS_MD_SHA384) {
    return TRAILER_SHA384;
  } else if (md == MBEDTLS_MD_SHA512) {
    return TRAILER_SHA512;
  } else if (md == MBEDTLS_MD_RIPEMD160) {
    return TRAILER_RIPEMD160;
  } else {
    ASSERT(false);
    return 0;
  }
}

typedef struct ISO97962Encoding {
  uint32_t key_size;  // RSA key size 1024, 2048, 4096, etc
  mbedtls_md_type_t md;
  bool implicity;

  uint32_t trailer;
} ISO97962Encoding;

void iso97962_init(ISO97962Encoding *enc, uint32_t key_size_byte,
                   mbedtls_md_type_t md, bool implicity) {
  enc->key_size = key_size_byte * 8;
  enc->md = md;
  enc->implicity = implicity;

  enc->trailer = get_trailer_by_md(md);
}

int iso97962_verify(ISO97962Encoding *enc, const uint8_t *block,
                    uint32_t block_len, const uint8_t *origin,
                    uint32_t origin_len, uint8_t *msg, uint32_t *msg_len) {
  int err = 0;
  const mbedtls_md_info_t *digest = mbedtls_md_info_from_type(enc->md);
  if (digest == NULL) {
    return ERROR_ISO97962_INVALID_ARG6;
  }
  int hash_len = digest->size;
  uint8_t hash[MBEDTLS_MD_MAX_SIZE] = {0};

  int alloc_buff_size = 20 * 1024;
  uint8_t alloc_buff[alloc_buff_size];
  mbedtls_memory_buffer_alloc_init(alloc_buff, alloc_buff_size);

  CHECK2(block != NULL && msg != NULL, ERROR_ISO97962_INVALID_ARG1);
  CHECK2(*msg_len >= block_len, ERROR_ISO97962_INVALID_ARG1);
  CHECK2(block_len == enc->key_size / 8, ERROR_ISO97962_INVALID_ARG1);

  if (((block[0] & 0xC0) ^ 0x40) != 0) {
    return ERROR_ISO97962_INVALID_ARG2;
  }

  if (((block[block_len - 1] & 0xF) ^ 0xC) != 0) {
    return ERROR_ISO97962_INVALID_ARG3;
  }

  int delta = 0;

  if (((block[block_len - 1] & 0xFF) ^ 0xBC) == 0) {
    delta = 1;
  } else {
    int sig_trail =
        ((block[block_len - 2] & 0xFF) << 8) | (block[block_len - 1] & 0xFF);
    int trailer_obj = get_trailer_by_md(enc->md);

    if (trailer_obj != 0) {
      if (sig_trail != trailer_obj) {
        if (!(trailer_obj == TRAILER_SHA512_256 && sig_trail == 0x40CC)) {
          return ERROR_ISO97962_INVALID_ARG4;
        }
      }
    } else {
      // this branch can't be reached due to "if (digest == NULL)" above.
      // but still keep it here for defensive purpose
      return ERROR_ISO97962_INVALID_ARG4;
    }

    delta = 2;
  }

  // find out how much padding we've got
  int msg_start = 0;

  for (msg_start = 0; msg_start != block_len; msg_start++) {
    if (((block[msg_start] & 0x0f) ^ 0x0a) == 0) {
      break;
    }
  }
  msg_start++;

  int off = block_len - delta - digest->size;
  if ((off - msg_start) <= 0) {
    return ERROR_ISO97962_INVALID_ARG5;
  }

  if ((block[0] & 0x20) == 0) {
    mbedtls_md(digest, block + msg_start, off - msg_start, hash);

    *msg_len = off - msg_start;
    memcpy(msg, block + msg_start, *msg_len);

    for (int i = 0; i != hash_len; i++) {
      if (block[off + i] != hash[i]) {
        err = ERROR_ISO97962_MISMATCH_HASH;
        goto exit;
      }
    }

  } else {
    mbedtls_md(digest, origin, origin_len, hash);

    *msg_len = off - msg_start;
    memcpy(msg, block + msg_start, *msg_len);

    for (int i = 0; i != hash_len; i++) {
      if (block[off + i] != hash[i]) {
        err = ERROR_ISO97962_MISMATCH_HASH;
        goto exit;
      }
    }
  }
  err = 0;
exit:
  return err;
}

int validate_signature_iso9796_2(void *_p, const uint8_t *sig_buf,
                                 size_t sig_len, const uint8_t *msg_buf,
                                 size_t msg_len, uint8_t *out,
                                 size_t *out_len) {
  int err = 0;

  (void)_p;
  RsaInfo *info = (RsaInfo *)sig_buf;
  mbedtls_rsa_context rsa;
  mbedtls_mpi N;
  mbedtls_mpi E;

  if (sig_len < sizeof(RsaInfo)) {
    return ERROR_ISO97962_INVALID_ARG12;
  }
  uint32_t key_size_byte = get_key_size(info->key_size) / 8;

  uint8_t *sig = NULL;
  uint8_t block[key_size_byte];
  uint8_t m1[key_size_byte];
  uint32_t m1_len = key_size_byte;
  uint8_t full_msg[key_size_byte * 2];
  uint8_t new_msg[key_size_byte * 2];
  uint32_t new_msg_len = key_size_byte;

  int alloc_buff_size = 20 * 1024;
  unsigned char alloc_buff[alloc_buff_size];
  mbedtls_memory_buffer_alloc_init(alloc_buff, alloc_buff_size);

  CHECK2(key_size_byte > 0, ERROR_ISO97962_INVALID_ARG7);
  CHECK2(msg_buf != NULL, ERROR_ISO97962_INVALID_ARG8);
  CHECK2(out != NULL, ERROR_ISO97962_INVALID_ARG8);
  CHECK2(out_len != NULL, ERROR_ISO97962_INVALID_ARG8);
  CHECK2(key_size_byte > 0, ERROR_ISO97962_INVALID_ARG8);
  CHECK2(is_valid_iso97962_md_type(info->md_type), ERROR_INVALID_MD_TYPE);

  mbedtls_mpi_init(&N);
  mbedtls_mpi_init(&E);

  err = mbedtls_mpi_read_binary_le(&N, (uint8_t *)info->N, key_size_byte);
  CHECK2(err == 0, ERROR_ISO97962_INVALID_ARG9);
  err = mbedtls_mpi_read_binary_le(&E, (uint8_t *)&info->E, 4);
  CHECK2(err == 0, ERROR_ISO97962_INVALID_ARG10);

  CHECK(check_pubkey(&N, &E));

  mbedtls_rsa_init(&rsa, MBEDTLS_RSA_PKCS_V15, 0);
  err = mbedtls_rsa_import(&rsa, &N, NULL, NULL, NULL, &E);
  CHECK2(err == 0, ERROR_ISO97962_INVALID_ARG11);

  sig = get_rsa_signature(info);

  err = mbedtls_rsa_public(&rsa, sig, block);
  CHECK2(err == 0, ERROR_ISO97962_INVALID_ARG12);

  ISO97962Encoding enc = {0};
  mbedtls_md_type_t md_type = convert_md_type(info->md_type);

  iso97962_init(&enc, key_size_byte, md_type, false);
  err = iso97962_verify(&enc, block, key_size_byte, msg_buf, msg_len, m1,
                        &m1_len);
  CHECK2(err == 0 || err == ERROR_ISO97962_MISMATCH_HASH,
         ERROR_ISO97962_INVALID_ARG9);

  memcpy(full_msg, m1, m1_len);
  memcpy(full_msg + m1_len, msg_buf, msg_len);

  err = iso97962_verify(&enc, block, sizeof(block), full_msg, m1_len + msg_len,
                        new_msg, &new_msg_len);
  CHECK(err);

  uint32_t copy_size = new_msg_len > *out_len ? *out_len : new_msg_len;
  memcpy(out, new_msg, copy_size);
  *out = copy_size;

  err = 0;
exit:
  if (err == 0) {
    mbedtls_printf("validate_signature_iso9796_2() passed.\n");
  } else {
    mbedtls_printf("validate_signature_iso9796_2() failed: %d\n", err);
  }
  return err;
}
