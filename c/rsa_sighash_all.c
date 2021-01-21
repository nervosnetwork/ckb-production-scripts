
// uncomment to enable printf in CKB-VM
//#define CKB_C_STDLIB_PRINTF
//#include <stdio.h>
#ifndef ASSERT
#define ASSERT(s) (void)0
#endif

#include "rsa_sighash_all.h"

#include <string.h>

#include "blake2b.h"
#include "blockchain.h"
#include "mbedtls/md.h"
#include "mbedtls/md_internal.h"
#include "mbedtls/memory_buffer_alloc.h"
#include "mbedtls/rsa.h"

#ifdef CKB_USE_SIM
#include "ckb_consts.h"
#include "ckb_syscall_sim.h"
#else
#include "ckb_syscalls.h"
#endif
#if defined(CKB_USE_SIM)
#include <stdio.h>
#define mbedtls_printf printf
#else
#define mbedtls_printf(x, ...) (void)0
#endif

#define BLAKE2B_BLOCK_SIZE 32
#define BLAKE160_SIZE 20
/* 32 KB */
#define MAX_WITNESS_SIZE 32768
#define SCRIPT_SIZE 32768
#define TEMP_SIZE 32768
#define ONE_BATCH_SIZE 32768

#define CKB_SUCCESS 0
#define ERROR_ARGUMENTS_LEN (-1)
#define ERROR_ENCODING (-2)
#define ERROR_SYSCALL (-3)
#define ERROR_SCRIPT_TOO_LONG (-21)
#define ERROR_WITNESS_SIZE (-22)
#define ERROR_WRONG_SCRIPT_ARGS_LEN (-23)
#define ERROR_RSA_INVALID_PARAM1 (-40)
#define ERROR_RSA_INVALID_PARAM2 (-41)
#define ERROR_RSA_MDSTRING_FAILED (-42)
#define ERROR_RSA_VERIFY_FAILED (-43)
#define ERROR_RSA_ONLY_INIT (-44)
#define ERROR_RSA_INVALID_KEY_SIZE (-45)
#define ERROR_RSA_INVALID_BLADE2B_SIZE (-46)
#define ERROR_RSA_INVALID_ID (-47)
#define ERROR_RSA_NOT_IMPLEMENTED (-48)
#define ERROR_BAD_MEMORY_LAYOUT (-49)
#define ERROR_INVALID_MD_TYPE (-50)
#define ERROR_INVALID_PADDING (-51)
#define ERROR_MD_FAILED (-52)

#define ERROR_ISO97962_INVALID_ARG1 (-51)
#define ERROR_ISO97962_INVALID_ARG2 (-52)
#define ERROR_ISO97962_INVALID_ARG3 (-53)
#define ERROR_ISO97962_INVALID_ARG4 (-54)
#define ERROR_ISO97962_INVALID_ARG5 (-55)
#define ERROR_ISO97962_INVALID_ARG6 (-56)
#define ERROR_ISO97962_INVALID_ARG7 (-57)
#define ERROR_ISO97962_INVALID_ARG8 (-58)
#define ERROR_ISO97962_INVALID_ARG9 (-59)
#define ERROR_ISO97962_MISMATCH_HASH (-60)
#define ERROR_ISO97962_NOT_FULL_MSG (-61)

#define RSA_VALID_KEY_SIZE1 1024
#define RSA_VALID_KEY_SIZE2 2048
#define RSA_VALID_KEY_SIZE3 4096

#define BLAKE2B_BLOCK_SIZE 32
#define BLAKE160_SIZE 20

#define PUBLIC_KEY_SIZE1 (RSA_VALID_KEY_SIZE1 / 8 + 4)
#define PUBLIC_KEY_SIZE2 (RSA_VALID_KEY_SIZE2 / 8 + 4)
#define PUBLIC_KEY_SIZE3 (RSA_VALID_KEY_SIZE3 / 8 + 4)

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

bool is_valid_md_type(uint8_t md) {
  return md == CKB_MD_SHA1 || md == CKB_MD_SHA224 || md == CKB_MD_SHA256 ||
         md == CKB_MD_SHA384 || md == CKB_MD_SHA512 || md == CKB_MD_RIPEMD160;
}

bool is_valid_key_size(uint8_t size) {
  return size == CKB_KEYSIZE_1024 || size == CKB_KEYSIZE_2048 ||
         size == CKB_KEYSIZE_4096;
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
    case CKB_MD_RIPEMD160:
      result = MBEDTLS_MD_RIPEMD160;
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

int mbedtls_hardware_poll(void *data, unsigned char *output, size_t len,
                          size_t *olen) {
  return 0;
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

  CHECK2(is_valid_md_type(input_info->md_type), ERROR_INVALID_MD_TYPE);
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
  hash_size = md_info->size;
  int padding = convert_padding(input_info->padding);

  is_rsa_inited = true;
  mbedtls_rsa_init(&rsa, padding, 0);

  mbedtls_mpi_read_binary_le(&rsa.E, (const unsigned char *)&input_info->E,
                             sizeof(uint32_t));
  mbedtls_mpi_read_binary_le(&rsa.N, input_info->N, key_size / 8);
  rsa.len = (mbedtls_mpi_bitlen(&rsa.N) + 7) >> 3;

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
  if (is_rsa_inited)
    mbedtls_rsa_free(&rsa);
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

/*
 * The following code is to add RSA "validate all" method.
 * It mimic the behavior of validate_secp256k1_blake2b_sighash_all.
 */

int load_and_hash_witness(blake2b_state *ctx, size_t index, size_t source) {
  uint8_t temp[ONE_BATCH_SIZE];
  uint64_t len = ONE_BATCH_SIZE;
  int ret = ckb_load_witness(temp, &len, 0, index, source);
  if (ret != CKB_SUCCESS) {
    return ret;
  }
  blake2b_update(ctx, (char *)&len, sizeof(uint64_t));
  uint64_t offset = (len > ONE_BATCH_SIZE) ? ONE_BATCH_SIZE : len;
  blake2b_update(ctx, temp, offset);
  while (offset < len) {
    uint64_t current_len = ONE_BATCH_SIZE;
    ret = ckb_load_witness(temp, &current_len, offset, index, source);
    if (ret != CKB_SUCCESS) {
      return ret;
    }
    uint64_t current_read =
        (current_len > ONE_BATCH_SIZE) ? ONE_BATCH_SIZE : current_len;
    blake2b_update(ctx, temp, current_read);
    offset += current_read;
  }
  return CKB_SUCCESS;
}

// Extract lock from WitnessArgs
int extract_witness_lock(uint8_t *witness, uint64_t len,
                         mol_seg_t *lock_bytes_seg) {
  mol_seg_t witness_seg;
  witness_seg.ptr = witness;
  witness_seg.size = len;

  if (MolReader_WitnessArgs_verify(&witness_seg, false) != MOL_OK) {
    return ERROR_ENCODING;
  }
  mol_seg_t lock_seg = MolReader_WitnessArgs_get_lock(&witness_seg);

  if (MolReader_BytesOpt_is_none(&lock_seg)) {
    return ERROR_ENCODING;
  }
  *lock_bytes_seg = MolReader_Bytes_raw_bytes(&lock_seg);
  return CKB_SUCCESS;
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

// this method performs RSA signature verification: it supports variable key
// sizes: 1024, 2048 and 4096.
//
// Given a blake160 format public key hash, this
// method performs signature verifications on input cells using current lock
// script hash. It then asserts that the derive public key hash from the
// signature matches the given public key hash.
//
// Note that this method is exposed
// for dynamic linking usage, so the "current lock script" mentioned above, does
// not have to be this current script code. It could be a different script code
// using this script via as a library.
__attribute__((visibility("default"))) int validate_rsa_sighash_all(
    uint8_t *output_public_key_hash) {
  int ret = ERROR_RSA_ONLY_INIT;
  unsigned char first_witness[TEMP_SIZE];
  uint64_t len = 0;

  // Load witness of first input
  uint64_t witness_len = MAX_WITNESS_SIZE;
  ret = ckb_load_witness(first_witness, &witness_len, 0, 0,
                         CKB_SOURCE_GROUP_INPUT);
  if (ret != CKB_SUCCESS) {
    return ERROR_SYSCALL;
  }

  if (witness_len > MAX_WITNESS_SIZE) {
    return ERROR_WITNESS_SIZE;
  }

  // load signature
  mol_seg_t lock_bytes_seg;
  ret = extract_witness_lock(first_witness, witness_len, &lock_bytes_seg);
  if (ret != 0) {
    return ERROR_ENCODING;
  }

  uint32_t key_size_enum = ((RsaInfo *)lock_bytes_seg.ptr)->key_size;
  uint32_t key_size = get_key_size(key_size_enum);
  if (key_size == 0) {
    return ERROR_ARGUMENTS_LEN;
  }
  uint32_t info_len = calculate_rsa_info_length(key_size);
  if (lock_bytes_seg.size != info_len) {
    return ERROR_ARGUMENTS_LEN;
  }
  // RSA signature size is different than secp256k1
  // secp256k1 use 65 bytes as signature but RSA actually has dynamic size
  // depending on key size.
  unsigned char rsa_info[info_len];
  memcpy(rsa_info, lock_bytes_seg.ptr, lock_bytes_seg.size);

  // Load tx hash
  unsigned char tx_hash[BLAKE2B_BLOCK_SIZE];
  len = BLAKE2B_BLOCK_SIZE;
  ret = ckb_load_tx_hash(tx_hash, &len, 0);
  if (ret != CKB_SUCCESS) {
    return ret;
  }
  if (len != BLAKE2B_BLOCK_SIZE) {
    return ERROR_SYSCALL;
  }

  // Prepare sign message
  // message = hash(tx_hash + first_witness_len + first_witness +
  // other_witness(with length))
  unsigned char message[BLAKE2B_BLOCK_SIZE];
  blake2b_state blake2b_ctx;
  blake2b_init(&blake2b_ctx, BLAKE2B_BLOCK_SIZE);
  blake2b_update(&blake2b_ctx, tx_hash, BLAKE2B_BLOCK_SIZE);

  // Clear lock field to zero. Note, the molecule header (4 byte with content
  // SIGNATURE_SIZE) is not cleared. That means, SIGNATURE_SIZE should be always
  // the same value.
  memset((void *)lock_bytes_seg.ptr, 0, lock_bytes_seg.size);
  // digest the first witness
  blake2b_update(&blake2b_ctx, (char *)&witness_len, sizeof(witness_len));
  blake2b_update(&blake2b_ctx, first_witness, witness_len);

  // Digest same group witnesses
  size_t i = 1;
  while (1) {
    ret = load_and_hash_witness(&blake2b_ctx, i, CKB_SOURCE_GROUP_INPUT);
    if (ret == CKB_INDEX_OUT_OF_BOUND) {
      break;
    }
    if (ret != CKB_SUCCESS) {
      return ERROR_SYSCALL;
    }
    i += 1;
  }
  // Digest witnesses that not covered by inputs
  i = ckb_calculate_inputs_len();
  while (1) {
    ret = load_and_hash_witness(&blake2b_ctx, i, CKB_SOURCE_INPUT);
    if (ret == CKB_INDEX_OUT_OF_BOUND) {
      break;
    }
    if (ret != CKB_SUCCESS) {
      return ERROR_SYSCALL;
    }
    i += 1;
  }
  blake2b_final(&blake2b_ctx, message, BLAKE2B_BLOCK_SIZE);

  size_t pub_key_hash_size = BLAKE160_SIZE;
  int result = validate_signature(NULL, (const uint8_t *)rsa_info, info_len,
                                  (const uint8_t *)message, BLAKE2B_BLOCK_SIZE,
                                  output_public_key_hash, &pub_key_hash_size);
  if (result == 0) {
    mbedtls_printf("validate signature passed\n");
  } else {
    mbedtls_printf("validate signature failed: %d\n", result);
    return ERROR_RSA_VERIFY_FAILED;
  }

  blake2b_init(&blake2b_ctx, BLAKE2B_BLOCK_SIZE);
  // pub key hash = blake2b(E + N), common header is not included.
  blake2b_update(&blake2b_ctx, rsa_info + 4, 4 + key_size / 8);
  unsigned char blake2b_hash[BLAKE2B_BLOCK_SIZE] = {0};
  blake2b_final(&blake2b_ctx, blake2b_hash, BLAKE2B_BLOCK_SIZE);

  memcpy(output_public_key_hash, blake2b_hash, BLAKE160_SIZE);

  return CKB_SUCCESS;
}

// ISO 9796-2, scheme #1
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
  uint32_t key_size;  // RSA key size 1024, 2048, etc
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
  uint8_t hash[hash_len];
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

  uint32_t key_size_byte = get_key_size(info->key_size) / 8;
  uint8_t *sig = NULL;
  uint8_t block[key_size_byte];
  uint8_t m1[key_size_byte];
  uint32_t m1_len = key_size_byte;
  uint8_t full_msg[key_size_byte * 2];
  uint8_t new_msg[key_size_byte * 2];
  uint32_t new_msg_len = key_size_byte;

  int alloc_buff_size = 200 * 1024;
  unsigned char alloc_buff[alloc_buff_size];
  mbedtls_memory_buffer_alloc_init(alloc_buff, alloc_buff_size);

  CHECK2(key_size_byte > 0, ERROR_ISO97962_INVALID_ARG7);
  CHECK2(msg_buf != NULL, ERROR_ISO97962_INVALID_ARG8);
  CHECK2(out != NULL, ERROR_ISO97962_INVALID_ARG8);
  CHECK2(out_len != NULL, ERROR_ISO97962_INVALID_ARG8);
  CHECK2(key_size_byte > 0, ERROR_ISO97962_INVALID_ARG8);
  CHECK2(is_valid_md_type(info->md_type), ERROR_INVALID_MD_TYPE);

  mbedtls_mpi_init(&N);
  mbedtls_mpi_init(&E);

  mbedtls_mpi_read_binary_le(&N, (uint8_t *)info->N, key_size_byte);
  mbedtls_mpi_read_binary_le(&E, (uint8_t *)&info->E, 4);
  mbedtls_rsa_init(&rsa, MBEDTLS_RSA_PKCS_V15, 0);
  mbedtls_rsa_import(&rsa, &N, NULL, NULL, NULL, &E);
  sig = get_rsa_signature(info);

  err = mbedtls_rsa_public(&rsa, sig, block);
  CHECK(err);

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
