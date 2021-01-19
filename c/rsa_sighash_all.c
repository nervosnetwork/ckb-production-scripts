// # rsa_sighash_all
// same as secp256k1_blake2b_sighash_all_dual but with RSA (mbedtls)
//#define CKB_C_STDLIB_PRINTF
//#include <stdio.h>
#ifndef ASSERT
#define ASSERT(s) (void)0
#endif

#include "rsa_sighash_all.h"

#include <string.h>

#include "blake2b.h"
#include "blockchain.h"
#include "mbedtls/ecdsa.h"
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

int mbedtls_hardware_poll(void *data, unsigned char *output, size_t len,
                          size_t *olen) {
  return 0;
}
/**
 * Note: there is no prefilled data for RSA, it's only be used in secp256k1.
 * Always succeed.
 * @param data
 * @param len
 * @return
 */
__attribute__((visibility("default"))) int load_prefilled_data(void *data,
                                                               size_t *len) {
  (void)data;
  *len = 0;
  return CKB_SUCCESS;
}

uint8_t *get_rsa_signature(RsaInfo *info) {
  int length = info->key_size / 8;
  return (uint8_t *)&info->N[length];
}

uint32_t calculate_rsa_info_length(int key_size) { return 12 + key_size / 4; }

/**
 *
 * @param prefilled_data ignore. Not used.
 * @param signature_buffer pointer to signature buffer. It is casted to type
 * "RsaInfo*"
 * @param signature_size size of signature_buffer. it should be exactly the same
 * as size of "RsaInfo".
 * @param message_buffer pointer to message buffer.
 * @param message_size size of message_buffer.
 * @param output ignore. Not used
 * @param output_len ignore. Not used.
 * @return
 */
int validate_signature_rsa(void *prefilled_data,
                           const uint8_t *signature_buffer,
                           size_t signature_size, const uint8_t *msg_buf,
                           size_t msg_size, uint8_t *output,
                           size_t *output_len) {
  (void)prefilled_data;
  int ret;
  int err = ERROR_RSA_ONLY_INIT;
  uint8_t hash_buf[32] = {0};
  uint32_t hash_size = 0;

  mbedtls_rsa_context rsa;
  RsaInfo *input_info = (RsaInfo *)signature_buffer;

  // for key size with 1024 and 2048 bits, it uses up to 7K bytes.
  int alloc_buff_size = 1024 * 7;
  // for key size with 4096 bits, it uses 12K bytes at most.
  if (input_info->key_size > 2048) alloc_buff_size = 1024 * 12;
  unsigned char alloc_buff[alloc_buff_size];
  mbedtls_memory_buffer_alloc_init(alloc_buff, alloc_buff_size);

  mbedtls_rsa_init(&rsa, MBEDTLS_RSA_PKCS_V15, 0);
  CHECK2(input_info->key_size == RSA_VALID_KEY_SIZE1 ||
             input_info->key_size == RSA_VALID_KEY_SIZE2 ||
             input_info->key_size == RSA_VALID_KEY_SIZE3,
         ERROR_RSA_INVALID_KEY_SIZE);
  CHECK2(signature_buffer != NULL, ERROR_RSA_INVALID_PARAM1);
  CHECK2(msg_buf != NULL, ERROR_RSA_INVALID_PARAM1);
  CHECK2(
      signature_size == (size_t)calculate_rsa_info_length(input_info->key_size),
      ERROR_RSA_INVALID_PARAM2);
  CHECK2(*output_len >= BLAKE160_SIZE, ERROR_RSA_INVALID_BLADE2B_SIZE);

  mbedtls_mpi_read_binary_le(&rsa.E, (const unsigned char *)&input_info->E,
                             sizeof(uint32_t));
  mbedtls_mpi_read_binary_le(&rsa.N, input_info->N, input_info->key_size / 8);
  rsa.len = (mbedtls_mpi_bitlen(&rsa.N) + 7) >> 3;

  ret = md_string(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), msg_buf,
                  msg_size, hash_buf);
  CHECK(ret);

  ret = mbedtls_rsa_pkcs1_verify(&rsa, NULL, NULL, MBEDTLS_RSA_PUBLIC,
                                 MBEDTLS_MD_SHA256, hash_size, hash_buf,
                                 get_rsa_signature(input_info));
  if (ret != 0) {
    mbedtls_printf("mbedtls_rsa_pkcs1_verify returned -0x%0x\n",
                   (unsigned int)-ret);
    err = ERROR_RSA_VERIFY_FAILED;
    goto exit;
  }

  blake2b_state blake2b_ctx;
  blake2b_init(&blake2b_ctx, BLAKE2B_BLOCK_SIZE);
  // pub key hash = blake2b(key size + E + N)
  // here pub key = E+N
  blake2b_update(&blake2b_ctx, input_info, 8 + input_info->key_size / 8);
  unsigned char blake2b_hash[BLAKE2B_BLOCK_SIZE] = {0};
  blake2b_final(&blake2b_ctx, blake2b_hash, BLAKE2B_BLOCK_SIZE);

  *output_len = BLAKE160_SIZE;
  memcpy(output, blake2b_hash, BLAKE160_SIZE);

  err = CKB_SUCCESS;

exit:
  if (err != CKB_SUCCESS) {
    mbedtls_printf("validate_signature_rsa() failed.\n");
  }
  mbedtls_rsa_free(&rsa);
  return err;
}

int serialize_secp256r1info(const mbedtls_ecp_point *Q, const mbedtls_mpi *r,
                            mbedtls_mpi *s, Secp256r1Info *info) {
  int err = 0;

  err = mbedtls_mpi_write_binary_le(&Q->X, info->public_key,
                                    SECP256R1_PUBLIC_KEY_SIZE / 2);
  CHECK(err);
  err = mbedtls_mpi_write_binary_le(
      &Q->Y, info->public_key + SECP256R1_PUBLIC_KEY_SIZE / 2,
      SECP256R1_PUBLIC_KEY_SIZE / 2);
  CHECK(err);

  err = mbedtls_mpi_write_binary_le(r, info->sig, SECP256R1_SIG_SIZE / 2);
  CHECK(err);
  err = mbedtls_mpi_write_binary_le(s, info->sig + SECP256R1_SIG_SIZE / 2,
                                    SECP256R1_SIG_SIZE / 2);
  CHECK(err);

  err = CKB_SUCCESS;

exit:
  return err;
}

int deserialize_secp256r1info(mbedtls_ecp_point *Q, mbedtls_mpi *r,
                              mbedtls_mpi *s, const Secp256r1Info *info) {
  int err = 0;
  mbedtls_ecp_point_init(Q);
  mbedtls_mpi_init(r);
  mbedtls_mpi_init(s);

  err = mbedtls_mpi_read_binary_le(&Q->X, info->public_key,
                                   SECP256R1_PUBLIC_KEY_SIZE / 2);
  CHECK(err);
  err = mbedtls_mpi_read_binary_le(
      &Q->Y, info->public_key + SECP256R1_PUBLIC_KEY_SIZE / 2,
      SECP256R1_PUBLIC_KEY_SIZE / 2);
  CHECK(err);

  const uint32_t one = 1;
  err = mbedtls_mpi_read_binary_le(&Q->Z, (const unsigned char *)&one, 4);
  CHECK(err);

  err = mbedtls_mpi_read_binary_le(r, info->sig, SECP256R1_SIG_SIZE / 2);
  CHECK(err);
  err = mbedtls_mpi_read_binary_le(s, info->sig + SECP256R1_SIG_SIZE / 2,
                                   SECP256R1_SIG_SIZE / 2);
  CHECK(err);

  err = CKB_SUCCESS;
exit:
  return err;
}

int validate_signature_secp256r1(void *prefilled_data,
                                 const uint8_t *signature_buffer,
                                 size_t signature_size,
                                 const uint8_t *hash_buff, size_t hash_size,
                                 uint8_t *output, size_t *output_len) {
  (void)prefilled_data;
  (void)output;
  (void)output_len;
  int err = 0;
  int id = MBEDTLS_ECP_DP_SECP256R1;
  mbedtls_ecp_group grp;
  int alloc_buff_size = 700 * 1024;

  unsigned char alloc_buff[alloc_buff_size];
  mbedtls_memory_buffer_alloc_init(alloc_buff, alloc_buff_size);

  const Secp256r1Info *info = (Secp256r1Info *)signature_buffer;
  CHECK2(signature_size == sizeof(Secp256r1Info), ERROR_RSA_INVALID_PARAM1);
  CHECK2(hash_size == 32, ERROR_RSA_INVALID_PARAM1);

  mbedtls_ecp_group_init(&grp);
  err = mbedtls_ecp_group_load(&grp, id);
  CHECK(err);

  mbedtls_ecp_point Q;
  mbedtls_mpi r;
  mbedtls_mpi s;
  err = deserialize_secp256r1info(&Q, &r, &s, info);
  CHECK(err);

  err = mbedtls_ecdsa_verify(&grp, hash_buff, hash_size, &Q, &r, &s);
  CHECK(err);

  err = CKB_SUCCESS;
exit:
  return err;
}

/**
 * entry for different algorithms
 * The fist byte of signature_buffer is the id of algorithm, it can be:
 * #define CKB_VERIFY_RSA 1
 * #define CKB_VERIFY_SECP256R1 2
 */
__attribute__((visibility("default"))) int validate_signature(
    void *prefilled_data, const uint8_t *sig_buf, size_t sig_len,
    const uint8_t *msg_buf, size_t msg_len, uint8_t *output,
    size_t *output_len) {
  if (sig_buf == NULL) {
    ASSERT(0);
    return ERROR_RSA_INVALID_PARAM1;
  }
  uint32_t id = ((RsaInfo *)sig_buf)->algorithm_id;

  if (id == CKB_VERIFY_RSA) {
    return validate_signature_rsa(prefilled_data, sig_buf, sig_len, msg_buf,
                                  msg_len, output, output_len);
  } else if (id == CKB_VERIFY_SECP256R1) {
    // disable the entry of secp256r1 because the cycles is too high and can't
    // be used. to reduce code size.
    //    return validate_signature_secp256r1(prefilled_data, sig_buf, sig_len,
    //                                        msg_buf, msg_len, output,
    //                                        output_len);
    return ERROR_RSA_NOT_IMPLEMENTED;
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

int load_public_key_hash(unsigned char *public_key) {
  int ret;
  uint64_t len = 0;

  /* Load args */
  unsigned char script[SCRIPT_SIZE];
  len = SCRIPT_SIZE;
  ret = ckb_load_script(script, &len, 0);
  if (ret != CKB_SUCCESS) {
    return ERROR_SYSCALL;
  }
  if (len > SCRIPT_SIZE) {
    return ERROR_SCRIPT_TOO_LONG;
  }
  mol_seg_t script_seg;
  script_seg.ptr = (uint8_t *)script;
  script_seg.size = len;

  if (MolReader_Script_verify(&script_seg, false) != MOL_OK) {
    return ERROR_ENCODING;
  }

  mol_seg_t args_seg = MolReader_Script_get_args(&script_seg);
  mol_seg_t args_bytes_seg = MolReader_Bytes_raw_bytes(&args_seg);
  if (args_bytes_seg.size != PUBLIC_KEY_SIZE1) {
    return ERROR_WRONG_SCRIPT_ARGS_LEN;
  }
  memcpy(public_key, args_bytes_seg.ptr, args_bytes_seg.size);
  return CKB_SUCCESS;
}

int md_string(const mbedtls_md_info_t *md_info, const uint8_t *buf, size_t n,
              unsigned char *output) {
  int ret = -1;
  mbedtls_md_context_t ctx;

  if (md_info == NULL) return (MBEDTLS_ERR_MD_BAD_INPUT_DATA);

  mbedtls_md_init(&ctx);

  if ((ret = mbedtls_md_setup(&ctx, md_info, 0)) != 0) goto cleanup;

  if ((ret = mbedtls_md_starts(&ctx)) != 0) goto cleanup;

  if ((ret = mbedtls_md_update(&ctx, (const unsigned char *)buf, n)) != 0)
    goto cleanup;

  ret = mbedtls_md_finish(&ctx, output);

cleanup:
  mbedtls_md_free(&ctx);
  return ret;
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

  uint32_t key_size = ((RsaInfo *)lock_bytes_seg.ptr)->key_size;
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

mbedtls_md_type_t get_md_by_trailer(uint16_t trailer) {
  if (trailer == TRAILER_IMPLICIT) {
    return MBEDTLS_MD_NONE;
  } else if (trailer == TRAILER_SHA1) {
    return MBEDTLS_MD_SHA1;
  } else if (trailer == TRAILER_SHA224) {
    return MBEDTLS_MD_SHA224;
  } else if (trailer == TRAILER_SHA256) {
    return MBEDTLS_MD_SHA256;
  } else if (trailer == TRAILER_SHA384) {
    return MBEDTLS_MD_SHA384;
  } else if (trailer == TRAILER_SHA512) {
    return MBEDTLS_MD_SHA512;
  } else if (trailer == TRAILER_RIPEMD160) {
    return MBEDTLS_MD_RIPEMD160;
  } else {
    ASSERT(false);
    return MBEDTLS_MD_NONE;
  }
}

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

void iso97962_init(ISO97962Encoding *enc, uint32_t key_size,
                   mbedtls_md_type_t md, bool implicity) {
  enc->key_size = key_size;
  enc->md = md;
  enc->implicity = implicity;

  enc->trailer = get_trailer_by_md(md);
}

int iso97962_sign(ISO97962Encoding *enc, uint8_t *msg, int msg_len,
                  uint8_t *block, int block_len) {
  int err = 0;
  const mbedtls_md_info_t *digest = mbedtls_md_info_from_type(enc->md);
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

int iso97962_verify(ISO97962Encoding *enc, const uint8_t *block,
                    uint32_t block_len, const uint8_t *origin,
                    uint32_t origin_len, uint8_t *msg, uint32_t *msg_len) {
  int err = 0;
  const mbedtls_md_info_t *digest = mbedtls_md_info_from_type(enc->md);
  int hash_len = digest->size;
  uint8_t hash[hash_len];
  int alloc_buff_size = 1024 * 1024;
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

  uint32_t key_size = info->key_size / 8;  // in byte
  uint8_t *sig = NULL;
  uint8_t block[key_size];
  uint8_t m1[key_size];
  uint32_t m1_len = key_size;
  uint8_t full_msg[key_size * 2];
  uint8_t new_msg[key_size * 2];
  uint32_t new_msg_len = key_size;

  int alloc_buff_size = 1024 * 1024;
  unsigned char alloc_buff[alloc_buff_size];
  mbedtls_memory_buffer_alloc_init(alloc_buff, alloc_buff_size);

  CHECK2(msg_buf != NULL, ERROR_ISO97962_INVALID_ARG8);
  CHECK2(out != NULL, ERROR_ISO97962_INVALID_ARG8);
  CHECK2(out_len != NULL, ERROR_ISO97962_INVALID_ARG8);
  CHECK2(key_size > 0, ERROR_ISO97962_INVALID_ARG8);

  mbedtls_mpi_init(&N);
  mbedtls_mpi_init(&E);

  mbedtls_mpi_read_binary_le(&N, (uint8_t *)info->N, key_size);
  mbedtls_mpi_read_binary_le(&E, (uint8_t *)&info->E, 4);
  mbedtls_rsa_init(&rsa, MBEDTLS_RSA_PKCS_V15, 0);
  mbedtls_rsa_import(&rsa, &N, NULL, NULL, NULL, &E);
  sig = get_rsa_signature(info);

  err = mbedtls_rsa_public(&rsa, sig, block);
  CHECK(err);

  ISO97962Encoding enc = {0};
  iso97962_init(&enc, 1024, MBEDTLS_MD_SHA1, false);
  err = iso97962_verify(&enc, block, key_size, msg_buf, msg_len, m1, &m1_len);
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
