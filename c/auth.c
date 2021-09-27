
// clang-format off
#include "mbedtls/md.h"

#include "ckb_consts.h"
#if defined(CKB_USE_SIM)
// exclude ckb_dlfcn.h
#define CKB_C_STDLIB_CKB_DLFCN_H_
#include "ckb_syscall_auth_sim.h"
#else
#include "ckb_syscalls.h"
#endif

#include "ckb_keccak256.h"
#include "secp256k1_helper.h"

#include "ckb_auth.h"
#include "validate_signature_rsa.h"
// secp256k1 also defines this macros
#undef CHECK2
#undef CHECK
#include "validate_signature_rsa.c"
#include "ckb_exec.h"
// clang-format on

#define CKB_AUTH_LEN 21
#define BLAKE160_SIZE 20
#define BLAKE2B_BLOCK_SIZE 32
#define SECP256K1_PUBKEY_SIZE 33
#define UNCOMPRESSED_SECP256K1_PUBKEY_SIZE 65
#define SECP256K1_SIGNATURE_SIZE 65
#define SECP256K1_MESSAGE_SIZE 32
#define RECID_INDEX 64
#define SHA256_SIZE 32
#define RIPEMD160_SIZE 20

enum AuthErrorCodeType {
  ERROR_NOT_IMPLEMENTED = 100,
  ERROR_MISMATCHED,
  ERROR_INVALID_ARG,
  ERROR_WRONG_STATE,
  // exec
  ERROR_EXEC_INVALID_LENGTH,
  ERROR_EXEC_INVALID_PARAM,
  ERROR_EXEC_NOT_PAIRED,
  ERROR_EXEC_INVALID_SIG,
  ERROR_EXEC_INVALID_MSG
};

typedef int (*validate_signature_t)(void *prefilled_data, const uint8_t *sig,
                                    size_t sig_len, const uint8_t *msg,
                                    size_t msg_len, uint8_t *output,
                                    size_t *output_len);

typedef int (*convert_msg_t)(const uint8_t *msg, size_t msg_len,
                             uint8_t *new_msg, size_t new_msg_len);

static int _recover_secp256k1_pubkey(const uint8_t *sig, size_t sig_len,
                                     const uint8_t *msg, size_t msg_len,
                                     uint8_t *out_pubkey,
                                     size_t *out_pubkey_size, bool compressed) {
  int ret = 0;

  if (sig_len != SECP256K1_SIGNATURE_SIZE) {
    return ERROR_INVALID_ARG;
  }
  if (msg_len != SECP256K1_MESSAGE_SIZE) {
    return ERROR_INVALID_ARG;
  }

  /* Load signature */
  secp256k1_context context;
  uint8_t secp_data[CKB_SECP256K1_DATA_SIZE];
  ret = ckb_secp256k1_custom_verify_only_initialize(&context, secp_data);
  if (ret != 0) {
    return ret;
  }

  secp256k1_ecdsa_recoverable_signature signature;
  if (secp256k1_ecdsa_recoverable_signature_parse_compact(
          &context, &signature, sig, sig[RECID_INDEX]) == 0) {
    return ERROR_WRONG_STATE;
  }

  /* Recover pubkey */
  secp256k1_pubkey pubkey;
  if (secp256k1_ecdsa_recover(&context, &pubkey, &signature, msg) != 1) {
    return ERROR_WRONG_STATE;
  }

  unsigned int flag = SECP256K1_EC_COMPRESSED;
  if (compressed) {
    *out_pubkey_size = SECP256K1_PUBKEY_SIZE;
    flag = SECP256K1_EC_COMPRESSED;
  } else {
    *out_pubkey_size = UNCOMPRESSED_SECP256K1_PUBKEY_SIZE;
    flag = SECP256K1_EC_UNCOMPRESSED;
  }
  if (secp256k1_ec_pubkey_serialize(&context, out_pubkey, out_pubkey_size,
                                    &pubkey, flag) != 1) {
    return ERROR_WRONG_STATE;
  }
  return ret;
}

static int _recover_secp256k1_pubkey_btc(const uint8_t *sig, size_t sig_len,
                                         const uint8_t *msg, size_t msg_len,
                                         uint8_t *out_pubkey,
                                         size_t *out_pubkey_size,
                                         bool compressed) {
  (void)compressed;
  int ret = 0;

  if (sig_len != SECP256K1_SIGNATURE_SIZE) {
    return ERROR_INVALID_ARG;
  }
  if (msg_len != SECP256K1_MESSAGE_SIZE) {
    return ERROR_INVALID_ARG;
  }

  // change 1
  int recid = (sig[0] - 27) & 3;
  bool comp = ((sig[0] - 27) & 4) != 0;

  /* Load signature */
  secp256k1_context context;
  uint8_t secp_data[CKB_SECP256K1_DATA_SIZE];
  ret = ckb_secp256k1_custom_verify_only_initialize(&context, secp_data);
  if (ret != 0) {
    return ret;
  }

  secp256k1_ecdsa_recoverable_signature signature;
  // change 2,3
  if (secp256k1_ecdsa_recoverable_signature_parse_compact(
          &context, &signature, sig + 1, recid) == 0) {
    return ERROR_WRONG_STATE;
  }

  /* Recover pubkey */
  secp256k1_pubkey pubkey;
  if (secp256k1_ecdsa_recover(&context, &pubkey, &signature, msg) != 1) {
    return ERROR_WRONG_STATE;
  }

  unsigned int flag = SECP256K1_EC_COMPRESSED;
  if (comp) {
    *out_pubkey_size = SECP256K1_PUBKEY_SIZE;
    flag = SECP256K1_EC_COMPRESSED;
  } else {
    *out_pubkey_size = UNCOMPRESSED_SECP256K1_PUBKEY_SIZE;
    flag = SECP256K1_EC_UNCOMPRESSED;
  }
  // change 4
  if (secp256k1_ec_pubkey_serialize(&context, out_pubkey, out_pubkey_size,
                                    &pubkey, flag) != 1) {
    return ERROR_WRONG_STATE;
  }
  return ret;
}

int validate_signature_ckb(void *prefilled_data, const uint8_t *sig,
                           size_t sig_len, const uint8_t *msg, size_t msg_len,
                           uint8_t *output, size_t *output_len) {
  int ret = 0;
  if (*output_len < BLAKE160_SIZE) {
    return ERROR_INVALID_ARG;
  }
  uint8_t out_pubkey[SECP256K1_PUBKEY_SIZE];
  size_t out_pubkey_size = SECP256K1_PUBKEY_SIZE;
  ret = _recover_secp256k1_pubkey(sig, sig_len, msg, msg_len, out_pubkey,
                                  &out_pubkey_size, true);
  if (ret != 0) return ret;

  blake2b_state ctx;
  blake2b_init(&ctx, BLAKE2B_BLOCK_SIZE);
  blake2b_update(&ctx, out_pubkey, out_pubkey_size);
  blake2b_final(&ctx, out_pubkey, BLAKE2B_BLOCK_SIZE);

  memcpy(output, out_pubkey, BLAKE160_SIZE);
  *output_len = BLAKE160_SIZE;

  return ret;
}

int validate_signature_eth(void *prefilled_data, const uint8_t *sig,
                           size_t sig_len, const uint8_t *msg, size_t msg_len,
                           uint8_t *output, size_t *output_len) {
  int ret = 0;
  if (*output_len < BLAKE160_SIZE) {
    return SECP256K1_PUBKEY_SIZE;
  }
  uint8_t out_pubkey[UNCOMPRESSED_SECP256K1_PUBKEY_SIZE];
  size_t out_pubkey_size = UNCOMPRESSED_SECP256K1_PUBKEY_SIZE;
  ret = _recover_secp256k1_pubkey(sig, sig_len, msg, msg_len, out_pubkey,
                                  &out_pubkey_size, false);
  if (ret != 0) return ret;

  // here are the 2 differences than validate_signature_secp256k1
  SHA3_CTX sha3_ctx;
  keccak_init(&sha3_ctx);
  keccak_update(&sha3_ctx, &out_pubkey[1], out_pubkey_size - 1);
  keccak_final(&sha3_ctx, out_pubkey);

  memcpy(output, &out_pubkey[12], BLAKE160_SIZE);
  *output_len = BLAKE160_SIZE;

  return ret;
}

int validate_signature_btc(void *prefilled_data, const uint8_t *sig,
                           size_t sig_len, const uint8_t *msg, size_t msg_len,
                           uint8_t *output, size_t *output_len) {
  int err = 0;
  if (*output_len < BLAKE160_SIZE) {
    return SECP256K1_PUBKEY_SIZE;
  }
  uint8_t out_pubkey[UNCOMPRESSED_SECP256K1_PUBKEY_SIZE];
  size_t out_pubkey_size = UNCOMPRESSED_SECP256K1_PUBKEY_SIZE;
  err = _recover_secp256k1_pubkey_btc(sig, sig_len, msg, msg_len, out_pubkey,
                                      &out_pubkey_size, false);
  CHECK(err);

  const mbedtls_md_info_t *md_info =
      mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  unsigned char temp[SHA256_SIZE];
  err = md_string(md_info, out_pubkey, out_pubkey_size, temp);
  CHECK(err);

  md_info = mbedtls_md_info_from_type(MBEDTLS_MD_RIPEMD160);
  err = md_string(md_info, temp, SHA256_SIZE, temp);
  CHECK(err);

  memcpy(output, temp, BLAKE160_SIZE);
  *output_len = BLAKE160_SIZE;

exit:
  return err;
}

int convert_copy(const uint8_t *msg, size_t msg_len, uint8_t *new_msg,
                 size_t new_msg_len) {
  if (msg_len != new_msg_len || msg_len != BLAKE2B_BLOCK_SIZE)
    return ERROR_INVALID_ARG;
  memcpy(new_msg, msg, msg_len);
  return 0;
}

int convert_eth_message(const uint8_t *msg, size_t msg_len, uint8_t *new_msg,
                        size_t new_msg_len) {
  if (msg_len != new_msg_len || msg_len != BLAKE2B_BLOCK_SIZE)
    return ERROR_INVALID_ARG;

  SHA3_CTX sha3_ctx;
  keccak_init(&sha3_ctx);
  /* personal hash, ethereum prefix  \u0019Ethereum Signed Message:\n32  */
  unsigned char eth_prefix[28];
  eth_prefix[0] = 0x19;
  memcpy(eth_prefix + 1, "Ethereum Signed Message:\n32", 27);

  keccak_update(&sha3_ctx, eth_prefix, 28);
  keccak_update(&sha3_ctx, (unsigned char *)msg, 32);
  keccak_final(&sha3_ctx, new_msg);
  return 0;
}

int convert_tron_message(const uint8_t *msg, size_t msg_len, uint8_t *new_msg,
                         size_t new_msg_len) {
  if (msg_len != new_msg_len || msg_len != BLAKE2B_BLOCK_SIZE)
    return ERROR_INVALID_ARG;

  SHA3_CTX sha3_ctx;
  keccak_init(&sha3_ctx);
  /* ASCII code for tron prefix \x19TRON Signed Message:\n32, refer
   * https://github.com/tronprotocol/tips/issues/104 */
  unsigned char tron_prefix[24];
  tron_prefix[0] = 0x19;
  memcpy(tron_prefix + 1, "TRON Signed Message:\n32", 23);

  keccak_update(&sha3_ctx, tron_prefix, 24);
  keccak_update(&sha3_ctx, (unsigned char *)msg, 32);
  keccak_final(&sha3_ctx, new_msg);
  return 0;
}

static void bin_to_hex(const uint8_t *source, uint8_t *dest, size_t len) {
  const static uint8_t HEX_TABLE[] = {'0', '1', '2', '3', '4', '5', '6', '7',
                                      '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
  for (int i = 0; i < len; i++) {
    dest[i * 2] = HEX_TABLE[source[i] >> 4];
    dest[i * 2 + 1] = HEX_TABLE[source[i] & 0x0F];
  }
}

static void split_hex_hash(const uint8_t *source, unsigned char *dest) {
  int i;
  char hex_chars[] = "0123456789abcdef";

  for (i = 0; i < BLAKE2B_BLOCK_SIZE; i++) {
    if (i > 0 && i % 6 == 0) {
      *(dest++) = ' ';
    }
    *(dest++) = hex_chars[source[i] / 16];
    *(dest++) = hex_chars[source[i] % 16];
  }
}

int convert_eos_message(const uint8_t *msg, size_t msg_len, uint8_t *new_msg,
                        size_t new_msg_len) {
  int err = 0;
  if (msg_len != new_msg_len || msg_len != BLAKE2B_BLOCK_SIZE)
    return ERROR_INVALID_ARG;
  int split_message_len = BLAKE2B_BLOCK_SIZE * 2 + 5;
  unsigned char splited_message[split_message_len];
  /* split message to words length <= 12 */
  split_hex_hash(msg, splited_message);

  const mbedtls_md_info_t *md_info =
      mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

  err = md_string(md_info, msg, msg_len, new_msg);
  if (err != 0) return err;
  return 0;
}

#define MESSAGE_HEX_LEN 64
const char BTC_MESSAGE_MAGIC[25] = "Bitcoin Signed Message:\n";
const int8_t BTC_MAGIC_LEN = 24;

int convert_btc_message(const uint8_t *msg, size_t msg_len, uint8_t *new_msg,
                        size_t new_msg_len) {
  int err = 0;
  if (msg_len != new_msg_len || msg_len != SHA256_SIZE)
    return ERROR_INVALID_ARG;

  uint8_t temp[MESSAGE_HEX_LEN];
  bin_to_hex(msg, temp, 32);

  // len of magic + magic string + len of message, size is 26 Byte
  uint8_t magic[BTC_MAGIC_LEN + 2];
  magic[0] = BTC_MAGIC_LEN;  // MESSAGE_MAGIC length
  memcpy(&magic[1], BTC_MESSAGE_MAGIC, BTC_MAGIC_LEN);
  magic[25] = MESSAGE_HEX_LEN;  // message length

  const mbedtls_md_info_t *md_info =
      mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

  /* Calculate signature message */
  uint8_t temp2[BTC_MAGIC_LEN + 2 + MESSAGE_HEX_LEN];
  uint32_t temp2_size = BTC_MAGIC_LEN + 2 + MESSAGE_HEX_LEN;
  memcpy(temp2, magic, BTC_MAGIC_LEN + 2);
  memcpy(temp2 + BTC_MAGIC_LEN + 2, temp, MESSAGE_HEX_LEN);
  err = md_string(md_info, temp2, temp2_size, new_msg);
  if (err != 0) return err;
  err = md_string(md_info, new_msg, SHA256_SIZE, new_msg);
  if (err != 0) return err;
  return 0;
}

const char DOGE_MESSAGE_MAGIC[26] = "Dogecoin Signed Message:\n";
const int8_t DOGE_MAGIC_LEN = 25;

int convert_doge_message(const uint8_t *msg, size_t msg_len, uint8_t *new_msg,
                         size_t new_msg_len) {
  int err = 0;
  if (msg_len != new_msg_len || msg_len != SHA256_SIZE)
    return ERROR_INVALID_ARG;

  uint8_t temp[MESSAGE_HEX_LEN];
  bin_to_hex(msg, temp, 32);

  // len of magic + magic string + len of message, size is 27 Byte
  uint8_t magic[DOGE_MAGIC_LEN + 2];
  magic[0] = DOGE_MAGIC_LEN;
  memcpy(&magic[1], DOGE_MESSAGE_MAGIC, DOGE_MAGIC_LEN);
  magic[26] = MESSAGE_HEX_LEN;

  const mbedtls_md_info_t *md_info =
      mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

  /* Calculate signature message */
  uint8_t temp2[DOGE_MAGIC_LEN + 2 + MESSAGE_HEX_LEN];
  uint32_t temp2_size = DOGE_MAGIC_LEN + 2 + MESSAGE_HEX_LEN;
  memcpy(temp2, magic, DOGE_MAGIC_LEN + 2);
  memcpy(temp2 + DOGE_MAGIC_LEN + 2, temp, MESSAGE_HEX_LEN);
  err = md_string(md_info, temp2, temp2_size, new_msg);
  if (err != 0) return err;
  err = md_string(md_info, new_msg, SHA256_SIZE, new_msg);
  if (err != 0) return 0;
  return 0;
}

bool is_lock_script_hash_present(uint8_t *lock_script_hash) {
  int err = 0;
  size_t i = 0;
  while (true) {
    uint8_t buff[BLAKE2B_BLOCK_SIZE];
    uint64_t len = BLAKE2B_BLOCK_SIZE;
    err = ckb_checked_load_cell_by_field(buff, &len, 0, i, CKB_SOURCE_INPUT,
                                         CKB_CELL_FIELD_LOCK_HASH);
    if (err == CKB_INDEX_OUT_OF_BOUND) {
      break;
    }
    if (err != 0) {
      break;
    }

    if (memcmp(lock_script_hash, buff, BLAKE160_SIZE) == 0) {
      return true;
    }
    i += 1;
  }
  return false;
}

static int verify(uint8_t *pubkey_hash, const uint8_t *sig, uint32_t sig_len,
                  const uint8_t *msg, uint32_t msg_len,
                  validate_signature_t func, convert_msg_t convert) {
  int err = 0;
  uint8_t new_msg[BLAKE2B_BLOCK_SIZE];

  // for md_string
  unsigned char alloc_buff[1024];
  mbedtls_memory_buffer_alloc_init(alloc_buff, sizeof(alloc_buff));

  err = convert(msg, msg_len, new_msg, sizeof(new_msg));
  CHECK(err);

  uint8_t output_pubkey_hash[BLAKE160_SIZE];
  size_t output_len = BLAKE160_SIZE;
  err = func(NULL, sig, sig_len, new_msg, sizeof(new_msg), output_pubkey_hash,
             &output_len);
  CHECK(err);

  int same = memcmp(pubkey_hash, output_pubkey_hash, BLAKE160_SIZE);
  CHECK2(same == 0, ERROR_MISMATCHED);

exit:
  return err;
}

// origin:
// https://github.com/nervosnetwork/ckb-system-scripts/blob/master/c/secp256k1_blake160_multisig_all.c
// Script args validation errors
#define ERROR_INVALID_RESERVE_FIELD -41
#define ERROR_INVALID_PUBKEYS_CNT -42
#define ERROR_INVALID_THRESHOLD -43
#define ERROR_INVALID_REQUIRE_FIRST_N -44
// Multi-sigining validation errors
#define ERROR_MULTSIG_SCRIPT_HASH -51
#define ERROR_VERIFICATION -52
#define ERROR_WITNESS_SIZE -22
#define ERROR_SECP_PARSE_SIGNATURE -14
#define ERROR_SECP_RECOVER_PUBKEY -11
#define ERROR_SECP_SERIALIZE_PUBKEY -15

#define FLAGS_SIZE 4
#define SIGNATURE_SIZE 65
#define PUBKEY_SIZE 33

int verify_multisig(const uint8_t *lock_bytes, size_t lock_bytes_len,
                    const uint8_t *message, const uint8_t *hash) {
  int ret;
  uint8_t temp[BLAKE2B_BLOCK_SIZE];

  // Extract multisig script flags.
  uint8_t pubkeys_cnt = lock_bytes[3];
  uint8_t threshold = lock_bytes[2];
  uint8_t require_first_n = lock_bytes[1];
  uint8_t reserved_field = lock_bytes[0];
  if (reserved_field != 0) {
    return ERROR_INVALID_RESERVE_FIELD;
  }
  if (pubkeys_cnt == 0) {
    return ERROR_INVALID_PUBKEYS_CNT;
  }
  if (threshold > pubkeys_cnt) {
    return ERROR_INVALID_THRESHOLD;
  }
  if (threshold == 0) {
    return ERROR_INVALID_THRESHOLD;
  }
  if (require_first_n > threshold) {
    return ERROR_INVALID_REQUIRE_FIRST_N;
  }
  // Based on the number of public keys and thresholds, we can calculate
  // the required length of the lock field.
  size_t multisig_script_len = FLAGS_SIZE + BLAKE160_SIZE * pubkeys_cnt;
  size_t signatures_len = SIGNATURE_SIZE * threshold;
  size_t required_lock_len = multisig_script_len + signatures_len;
  if (lock_bytes_len != required_lock_len) {
    return ERROR_WITNESS_SIZE;
  }

  // Perform hash check of the `multisig_script` part, notice the signature part
  // is not included here.
  blake2b_state blake2b_ctx;
  blake2b_init(&blake2b_ctx, BLAKE2B_BLOCK_SIZE);
  blake2b_update(&blake2b_ctx, lock_bytes, multisig_script_len);
  blake2b_final(&blake2b_ctx, temp, BLAKE2B_BLOCK_SIZE);

  if (memcmp(hash, temp, BLAKE160_SIZE) != 0) {
    return ERROR_MULTSIG_SCRIPT_HASH;
  }

  // Verify threshold signatures, threshold is a uint8_t, at most it is
  // 255, meaning this array will definitely have a reasonable upper bound.
  // Also this code uses C99's new feature to allocate a variable length array.
  uint8_t used_signatures[threshold];
  memset(used_signatures, 0, threshold);

  // We are using bitcoin's [secp256k1
  // library](https://github.com/bitcoin-core/secp256k1) for signature
  // verification here. To the best of our knowledge, this is an unmatched
  // advantage of CKB: you can ship cryptographic algorithm within your smart
  // contract, you don't have to wait for the foundation to ship a new
  // cryptographic algorithm. You can just build and ship your own.
  secp256k1_context context;
  uint8_t secp_data[CKB_SECP256K1_DATA_SIZE];
  ret = ckb_secp256k1_custom_verify_only_initialize(&context, secp_data);
  if (ret != 0) return ret;

  // We will perform *threshold* number of signature verifications here.
  for (size_t i = 0; i < threshold; i++) {
    // Load signature
    secp256k1_ecdsa_recoverable_signature signature;
    size_t signature_offset = multisig_script_len + i * SIGNATURE_SIZE;
    if (secp256k1_ecdsa_recoverable_signature_parse_compact(
            &context, &signature, &lock_bytes[signature_offset],
            lock_bytes[signature_offset + RECID_INDEX]) == 0) {
      return ERROR_SECP_PARSE_SIGNATURE;
    }

    // verify signature and Recover pubkey
    secp256k1_pubkey pubkey;
    if (secp256k1_ecdsa_recover(&context, &pubkey, &signature, message) != 1) {
      return ERROR_SECP_RECOVER_PUBKEY;
    }

    // Calculate the blake160 hash of the derived public key
    size_t pubkey_size = PUBKEY_SIZE;
    if (secp256k1_ec_pubkey_serialize(&context, temp, &pubkey_size, &pubkey,
                                      SECP256K1_EC_COMPRESSED) != 1) {
      return ERROR_SECP_SERIALIZE_PUBKEY;
    }

    unsigned char calculated_pubkey_hash[BLAKE2B_BLOCK_SIZE];
    blake2b_state blake2b_ctx;
    blake2b_init(&blake2b_ctx, BLAKE2B_BLOCK_SIZE);
    blake2b_update(&blake2b_ctx, temp, PUBKEY_SIZE);
    blake2b_final(&blake2b_ctx, calculated_pubkey_hash, BLAKE2B_BLOCK_SIZE);

    // Check if this signature is signed with one of the provided public key.
    uint8_t matched = 0;
    for (size_t i = 0; i < pubkeys_cnt; i++) {
      if (used_signatures[i] == 1) {
        continue;
      }
      if (memcmp(&lock_bytes[FLAGS_SIZE + i * BLAKE160_SIZE],
                 calculated_pubkey_hash, BLAKE160_SIZE) != 0) {
        continue;
      }
      matched = 1;
      used_signatures[i] = 1;
      break;
    }

    // If the signature doesn't match any of the provided public key, the script
    // will exit with an error.
    if (matched != 1) {
      return ERROR_VERIFICATION;
    }
  }

  // The above scheme just ensures that a *threshold* number of signatures have
  // successfully been verified, and they all come from the provided public
  // keys. However, the multisig script might also require some numbers of
  // public keys to always be signed for the script to pass verification. This
  // is indicated via the *required_first_n* flag. Here we also checks to see
  // that this rule is also satisfied.
  for (size_t i = 0; i < require_first_n; i++) {
    if (used_signatures[i] != 1) {
      return ERROR_VERIFICATION;
    }
  }

  return 0;
}

// dynamic linking entry
__attribute__((visibility("default"))) int ckb_auth_validate(
    uint8_t auth_algorithm_id, const uint8_t *signature,
    uint32_t signature_size, const uint8_t *message, uint32_t message_size,
    uint8_t *pubkey_hash, uint32_t pubkey_hash_size) {
  int err = 0;
  CHECK2(signature != NULL, ERROR_INVALID_ARG);
  CHECK2(message != NULL, ERROR_INVALID_ARG);
  CHECK2(message_size > 0, ERROR_INVALID_ARG);
  CHECK2(pubkey_hash_size == BLAKE160_SIZE, ERROR_INVALID_ARG);

  if (auth_algorithm_id == AuthAlgorithmIdCkb) {
    CHECK2(signature_size == SECP256K1_SIGNATURE_SIZE, ERROR_INVALID_ARG);
    err = verify(pubkey_hash, signature, signature_size, message, message_size,
                 validate_signature_ckb, convert_copy);
    CHECK(err);
  } else if (auth_algorithm_id == AuthAlgorithmIdEthereum) {
    CHECK2(signature_size == SECP256K1_SIGNATURE_SIZE, ERROR_INVALID_ARG);
    err = verify(pubkey_hash, signature, signature_size, message, message_size,
                 validate_signature_eth, convert_eth_message);
    CHECK(err);
  } else if (auth_algorithm_id == AuthAlgorithmIdEos) {
    CHECK2(signature_size == SECP256K1_SIGNATURE_SIZE, ERROR_INVALID_ARG);
    err = verify(pubkey_hash, signature, signature_size, message, message_size,
                 validate_signature_eth, convert_eos_message);
    CHECK(err);
  } else if (auth_algorithm_id == AuthAlgorithmIdTron) {
    CHECK2(signature_size == SECP256K1_SIGNATURE_SIZE, ERROR_INVALID_ARG);
    err = verify(pubkey_hash, signature, signature_size, message, message_size,
                 validate_signature_eth, convert_tron_message);
    CHECK(err);
  } else if (auth_algorithm_id == AuthAlgorithmIdBitcoin) {
    err = verify(pubkey_hash, signature, signature_size, message, message_size,
                 validate_signature_btc, convert_btc_message);
    CHECK(err);
  } else if (auth_algorithm_id == AuthAlgorithmIdDogecoin) {
    err = verify(pubkey_hash, signature, signature_size, message, message_size,
                 validate_signature_btc, convert_doge_message);
    CHECK(err);
  } else if (auth_algorithm_id == AuthAlgorithmIdCkbMultisig) {
    err = verify_multisig(signature, signature_size, message, pubkey_hash);
    CHECK(err);
  } else if (auth_algorithm_id == AuthAlgorithmIdSchnorr) {
    return ERROR_NOT_IMPLEMENTED;
  } else if (auth_algorithm_id == AuthAlgorithmIdRsa) {
    uint8_t hash[BLAKE160_SIZE];
    size_t len = BLAKE160_SIZE;
    err = validate_signature_rsa(NULL, signature, signature_size, message,
                                 message_size, hash, &len);
    CHECK(err);
    CHECK2(len == BLAKE160_SIZE, ERROR_WRONG_STATE);
    int same = memcmp(hash, pubkey_hash, BLAKE160_SIZE);
    CHECK2(same == 0, ERROR_MISMATCHED);
  } else if (auth_algorithm_id == AuthAlgorithmIdIso97962) {
    uint8_t hash[BLAKE160_SIZE];
    size_t len = BLAKE160_SIZE;
    err = validate_signature_iso9796_2_batch(NULL, signature, signature_size,
                                             message, message_size, hash, &len);
    CHECK(err);
    CHECK2(len == BLAKE160_SIZE, ERROR_WRONG_STATE);
    int same = memcmp(hash, pubkey_hash, BLAKE160_SIZE);
    CHECK2(same == 0, ERROR_MISMATCHED);
  } else if (auth_algorithm_id == AuthAlgorithmIdOwnerLock) {
    CHECK2(is_lock_script_hash_present(pubkey_hash), ERROR_MISMATCHED);
    err = 0;
  } else {
    CHECK2(false, ERROR_NOT_IMPLEMENTED);
  }
exit:
  return err;
}

#define MAX_ENTRY_SIZE 128
typedef struct ValidationEntry {
  uint8_t auth_algorithm_id;
  uint8_t *pubkey_hash;
  uint32_t pubkey_hash_len;

  uint8_t *msg;
  uint32_t msg_len;
  uint8_t *sig;
  uint32_t sig_len;
} ValidationEntry;

int chained_continue(int argc, char *argv[]) {
  int err = 0;
  char *next = NULL;
  uint8_t *param_ptr = NULL;
  uint32_t param_len = 0;

  size_t param_index = 0;
  uint8_t next_code_hash[32] = {0};

  // don't change argv[1] in place
  char argv1[256] = {0};
  size_t argv1_len = strlen(argv[1]);
  if (argv1_len >= 255) {
    memcpy(argv1, argv[1], 255);
  } else {
    memcpy(argv1, argv[1], argv1_len);
  }

  next = argv1;
  while (true) {
    CHECK2(next != NULL, ERROR_EXEC_INVALID_LENGTH);
    err = ckb_exec_decode_params(next, &param_ptr, &param_len, &next);
    CHECK(err);
    CHECK2(param_len > 0, ERROR_EXEC_INVALID_LENGTH);
    if (param_index == 0) {
      CHECK2(param_len == 32, ERROR_EXEC_INVALID_LENGTH);
      memcpy(next_code_hash, param_ptr, 32);
    } else if (param_index == 1) {
      CHECK2(param_len == 1, ERROR_EXEC_INVALID_LENGTH);
      return ckb_exec_cell(next_code_hash, *param_ptr, 0, 0, argc - 1,
                           (const char **)(argv + 1));
    }
    param_index++;
  }

exit:
  return err;
}

#ifdef CKB_USE_SIM
int simulator_main(int argc, char *argv[]) {
#else
// exec entry
__attribute__((visibility("default"))) int main(int argc, char *argv[]) {
#endif
  test_blake2b();
  int err = 0;
  uint8_t *param_ptr = NULL;
  uint32_t param_len = 0;

  if (argc <= 0) {
    return -1;
  }

  char *next = argv[0];
  size_t param_index = 0;
  ValidationEntry entries[MAX_ENTRY_SIZE] = {0};
  size_t entry_index = 0;
  while (true) {
    // pattern to use "ckb_exec_decode_params":
    // if next is NULL, in last iterator, it encounters \0.
    // when error is returned, there must be an error in call
    if (next == NULL) break;
    err = ckb_exec_decode_params(next, &param_ptr, &param_len, &next);
    CHECK(err);

    if (param_index == 0) {
      // code hash
      CHECK2(param_len == 32, ERROR_EXEC_INVALID_LENGTH);
    } else if (param_index == 1) {
      // hash type
      CHECK2(param_len == 1, ERROR_EXEC_INVALID_LENGTH);
    } else if ((param_index - 2) % 4 == 0) {
      // auth algorithm id
      CHECK2(param_len == 1, ERROR_EXEC_INVALID_LENGTH);
      entry_index = (param_index - 2) / 4;
      CHECK2(entry_index < MAX_ENTRY_SIZE, CKB_INDEX_OUT_OF_BOUND);
      entries[entry_index].auth_algorithm_id = *param_ptr;
    } else if ((param_index - 2) % 4 == 1) {
      // signature
      CHECK2(param_len > 0, ERROR_EXEC_INVALID_SIG);
      entry_index = (param_index - 2) / 4;
      CHECK2(entry_index < MAX_ENTRY_SIZE, CKB_INDEX_OUT_OF_BOUND);
      entries[entry_index].sig = param_ptr;
      entries[entry_index].sig_len = param_len;
    } else if ((param_index - 2) % 4 == 2) {
      // message
      CHECK2(param_len > 0, ERROR_EXEC_INVALID_MSG);
      entry_index = (param_index - 2) / 4;
      CHECK2(entry_index < MAX_ENTRY_SIZE, CKB_INDEX_OUT_OF_BOUND);
      entries[entry_index].msg = param_ptr;
      entries[entry_index].msg_len = param_len;
    } else if ((param_index - 2) % 4 == 3) {
      // pubkey hash
      CHECK2(param_len > 0, ERROR_EXEC_INVALID_LENGTH);
      entry_index = (param_index - 2) / 4;
      CHECK2(entry_index < MAX_ENTRY_SIZE, CKB_INDEX_OUT_OF_BOUND);
      entries[entry_index].pubkey_hash = param_ptr;
      entries[entry_index].pubkey_hash_len = param_len;
    } else {
      // code error
      CHECK2(false, ERROR_EXEC_INVALID_PARAM);
    }
    param_index++;
  }
  // All of sig, msg, pubkey_hash must be present
  CHECK2(entries[entry_index].sig_len > 0, ERROR_EXEC_NOT_PAIRED);
  CHECK2(entries[entry_index].pubkey_hash_len > 0, ERROR_EXEC_NOT_PAIRED);
  CHECK2(entries[entry_index].msg_len > 0, ERROR_EXEC_NOT_PAIRED);

  for (size_t i = 0; i <= entry_index; i++) {
    ValidationEntry *entry = entries + i;
    err = ckb_auth_validate(entry->auth_algorithm_id, entry->sig,
                            entry->sig_len, entry->msg, entry->msg_len,
                            entry->pubkey_hash, entry->pubkey_hash_len);
    CHECK(err);
  }

  if (argc > 1) {
    // The chained lock script would locate the cell using code hash and hash
    // type included in argv[1]. It will then remove argv[0] from argvs, then
    // use the remaining arguments to invoke exec syscall using binary provided
    // by the located cell.
    err = chained_continue(argc, argv);
    CHECK(err);
  }

exit:
  return err;
}
