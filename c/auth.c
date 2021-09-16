
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
#include "blockchain.h"

#include "ckb_auth.h"
#include "validate_signature_rsa.h"
// secp256k1 also defines this macros
#undef CHECK2
#undef CHECK
#include "validate_signature_rsa.c"
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

static int _convert_copy(const uint8_t *msg, size_t msg_len, uint8_t *new_msg,
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

// dynamic linking entry
int ckb_auth_validate(uint8_t auth_algorithm_id, const uint8_t *signature,
                      uint32_t signature_size, const uint8_t *message,
                      uint32_t message_size, uint8_t *pubkey_hash,
                      uint32_t pubkey_hash_size) {
  int err = 0;
  CHECK2(signature != NULL, ERROR_INVALID_ARG);
  CHECK2(message != NULL, ERROR_INVALID_ARG);
  CHECK2(message_size > 0, ERROR_INVALID_ARG);
  CHECK2(pubkey_hash_size == BLAKE160_SIZE, ERROR_INVALID_ARG);

  if (auth_algorithm_id == AuthAlgorithmIdCkb) {
    CHECK2(signature_size == SECP256K1_SIGNATURE_SIZE, ERROR_INVALID_ARG);
    err = verify(pubkey_hash, signature, signature_size, message, message_size,
                 validate_signature_ckb, _convert_copy);
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
    return validate_signature_iso9796_2_batch(
        NULL, signature, signature_size, message, message_size, hash, &len);
    CHECK(err);
    CHECK2(len == BLAKE160_SIZE, ERROR_WRONG_STATE);
    int same = memcmp(hash, pubkey_hash, BLAKE160_SIZE);
    CHECK2(same == 0, ERROR_MISMATCHED);
  } else {
    CHECK2(false, ERROR_NOT_IMPLEMENTED);
  }

exit:
  return err;
}

#ifdef CKB_USE_SIM
int simulator_main() {
#else
// exec entry
int main(int argc, char *argv[]) {
#endif
  return 0;
}
