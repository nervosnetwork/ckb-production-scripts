#ifndef CKB_C_STDLIB_CKB_IDENTITY_H_
#define CKB_C_STDLIB_CKB_IDENTITY_H_
#include <blake2b.h>
#include <ckb_exec.h>

#include "ckb_consts.h"
#include "ckb_keccak256.h"
#include "ripemd160.h"
#include "sha256.h"

#define CKB_IDENTITY_LEN 21
#define AUTH160_SIZE 20
#define SHA256_SIZE 32
#define RECID_INDEX 64
#define ONE_BATCH_SIZE 32768
#define PUBKEY_SIZE 33
#define SECP256K1_PUBKEY_SIZE 33
#define UNCOMPRESSED_SECP256K1_PUBKEY_SIZE 65

#define MAX_WITNESS_SIZE 32768
#define BLAKE2B_BLOCK_SIZE 32
#define BLAKE160_SIZE 20
#define SECP256K1_SIGNATURE_SIZE 65
#define SECP256K1_MESSAGE_SIZE 32
#define MAX_PREIMAGE_SIZE 1024
#define MESSAGE_HEX_LEN 64

const char BTC_PREFIX[] = "CKB (Bitcoin Layer-2) transaction: 0x";
// BTC_PREFIX_LEN = 35
const size_t BTC_PREFIX_LEN = sizeof(BTC_PREFIX) - 1;

const char COMMON_PREFIX[] = "CKB transaction: 0x";
// COMMON_PREFIX_LEN = 17
const size_t COMMON_PREFIX_LEN = sizeof(COMMON_PREFIX) - 1;

enum CkbIdentityErrorCode {
  ERROR_IDENTITY_ARGUMENTS_LEN = -1,
  ERROR_IDENTITY_ENCODING = -2,
  ERROR_IDENTITY_SYSCALL = -3,

  // compatible with secp256k1 pubkey hash verification
  ERROR_IDENTITY_SECP_RECOVER_PUBKEY = -11,
  ERROR_IDENTITY_SECP_PARSE_SIGNATURE = -14,
  ERROR_IDENTITY_SECP_SERIALIZE_PUBKEY = -15,
  ERROR_IDENTITY_PUBKEY_BLAKE160_HASH = -31,
  // new error code
  ERROR_IDENTITY_LOCK_SCRIPT_HASH_NOT_FOUND = 70,
  ERROR_IDENTITY_WRONG_ARGS,
  ERROR_INVALID_PREIMAGE,
  ERROR_MISMATCHED,
  ERROR_INVALID_ARG,
  ERROR_WRONG_STATE
};

typedef struct CkbIdentityType {
  uint8_t flags;
  // unique id, it can be: blake160 (20 bytes) hash of lock script, pubkey or
  // preimage
  uint8_t id[20];
} CkbIdentityType;

enum IdentityFlagsType {
  IdentityFlagsCkb = 0,
  // values 1~5 are used by pw-lock
  IdentityFlagsEthereum = 1,
  IdentityFlagsEos = 2,
  IdentityFlagsTron = 3,
  IdentityFlagsBitcoin = 4,
  IdentityFlagsDogecoin = 5,
  IdentityCkbMultisig = 6,

  IdentityFlagsEthereumDisplaying = 18,
  IdentityFlagsOwnerLock = 0xFC,
  IdentityFlagsExec = 0xFD,
  IdentityFlagsDl = 0xFE,
};

typedef int (*validate_signature_t)(void *prefilled_data, const uint8_t *sig,
                                    size_t sig_len, const uint8_t *msg,
                                    size_t msg_len, uint8_t *output,
                                    size_t *output_len);

typedef int (*convert_msg_t)(const uint8_t *msg, size_t msg_len,
                             uint8_t *new_msg, size_t new_msg_len);

static void bin_to_hex(const uint8_t *source, uint8_t *dest, size_t len) {
  const static uint8_t HEX_TABLE[] = {'0', '1', '2', '3', '4', '5', '6', '7',
                                      '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
  for (int i = 0; i < len; i++) {
    dest[i * 2] = HEX_TABLE[source[i] >> 4];
    dest[i * 2 + 1] = HEX_TABLE[source[i] & 0x0F];
  }
}

static int extract_witness_lock(uint8_t *witness, uint64_t len,
                                mol_seg_t *lock_bytes_seg) {
  if (len < 20) {
    return ERROR_IDENTITY_ENCODING;
  }
  uint32_t lock_length = *((uint32_t *)(&witness[16]));
  if (len < 20 + lock_length) {
    return ERROR_IDENTITY_ENCODING;
  } else {
    lock_bytes_seg->ptr = &witness[20];
    lock_bytes_seg->size = lock_length;
  }
  return CKB_SUCCESS;
}

int load_and_hash_witness(blake2b_state *ctx, size_t start, size_t index,
                          size_t source, bool hash_length) {
  uint8_t temp[ONE_BATCH_SIZE];
  uint64_t len = ONE_BATCH_SIZE;
  int ret = ckb_load_witness(temp, &len, start, index, source);
  if (ret != CKB_SUCCESS) {
    return ret;
  }
  if (hash_length) {
    blake2b_update(ctx, (char *)&len, sizeof(uint64_t));
  }
  uint64_t offset = (len > ONE_BATCH_SIZE) ? ONE_BATCH_SIZE : len;
  blake2b_update(ctx, temp, offset);
  while (offset < len) {
    uint64_t current_len = ONE_BATCH_SIZE;
    ret = ckb_load_witness(temp, &current_len, start + offset, index, source);
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

void bitcoin_hash160(const uint8_t *data, size_t size, uint8_t *output) {
  unsigned char temp[SHA256_SIZE];
  SHA256_CTX sha256_ctx;
  sha256_init(&sha256_ctx);
  sha256_update(&sha256_ctx, data, size);
  sha256_final(&sha256_ctx, temp);

  ripemd160_state ripe160_ctx;
  ripemd160_init(&ripe160_ctx);
  ripemd160_update(&ripe160_ctx, temp, SHA256_SIZE);
  ripemd160_finalize(&ripe160_ctx, output);
}

static int _ckb_recover_secp256k1_pubkey(const uint8_t *sig, size_t sig_len,
                                         const uint8_t *msg, size_t msg_len,
                                         uint8_t *out_pubkey,
                                         size_t *out_pubkey_size,
                                         bool compressed) {
  int ret = 0;

  if (sig_len != SECP256K1_SIGNATURE_SIZE) {
    return ERROR_IDENTITY_ARGUMENTS_LEN;
  }
  if (msg_len != SECP256K1_MESSAGE_SIZE) {
    return ERROR_IDENTITY_ARGUMENTS_LEN;
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
    return ERROR_IDENTITY_SECP_PARSE_SIGNATURE;
  }

  /* Recover pubkey */
  secp256k1_pubkey pubkey;
  if (secp256k1_ecdsa_recover(&context, &pubkey, &signature, msg) != 1) {
    return ERROR_IDENTITY_SECP_RECOVER_PUBKEY;
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
    return ERROR_IDENTITY_SECP_SERIALIZE_PUBKEY;
  }
  return ret;
}

int validate_signature_secp256k1(void *prefilled_data, const uint8_t *sig,
                                 size_t sig_len, const uint8_t *msg,
                                 size_t msg_len, uint8_t *output,
                                 size_t *output_len) {
  int ret = 0;
  if (*output_len < BLAKE160_SIZE) {
    return ERROR_IDENTITY_ARGUMENTS_LEN;
  }
  uint8_t out_pubkey[SECP256K1_PUBKEY_SIZE];
  size_t out_pubkey_size = SECP256K1_PUBKEY_SIZE;
  ret = _ckb_recover_secp256k1_pubkey(sig, sig_len, msg, msg_len, out_pubkey,
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
    return ERROR_IDENTITY_ARGUMENTS_LEN;
  }
  uint8_t out_pubkey[UNCOMPRESSED_SECP256K1_PUBKEY_SIZE];
  size_t out_pubkey_size = UNCOMPRESSED_SECP256K1_PUBKEY_SIZE;
  ret = _ckb_recover_secp256k1_pubkey(sig, sig_len, msg, msg_len, out_pubkey,
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

// Refer to: https://en.bitcoin.it/wiki/BIP_0137
int get_btc_recid(uint8_t d, bool *compressed, bool *p2sh_hash) {
  *compressed = true;
  *p2sh_hash = false;
  if (d >= 27 && d <= 30) {  // P2PKH uncompressed
    *compressed = false;
    return d - 27;
  } else if (d >= 31 && d <= 34) {  // P2PKH compressed
    return d - 31;
  } else if (d >= 35 && d <= 38) {  // Segwit P2SH
    *p2sh_hash = true;
    return d - 35;
  } else if (d >= 39 && d <= 42) {  // Segwit Bech32
    return d - 39;
  } else {
    return -1;
  }
}

static int _recover_secp256k1_pubkey_btc(const uint8_t *sig, size_t sig_len,
                                         const uint8_t *msg, size_t msg_len,
                                         uint8_t *out_pubkey,
                                         size_t *out_pubkey_size) {
  int ret = 0;

  if (sig_len != SECP256K1_SIGNATURE_SIZE) {
    return ERROR_INVALID_ARG;
  }
  if (msg_len != SECP256K1_MESSAGE_SIZE) {
    return ERROR_INVALID_ARG;
  }
  bool compressed = true;
  bool p2sh_hash = false;
  int recid = get_btc_recid(sig[0], &compressed, &p2sh_hash);
  if (recid == -1) {
    return ERROR_INVALID_ARG;
  }

  secp256k1_context context;
  uint8_t secp_data[CKB_SECP256K1_DATA_SIZE];
  ret = ckb_secp256k1_custom_verify_only_initialize(&context, secp_data);
  if (ret != 0) {
    return ret;
  }

  secp256k1_ecdsa_recoverable_signature signature;

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
  if (compressed) {
    *out_pubkey_size = SECP256K1_PUBKEY_SIZE;
    flag = SECP256K1_EC_COMPRESSED;
    if (secp256k1_ec_pubkey_serialize(&context, out_pubkey, out_pubkey_size,
                                      &pubkey, flag) != 1) {
      return ERROR_WRONG_STATE;
    }

    if (p2sh_hash) {
      bitcoin_hash160(out_pubkey, *out_pubkey_size, out_pubkey + 2);

      out_pubkey[0] = 0;
      out_pubkey[1] = 20;  // RIPEMD160 size
      *out_pubkey_size = 22;
    }
  } else {
    *out_pubkey_size = UNCOMPRESSED_SECP256K1_PUBKEY_SIZE;
    flag = SECP256K1_EC_UNCOMPRESSED;
    if (secp256k1_ec_pubkey_serialize(&context, out_pubkey, out_pubkey_size,
                                      &pubkey, flag) != 1) {
      return ERROR_WRONG_STATE;
    }
  }
  return ret;
}

int validate_signature_btc(void *prefilled_data, const uint8_t *sig,
                           size_t sig_len, const uint8_t *msg, size_t msg_len,
                           uint8_t *output, size_t *output_len) {
  int err = 0;
  if (*output_len < AUTH160_SIZE) {
    return ERROR_INVALID_ARG;
  }
  uint8_t out_pubkey[UNCOMPRESSED_SECP256K1_PUBKEY_SIZE];
  size_t out_pubkey_size = UNCOMPRESSED_SECP256K1_PUBKEY_SIZE;
  err = _recover_secp256k1_pubkey_btc(sig, sig_len, msg, msg_len, out_pubkey,
                                      &out_pubkey_size);
  if (err) return err;
  unsigned char temp[AUTH160_SIZE];
  bitcoin_hash160(out_pubkey, out_pubkey_size, temp);
  memcpy(output, temp, AUTH160_SIZE);
  *output_len = AUTH160_SIZE;

  return 0;
}

int validate_signature_eos(void *prefilled_data, const uint8_t *sig,
                           size_t sig_len, const uint8_t *msg, size_t msg_len,
                           uint8_t *output, size_t *output_len) {
  int err = 0;
  if (*output_len < AUTH160_SIZE) {
    return ERROR_INVALID_ARG;
  }
  uint8_t out_pubkey[UNCOMPRESSED_SECP256K1_PUBKEY_SIZE];
  size_t out_pubkey_size = UNCOMPRESSED_SECP256K1_PUBKEY_SIZE;
  err = _recover_secp256k1_pubkey_btc(sig, sig_len, msg, msg_len, out_pubkey,
                                      &out_pubkey_size);
  if (err) return err;

  blake2b_state ctx;
  blake2b_init(&ctx, BLAKE2B_BLOCK_SIZE);
  blake2b_update(&ctx, out_pubkey, out_pubkey_size);
  blake2b_final(&ctx, out_pubkey, BLAKE2B_BLOCK_SIZE);

  memcpy(output, out_pubkey, AUTH160_SIZE);
  *output_len = AUTH160_SIZE;
  return err;
}

int generate_sighash_all(uint8_t *msg, size_t msg_len) {
  int ret;
  uint64_t len = 0;
  unsigned char temp[MAX_WITNESS_SIZE];
  uint64_t read_len = MAX_WITNESS_SIZE;
  uint64_t witness_len = MAX_WITNESS_SIZE;

  if (msg_len < BLAKE2B_BLOCK_SIZE) {
    return ERROR_IDENTITY_ARGUMENTS_LEN;
  }

  /* Load witness of first input */
  ret = ckb_load_witness(temp, &read_len, 0, 0, CKB_SOURCE_GROUP_INPUT);
  if (ret != CKB_SUCCESS) {
    return ERROR_IDENTITY_SYSCALL;
  }
  witness_len = read_len;
  if (read_len > MAX_WITNESS_SIZE) {
    read_len = MAX_WITNESS_SIZE;
  }

  /* load signature */
  mol_seg_t lock_bytes_seg;
  ret = extract_witness_lock(temp, read_len, &lock_bytes_seg);
  if (ret != 0) {
    return ERROR_IDENTITY_ENCODING;
  }

  /* Load tx hash */
  unsigned char tx_hash[BLAKE2B_BLOCK_SIZE];
  len = BLAKE2B_BLOCK_SIZE;
  ret = ckb_load_tx_hash(tx_hash, &len, 0);
  if (ret != CKB_SUCCESS) {
    return ret;
  }
  if (len != BLAKE2B_BLOCK_SIZE) {
    return ERROR_IDENTITY_SYSCALL;
  }

  /* Prepare sign message */
  blake2b_state blake2b_ctx;
  blake2b_init(&blake2b_ctx, BLAKE2B_BLOCK_SIZE);
  blake2b_update(&blake2b_ctx, tx_hash, BLAKE2B_BLOCK_SIZE);

  /* Clear lock field to zero, then digest the first witness
   * lock_bytes_seg.ptr actually points to the memory in temp buffer
   * */
  memset((void *)lock_bytes_seg.ptr, 0, lock_bytes_seg.size);
  blake2b_update(&blake2b_ctx, (char *)&witness_len, sizeof(uint64_t));
  blake2b_update(&blake2b_ctx, temp, read_len);

  // remaining of first witness
  if (read_len < witness_len) {
    ret = load_and_hash_witness(&blake2b_ctx, read_len, 0,
                                CKB_SOURCE_GROUP_INPUT, false);
    if (ret != CKB_SUCCESS) {
      return ERROR_IDENTITY_SYSCALL;
    }
  }

  // Digest same group witnesses
  size_t i = 1;
  while (1) {
    ret =
        load_and_hash_witness(&blake2b_ctx, 0, i, CKB_SOURCE_GROUP_INPUT, true);
    if (ret == CKB_INDEX_OUT_OF_BOUND) {
      break;
    }
    if (ret != CKB_SUCCESS) {
      return ERROR_IDENTITY_SYSCALL;
    }
    i += 1;
  }

  // Digest witnesses that not covered by inputs
  i = (size_t)ckb_calculate_inputs_len();
  while (1) {
    ret = load_and_hash_witness(&blake2b_ctx, 0, i, CKB_SOURCE_INPUT, true);
    if (ret == CKB_INDEX_OUT_OF_BOUND) {
      break;
    }
    if (ret != CKB_SUCCESS) {
      return ERROR_IDENTITY_SYSCALL;
    }
    i += 1;
  }

  blake2b_final(&blake2b_ctx, msg, BLAKE2B_BLOCK_SIZE);

  return 0;
}

static int _ckb_convert_copy(const uint8_t *msg, size_t msg_len,
                             uint8_t *new_msg, size_t new_msg_len) {
  if (msg_len != new_msg_len || msg_len != BLAKE2B_BLOCK_SIZE)
    return ERROR_IDENTITY_ARGUMENTS_LEN;
  memcpy(new_msg, msg, msg_len);
  return 0;
}

static int convert_eth_message(const uint8_t *msg, size_t msg_len,
                               uint8_t *new_msg, size_t new_msg_len) {
  if (msg_len != new_msg_len || msg_len != BLAKE2B_BLOCK_SIZE)
    return ERROR_IDENTITY_ARGUMENTS_LEN;

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

static int convert_eth_message_displaying(const uint8_t *msg, size_t msg_len,
                                          uint8_t *new_msg,
                                          size_t new_msg_len) {
  if (msg_len != new_msg_len || msg_len != BLAKE2B_BLOCK_SIZE)
    return ERROR_IDENTITY_ARGUMENTS_LEN;

  uint8_t hex_msg[MESSAGE_HEX_LEN] = {0};
  bin_to_hex(msg, hex_msg, 32);

  SHA3_CTX sha3_ctx;
  keccak_init(&sha3_ctx);
  /* personal_sign ethereum prefix  \u0019Ethereum Signed Message:\n */
  unsigned char eth_prefix[28];
  eth_prefix[0] = 0x19;
  memcpy(eth_prefix + 1, "Ethereum Signed Message:\n", 0x19);
  // COMMON_PREFIX_LEN + MESSAGE_HEX_LEN -> 19 + 64 = 83
  memcpy(eth_prefix + 1 + 0x19, "83", 2);

  keccak_update(&sha3_ctx, eth_prefix, 28);
  //
  // Displaying message on wallet like below:
  // CKB transaction: {txhash}
  //
  keccak_update(&sha3_ctx, (unsigned char *)COMMON_PREFIX, COMMON_PREFIX_LEN);
  keccak_update(&sha3_ctx, (unsigned char *)hex_msg, MESSAGE_HEX_LEN);
  keccak_final(&sha3_ctx, new_msg);
  return 0;
}

int verify_sighash_all(uint8_t *pubkey_hash, uint8_t *sig, uint32_t sig_len,
                       validate_signature_t func, convert_msg_t convert) {
  int ret = 0;
  uint8_t old_msg[BLAKE2B_BLOCK_SIZE];
  uint8_t new_msg[BLAKE2B_BLOCK_SIZE];
  ret = generate_sighash_all(old_msg, sizeof(old_msg));
  if (ret != 0) {
    return ret;
  }
  ret = convert(old_msg, sizeof(old_msg), new_msg, sizeof(new_msg));
  if (ret != 0) return ret;

  uint8_t output_pubkey_hash[BLAKE160_SIZE];
  size_t output_len = BLAKE160_SIZE;
  ret = func(NULL, sig, sig_len, new_msg, sizeof(new_msg), output_pubkey_hash,
             &output_len);
  if (ret != 0) {
    return ret;
  }
  if (memcmp(pubkey_hash, output_pubkey_hash, BLAKE160_SIZE) != 0) {
    return ERROR_IDENTITY_PUBKEY_BLAKE160_HASH;
  }

  return 0;
}

int convert_btc_message(const uint8_t *msg, size_t msg_len, uint8_t *new_msg,
                        size_t new_msg_len) {
  if (msg_len != new_msg_len || msg_len != SHA256_SIZE)
    return ERROR_INVALID_ARG;
  const char magic[25] = "Bitcoin Signed Message:\n";
  const int8_t magic_len = 24;
  const char *prefix = BTC_PREFIX;
  size_t prefix_len = BTC_PREFIX_LEN;
  //
  // Displaying message on wallet like below:
  // Bitcoin layer (CKB) transaction: {txhash}
  //
  uint8_t hex_msg[MESSAGE_HEX_LEN];
  bin_to_hex(msg, hex_msg, 32);

  // Signature message:
  //   magic_len   magic     prefix_len+MESSAGE_HEX_LEN    prefix    message_hex
  //      1       magic_len           1                  prefix_len   64
  uint8_t data[magic_len + 2 + MESSAGE_HEX_LEN + prefix_len];
  data[0] = magic_len;
  memcpy(data + 1, magic, magic_len);

  data[magic_len + 1] = MESSAGE_HEX_LEN + prefix_len;
  memcpy(data + magic_len + 2, prefix, prefix_len);
  memcpy(data + magic_len + 2 + prefix_len, hex_msg, MESSAGE_HEX_LEN);

  SHA256_CTX sha256_ctx;
  sha256_init(&sha256_ctx);
  sha256_update(&sha256_ctx, data, sizeof(data));
  sha256_final(&sha256_ctx, new_msg);

  SHA256_CTX sha256_ctx2;
  sha256_init(&sha256_ctx2);
  sha256_update(&sha256_ctx2, new_msg, SHA256_SIZE);
  sha256_final(&sha256_ctx2, new_msg);
  return 0;
}

int convert_copy(const uint8_t *msg, size_t msg_len, uint8_t *new_msg,
                 size_t new_msg_len) {
  if (msg_len != new_msg_len || msg_len != BLAKE2B_BLOCK_SIZE)
    return ERROR_INVALID_ARG;
  memcpy(new_msg, msg, msg_len);
  return 0;
}

int convert_doge_message(const uint8_t *msg, size_t msg_len, uint8_t *new_msg,
                         size_t new_msg_len) {
  if (msg_len != new_msg_len || msg_len != SHA256_SIZE)
    return ERROR_INVALID_ARG;
  const char magic[26] = "Dogecoin Signed Message:\n";
  const int8_t magic_len = 25;

  uint8_t temp[MESSAGE_HEX_LEN];
  bin_to_hex(msg, temp, 32);

  // len of magic + magic string + len of message, size is 26 Byte
  uint8_t new_magic[magic_len + 2];
  new_magic[0] = magic_len;  // MESSAGE_MAGIC length
  memcpy(&new_magic[1], magic, magic_len);
  new_magic[magic_len + 1] = MESSAGE_HEX_LEN;  // message length

  /* Calculate signature message */
  uint8_t temp2[magic_len + 2 + MESSAGE_HEX_LEN];
  uint32_t temp2_size = magic_len + 2 + MESSAGE_HEX_LEN;
  memcpy(temp2, new_magic, magic_len + 2);
  memcpy(temp2 + magic_len + 2, temp, MESSAGE_HEX_LEN);

  SHA256_CTX sha256_ctx;
  sha256_init(&sha256_ctx);
  sha256_update(&sha256_ctx, temp2, temp2_size);
  sha256_final(&sha256_ctx, new_msg);

  SHA256_CTX sha256_ctx2;
  sha256_init(&sha256_ctx2);
  sha256_update(&sha256_ctx2, new_msg, SHA256_SIZE);
  sha256_final(&sha256_ctx2, new_msg);
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

int verify_via_dl(CkbIdentityType *id, uint8_t *sig, uint32_t sig_len,
                  uint8_t *preimage, uint32_t preimage_len,
                  CkbSwappableSignatureInstance *inst) {
  int err = 0;
  uint8_t hash[BLAKE2B_BLOCK_SIZE];

  // code hash: 32 bytes
  // hash type: 1 byte
  // pubkey hash: 20 bytes
  if (preimage_len != (32 + 1 + 20)) return ERROR_INVALID_PREIMAGE;

  blake2b_state ctx;
  blake2b_init(&ctx, BLAKE2B_BLOCK_SIZE);
  blake2b_update(&ctx, preimage, preimage_len);
  blake2b_final(&ctx, hash, BLAKE2B_BLOCK_SIZE);
  if (memcmp(hash, id->id, BLAKE160_SIZE) != 0) return ERROR_INVALID_PREIMAGE;

  uint8_t *code_hash = preimage;
  uint8_t hash_type = *(preimage + 32);
  uint8_t *pubkey_hash = preimage + 32 + 1;

  err = ckb_initialize_swappable_signature(code_hash, hash_type, inst);
  if (err != 0) return err;

  return verify_sighash_all(pubkey_hash, sig, sig_len, inst->verify_func,
                            _ckb_convert_copy);
}

int verify_via_exec(CkbIdentityType *id, uint8_t *sig, uint32_t sig_len,
                    uint8_t *preimage, uint32_t preimage_len) {
  int err = 0;
  uint8_t hash[BLAKE2B_BLOCK_SIZE];

  // code hash: 32 bytes
  // hash type: 1 byte
  // place: 1 byte
  // bounds: 8 bytes
  // pubkey hash: 20 bytes
  if (preimage_len != (32 + 1 + 1 + 8 + 20)) {
    return ERROR_INVALID_PREIMAGE;
  }

  int ret = 0;

  // check preimage hash
  blake2b_state ctx;
  blake2b_init(&ctx, BLAKE2B_BLOCK_SIZE);
  blake2b_update(&ctx, preimage, preimage_len);
  blake2b_final(&ctx, hash, BLAKE2B_BLOCK_SIZE);
  if (memcmp(hash, id->id, BLAKE160_SIZE) != 0) {
    return ERROR_INVALID_PREIMAGE;
  }

  // get message
  uint8_t msg[BLAKE2B_BLOCK_SIZE];
  ret = generate_sighash_all(msg, sizeof(msg));
  if (ret != 0) {
    return ret;
  }

  uint8_t *code_hash = preimage;
  uint8_t hash_type = *(preimage + 32);
  // place is not used
  // uint8_t _place = *(preimage + 32 + 1);
  uint32_t *length = (uint32_t *)(preimage + 32 + 1 + 1);
  uint32_t *offset = (uint32_t *)(preimage + 32 + 1 + 1 + 4);
  uint8_t *pubkey_hash = preimage + 32 + 1 + 1 + 4 + 4;

  CkbBinaryArgsType bin_args;
  CkbHexArgsType out;
  ckb_exec_reset(&bin_args);
  // <code hash in hex>:<hash type in hex>:<pubkey hash in hex>:<message
  // 1>:<signature 1>
  err = ckb_exec_append(&bin_args, code_hash, 32);
  if (err != 0) return err;
  err = ckb_exec_append(&bin_args, &hash_type, 1);
  if (err != 0) return err;
  err = ckb_exec_append(&bin_args, pubkey_hash, 20);
  if (err != 0) return err;
  err = ckb_exec_append(&bin_args, msg, sizeof(msg));
  if (err != 0) return err;
  err = ckb_exec_append(&bin_args, sig, sig_len);
  if (err != 0) return err;
  err = ckb_exec_encode_params(&bin_args, &out);
  if (err != 0) return err;

  const char *argv[1] = {out.buff};
  return ckb_exec_cell(code_hash, hash_type, *offset, *length, 1, argv);
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

  // Perform hash check of the `multisig_script` part, notice the signature
  // part is not included here.
  blake2b_state blake2b_ctx;
  blake2b_init(&blake2b_ctx, BLAKE2B_BLOCK_SIZE);
  blake2b_update(&blake2b_ctx, lock_bytes, multisig_script_len);
  blake2b_final(&blake2b_ctx, temp, BLAKE2B_BLOCK_SIZE);

  if (memcmp(hash, temp, BLAKE160_SIZE) != 0) {
    return ERROR_MULTSIG_SCRIPT_HASH;
  }

  // Verify threshold signatures, threshold is a uint8_t, at most it is
  // 255, meaning this array will definitely have a reasonable upper bound.
  // Also this code uses C99's new feature to allocate a variable length
  // array.
  uint8_t used_signatures[pubkeys_cnt];
  memset(used_signatures, 0, pubkeys_cnt);

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

    // If the signature doesn't match any of the provided public key, the
    // script will exit with an error.
    if (matched != 1) {
      return ERROR_VERIFICATION;
    }
  }

  // The above scheme just ensures that a *threshold* number of signatures
  // have successfully been verified, and they all come from the provided
  // public keys. However, the multisig script might also require some numbers
  // of public keys to always be signed for the script to pass verification.
  // This is indicated via the *required_first_n* flag. Here we also checks to
  // see that this rule is also satisfied.
  for (size_t i = 0; i < require_first_n; i++) {
    if (used_signatures[i] != 1) {
      return ERROR_VERIFICATION;
    }
  }

  return 0;
}

static uint8_t *g_identity_code_buffer = NULL;
static uint32_t g_identity_code_size = 0;

int ckb_verify_identity(CkbIdentityType *id, uint8_t *sig, uint32_t sig_size,
                        uint8_t *preimage, uint32_t preimage_size) {
  if (id->flags == IdentityFlagsCkb) {
    if (sig == NULL || sig_size != SECP256K1_SIGNATURE_SIZE) {
      return ERROR_IDENTITY_WRONG_ARGS;
    }
    return verify_sighash_all(id->id, sig, sig_size,
                              validate_signature_secp256k1, _ckb_convert_copy);
  } else if (id->flags == IdentityFlagsEthereum) {
    if (sig == NULL || sig_size != SECP256K1_SIGNATURE_SIZE) {
      return ERROR_IDENTITY_WRONG_ARGS;
    }
    return verify_sighash_all(id->id, sig, sig_size, validate_signature_eth,
                              convert_eth_message);
  } else if (id->flags == IdentityFlagsEthereumDisplaying) {
    if (sig == NULL || sig_size != SECP256K1_SIGNATURE_SIZE) {
      return ERROR_IDENTITY_WRONG_ARGS;
    }
    return verify_sighash_all(id->id, sig, sig_size, validate_signature_eth,
                              convert_eth_message_displaying);
  } else if (id->flags == IdentityFlagsEos) {
    if (sig == NULL || sig_size != SECP256K1_SIGNATURE_SIZE) {
      return ERROR_IDENTITY_WRONG_ARGS;
    }
    return verify_sighash_all(id->id, sig, sig_size, validate_signature_eos,
                              convert_copy);
  } else if (id->flags == IdentityFlagsTron) {
    if (sig == NULL || sig_size != SECP256K1_SIGNATURE_SIZE) {
      return ERROR_IDENTITY_WRONG_ARGS;
    }
    return verify_sighash_all(id->id, sig, sig_size, validate_signature_eth,
                              convert_tron_message);
  } else if (id->flags == IdentityFlagsBitcoin) {
    if (sig == NULL || sig_size != SECP256K1_SIGNATURE_SIZE) {
      return ERROR_IDENTITY_WRONG_ARGS;
    }
    return verify_sighash_all(id->id, sig, sig_size, validate_signature_btc,
                              convert_btc_message);
  } else if (id->flags == IdentityFlagsDogecoin) {
    if (sig == NULL || sig_size != SECP256K1_SIGNATURE_SIZE) {
      return ERROR_IDENTITY_WRONG_ARGS;
    }
    return verify_sighash_all(id->id, sig, sig_size, validate_signature_btc,
                              convert_doge_message);
  } else if (id->flags == IdentityCkbMultisig) {
    uint8_t msg[BLAKE2B_BLOCK_SIZE];
    int ret = generate_sighash_all(msg, sizeof(msg));
    if (ret != 0) return ret;
    return verify_multisig(sig, sig_size, msg, id->id);
  } else if (id->flags == IdentityFlagsOwnerLock) {
    if (is_lock_script_hash_present(id->id)) {
      return 0;
    } else {
      return ERROR_IDENTITY_LOCK_SCRIPT_HASH_NOT_FOUND;
    }
  } else if (id->flags == IdentityFlagsDl) {
    if (g_identity_code_buffer == NULL) return ERROR_IDENTITY_WRONG_ARGS;
    CkbSwappableSignatureInstance swappable_inst = {
        .code_buffer = g_identity_code_buffer,
        .code_buffer_size = g_identity_code_size,
        .prefilled_data_buffer = NULL,
        .prefilled_buffer_size = 0,
        .verify_func = NULL};
    return verify_via_dl(id, sig, sig_size, preimage, preimage_size,
                         &swappable_inst);
  } else if (id->flags == IdentityFlagsExec) {
    return verify_via_exec(id, sig, sig_size, preimage, preimage_size);
  }
  return CKB_INVALID_DATA;
}

void ckb_identity_init_code_buffer(uint8_t *p, uint32_t size) {
  g_identity_code_buffer = p;
  g_identity_code_size = size;
}

#endif
