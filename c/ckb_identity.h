#ifndef CKB_C_STDLIB_CKB_IDENTITY_H_
#define CKB_C_STDLIB_CKB_IDENTITY_H_

#include <blake2b.h>
#include <ckb_exec.h>

#include "ckb_consts.h"
#include "ckb_keccak256.h"

#define CKB_IDENTITY_LEN 21
#define RECID_INDEX 64
#define ONE_BATCH_SIZE 32768
#define PUBKEY_SIZE 33
#define UNCOMPRESSED_PUBKEY_SIZE 65

#define MAX_WITNESS_SIZE 32768
#define BLAKE2B_BLOCK_SIZE 32
#define BLAKE160_SIZE 20
#define SECP256K1_SIGNATURE_SIZE 65
#define SECP256K1_MESSAGE_SIZE 32
#define MAX_PREIMAGE_SIZE 1024

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
};

typedef struct CkbAuthType {
  uint8_t flags;
  // unique id, it can be: blake160 (20 bytes) hash of lock script, pubkey or
  // preimage
  uint8_t id[20];
} CkbAuthType;

enum IdentityFlagsType {
  IdentityFlagsCkb = 0,
  // values 1~5 are used by pw-lock
  IdentityFlagsEthereum = 1,
  IdentityFlagsEos = 2,
  IdentityFlagsTron = 3,
  IdentityFlagsBitcoin = 4,
  IdentityFlagsDogecoin = 5,
  IdentityCkbMultisig = 6,

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
    *out_pubkey_size = PUBKEY_SIZE;
    flag = SECP256K1_EC_COMPRESSED;
  } else {
    *out_pubkey_size = UNCOMPRESSED_PUBKEY_SIZE;
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
  uint8_t out_pubkey[PUBKEY_SIZE];
  size_t out_pubkey_size = PUBKEY_SIZE;
  ret = _ckb_recover_secp256k1_pubkey(sig, sig_len, msg, msg_len, out_pubkey,
                                      &out_pubkey_size, true);
  if (ret != 0)
    return ret;

  blake2b_state ctx;
  blake2b_init(&ctx, BLAKE2B_BLOCK_SIZE);
  blake2b_update(&ctx, out_pubkey, out_pubkey_size);
  blake2b_final(&ctx, out_pubkey, BLAKE2B_BLOCK_SIZE);

  memcpy(output, out_pubkey, BLAKE160_SIZE);
  *output_len = BLAKE160_SIZE;

  return ret;
}

int validate_signature_secp256k1_pw(void *prefilled_data, const uint8_t *sig,
                                    size_t sig_len, const uint8_t *msg,
                                    size_t msg_len, uint8_t *output,
                                    size_t *output_len) {
  int ret = 0;
  if (*output_len < BLAKE160_SIZE) {
    return ERROR_IDENTITY_ARGUMENTS_LEN;
  }
  uint8_t out_pubkey[UNCOMPRESSED_PUBKEY_SIZE];
  size_t out_pubkey_size = UNCOMPRESSED_PUBKEY_SIZE;
  ret = _ckb_recover_secp256k1_pubkey(sig, sig_len, msg, msg_len, out_pubkey,
                                      &out_pubkey_size, false);
  if (ret != 0)
    return ret;

  // here are the 2 differences than validate_signature_secp256k1
  SHA3_CTX sha3_ctx;
  keccak_init(&sha3_ctx);
  keccak_update(&sha3_ctx, &out_pubkey[1], out_pubkey_size - 1);
  keccak_final(&sha3_ctx, out_pubkey);

  memcpy(output, &out_pubkey[12], BLAKE160_SIZE);
  *output_len = BLAKE160_SIZE;

  return ret;
}

int generate_message(uint8_t *msg, size_t msg_len) {
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

static int _ckb_convert_keccak256_hash(const uint8_t *msg, size_t msg_len,
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

int verify_signature(uint8_t *pubkey_hash, uint8_t *sig, uint32_t sig_len,
                     validate_signature_t func, convert_msg_t convert,
                     bool enable_opentx) {
  int ret = 0;
  uint8_t old_msg[BLAKE2B_BLOCK_SIZE];
  uint8_t new_msg[BLAKE2B_BLOCK_SIZE];
  if (enable_opentx) {
    OpenTxWitness opentx_witness = {0};
    ret = opentx_parse_witness(sig, sig_len, &opentx_witness);
    if (ret != 0)
      return ret;
    ret = opentx_generate_message(&opentx_witness, sig, sig_len, old_msg,
                                  sizeof(old_msg));
    if (ret != 0)
      return ret;
    sig = opentx_witness.real_sig;
    sig_len = opentx_witness.real_sig_len;
  } else {
    ret = generate_message(old_msg, sizeof(old_msg));

    if (ret != 0) {
      return ret;
    }
  }
  ret = convert(old_msg, sizeof(old_msg), new_msg, sizeof(new_msg));
  if (ret != 0)
    return ret;

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

int verify_via_dl(CkbAuthType *id, uint8_t *sig, uint32_t sig_len,
                  uint8_t *preimage, uint32_t preimage_len,
                  CkbSwappableSignatureInstance *inst, bool enable_opentx) {
  int err = 0;
  uint8_t hash[BLAKE2B_BLOCK_SIZE];

  // code hash: 32 bytes
  // hash type: 1 byte
  // pubkey hash: 20 bytes
  if (preimage_len != (32 + 1 + 20))
    return ERROR_INVALID_PREIMAGE;

  blake2b_state ctx;
  blake2b_init(&ctx, BLAKE2B_BLOCK_SIZE);
  blake2b_update(&ctx, preimage, preimage_len);
  blake2b_final(&ctx, hash, BLAKE2B_BLOCK_SIZE);
  if (memcmp(hash, id->id, BLAKE160_SIZE) != 0)
    return ERROR_INVALID_PREIMAGE;

  uint8_t *code_hash = preimage;
  uint8_t hash_type = *(preimage + 32);
  uint8_t *pubkey_hash = preimage + 32 + 1;

  err = ckb_initialize_swappable_signature(code_hash, hash_type, inst);
  if (err != 0)
    return err;

  return verify_signature(pubkey_hash, sig, sig_len, inst->verify_func,
                          _ckb_convert_copy, enable_opentx);
}

int verify_via_exec(CkbAuthType *id, uint8_t *sig, uint32_t sig_len,
                    uint8_t *preimage, uint32_t preimage_len,
                    bool enable_opentx) {
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

  if (enable_opentx) {
    OpenTxWitness opentx_witness = {0};
    ret = opentx_parse_witness(sig, sig_len, &opentx_witness);
    if (ret != 0)
      return ret;
    ret = opentx_generate_message(&opentx_witness, sig, sig_len, msg,
                                  sizeof(msg));
    if (ret != 0)
      return ret;
    sig = opentx_witness.real_sig;
    sig_len = opentx_witness.real_sig_len;
  } else {
    ret = generate_message(msg, sizeof(msg));

    if (ret != 0) {
      return ret;
    }
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
  if (err != 0)
    return err;
  err = ckb_exec_append(&bin_args, &hash_type, 1);
  if (err != 0)
    return err;
  err = ckb_exec_append(&bin_args, pubkey_hash, 20);
  if (err != 0)
    return err;
  err = ckb_exec_append(&bin_args, msg, sizeof(msg));
  if (err != 0)
    return err;
  err = ckb_exec_append(&bin_args, sig, sig_len);
  if (err != 0)
    return err;
  err = ckb_exec_encode_params(&bin_args, &out);
  if (err != 0)
    return err;

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
  if (ret != 0)
    return ret;

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

static uint8_t *g_identity_code_buffer = NULL;
static uint32_t g_identity_code_size = 0;

int ckb_verify_identity(CkbAuthType *id, uint8_t *sig, uint32_t sig_len,
                        uint8_t *preimage, uint32_t preimage_size,
                        bool enable_opentx) {
  if (id->flags == IdentityFlagsCkb) {
    if (sig == NULL || sig_len != SECP256K1_SIGNATURE_SIZE) {
      return ERROR_IDENTITY_WRONG_ARGS;
    }
    return verify_signature(id->id, sig, sig_len, validate_signature_secp256k1,
                            _ckb_convert_copy, enable_opentx);
  } else if (id->flags == IdentityFlagsEthereum) {
    if (sig == NULL || sig_len != SECP256K1_SIGNATURE_SIZE) {
      return ERROR_IDENTITY_WRONG_ARGS;
    }
    return verify_signature(id->id, sig, sig_len,
                            validate_signature_secp256k1_pw,
                            _ckb_convert_keccak256_hash, enable_opentx);
  } else if (id->flags == IdentityCkbMultisig) {
    int ret = 0;
    uint8_t msg[BLAKE2B_BLOCK_SIZE];
    if (enable_opentx) {
      OpenTxWitness opentx_witness = {0};
      ret = opentx_parse_witness(sig, sig_len, &opentx_witness);
      if (ret != 0)
        return ret;
      ret = opentx_generate_message(&opentx_witness, sig, sig_len, msg,
                                    sizeof(msg));
      if (ret != 0)
        return ret;
      sig = opentx_witness.real_sig;
      sig_len = opentx_witness.real_sig_len;
    } else {
      ret = generate_message(msg, sizeof(msg));

      if (ret != 0) {
        return ret;
      }
    }
    return verify_multisig(sig, sig_len, msg, id->id);
  } else if (id->flags == IdentityFlagsOwnerLock) {
    if (is_lock_script_hash_present(id->id)) {
      return 0;
    } else {
      return ERROR_IDENTITY_LOCK_SCRIPT_HASH_NOT_FOUND;
    }
  } else if (id->flags == IdentityFlagsDl) {
    if (g_identity_code_buffer == NULL)
      return ERROR_IDENTITY_WRONG_ARGS;
    CkbSwappableSignatureInstance swappable_inst = {
        .code_buffer = g_identity_code_buffer,
        .code_buffer_size = g_identity_code_size,
        .prefilled_data_buffer = NULL,
        .prefilled_buffer_size = 0,
        .verify_func = NULL};
    return verify_via_dl(id, sig, sig_len, preimage, preimage_size,
                         &swappable_inst, enable_opentx);
  } else if (id->flags == IdentityFlagsExec) {
    return verify_via_exec(id, sig, sig_len, preimage, preimage_size,
                           enable_opentx);
  }
  return CKB_INVALID_DATA;
}

void ckb_identity_init_code_buffer(uint8_t *p, uint32_t size) {
  g_identity_code_buffer = p;
  g_identity_code_size = size;
}

#endif
