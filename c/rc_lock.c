// uncomment to enable printf in CKB-VM
#define CKB_C_STDLIB_PRINTF
#include <stdio.h>

// it's used by blockchain-api2.h, the behavior when panic
#ifndef MOL2_EXIT
#define MOL2_EXIT ckb_exit
#endif
int ckb_exit(signed char);

#include <stdio.h>

#include "blockchain-api2.h"
#include "blockchain.h"
#include "ckb_consts.h"
#if defined(CKB_USE_SIM)
#include "ckb_syscall_rc_lock_sim.h"
#else
#include "ckb_syscalls.h"
#endif

#include "blake2b.h"
#include "ckb_smt.h"
#include "secp256k1_helper.h"
// CHECK is defined in secp256k1
#undef CHECK
#include "rce.h"

#define BLAKE2B_BLOCK_SIZE 32
#define BLAKE160_SIZE 20
#define PUBKEY_SIZE 33
#define TEMP_SIZE 32768
#define RECID_INDEX 64
/* 32 KB */
#define MAX_WITNESS_SIZE 32768
#define SCRIPT_SIZE 32768
#define SIGNATURE_SIZE 65
#define ONE_BATCH_SIZE 32768
#define MAX_LOCK_SCRIPT_HASH_COUNT 2048

enum RcLockErrorCode {
  ERROR_SECP_RECOVER_PUBKEY = -11,
  ERROR_SECP_PARSE_SIGNATURE = -14,
  ERROR_SECP_SERIALIZE_PUBKEY = -15,
  ERROR_PUBKEY_BLAKE160_HASH = -31,
  // rc lock error code is starting from 80
  ERROR_UNKNOWN_FLAGS = 80,
};

// ArgsType: rename it to a proper name, e.g. id_or_owner
typedef struct ArgsType {
  uint8_t flags;
  uint8_t pubkey_hash[20];
  uint8_t rc_root[32];
} ArgsType;

enum FlagsType {
  FlagsTypePlain = 0,
  FlagsTypeRc = 1,
};

// make compiler happy
int make_cursor_from_witness(WitnessArgsType *witness, bool *_input) {
  return 0;
}

int extract_witness_lock(uint8_t *witness, uint64_t len,
                         mol_seg_t *lock_bytes_seg) {
  if (len < 20) {
    return ERROR_ENCODING;
  }
  uint32_t lock_length = *((uint32_t *)(&witness[16]));
  if (len < 20 + lock_length) {
    return ERROR_ENCODING;
  } else {
    lock_bytes_seg->ptr = &witness[20];
    lock_bytes_seg->size = lock_length;
  }
  return CKB_SUCCESS;
}

int parse_args(ArgsType *args) {
  int err = 0;
  uint8_t script[SCRIPT_SIZE];
  uint64_t len = SCRIPT_SIZE;
  err = ckb_checked_load_script(script, &len, 0);
  CHECK(err);

  mol_seg_t script_seg;
  script_seg.ptr = script;
  script_seg.size = len;

  mol_errno mol_err = MolReader_Script_verify(&script_seg, false);
  CHECK2(mol_err == MOL_OK, ERROR_ENCODING);

  mol_seg_t args_seg = MolReader_Script_get_args(&script_seg);
  mol_seg_t args_bytes_seg = MolReader_Bytes_raw_bytes(&args_seg);
  CHECK2(args_bytes_seg.size >= 1, ERROR_ARGUMENTS_LEN);

  if (args_bytes_seg.ptr[0] == FlagsTypeRc) {
    CHECK2(args_bytes_seg.size >= (1 + 20 + 32), ERROR_ARGUMENTS_LEN);
    args->flags = args_bytes_seg.ptr[0];
    memcpy(args->pubkey_hash, args_bytes_seg.ptr + 1,
           sizeof(args->pubkey_hash));
    memcpy(args->rc_root, args_bytes_seg.ptr + 1 + 20, sizeof(args->rc_root));
  } else if (args_bytes_seg.ptr[0] == FlagsTypePlain) {
    CHECK2(args_bytes_seg.size >= (1 + 20), ERROR_ARGUMENTS_LEN);
    args->flags = args_bytes_seg.ptr[0];
    memcpy(args->pubkey_hash, args_bytes_seg.ptr + 1,
           sizeof(args->pubkey_hash));
  } else {
    err = ERROR_UNKNOWN_FLAGS;
  }

exit:
  return err;
}

int collect_input_lock_script_hash(smt_state_t *hashes) {
  int err = 0;

  size_t i = 0;
  while (1) {
    uint8_t buffer[BLAKE2B_BLOCK_SIZE];
    uint64_t len = BLAKE2B_BLOCK_SIZE;
    err = ckb_checked_load_cell_by_field(buffer, &len, 0, i, CKB_SOURCE_INPUT,
                                         CKB_CELL_FIELD_LOCK_HASH);
    if (err == CKB_INDEX_OUT_OF_BOUND) {
      break;
    }
    CHECK(err);
    CHECK2(hashes->len < hashes->capacity, ERROR_TOO_MANY_LOCK);

    memcpy(hashes->pairs[hashes->len].key, buffer, BLAKE2B_BLOCK_SIZE);
    hashes->len++;
    i += 1;
  }

  smt_state_normalize(hashes);

  err = 0;
exit:
  return err;
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

int verify_secp256k1_blake160_sighash_all(uint8_t *pubkey_hash) {
  int ret;
  uint64_t len = 0;
  unsigned char temp[MAX_WITNESS_SIZE];
  unsigned char lock_bytes[SIGNATURE_SIZE];
  uint64_t read_len = MAX_WITNESS_SIZE;
  uint64_t witness_len = MAX_WITNESS_SIZE;

  /* Load witness of first input */
  ret = ckb_load_witness(temp, &read_len, 0, 0, CKB_SOURCE_GROUP_INPUT);
  if (ret != CKB_SUCCESS) {
    return ERROR_SYSCALL;
  }
  witness_len = read_len;
  if (read_len > MAX_WITNESS_SIZE) {
    read_len = MAX_WITNESS_SIZE;
  }

  /* load signature */
  mol_seg_t lock_bytes_seg;
  ret = extract_witness_lock(temp, read_len, &lock_bytes_seg);
  if (ret != 0) {
    return ERROR_ENCODING;
  }

  // there will be "proof" data after signature
  if (lock_bytes_seg.size < SIGNATURE_SIZE) {
    return ERROR_ARGUMENTS_LEN;
  }
  memcpy(lock_bytes, lock_bytes_seg.ptr, SIGNATURE_SIZE);

  /* Load tx hash */
  unsigned char tx_hash[BLAKE2B_BLOCK_SIZE];
  len = BLAKE2B_BLOCK_SIZE;
  ret = ckb_load_tx_hash(tx_hash, &len, 0);
  if (ret != CKB_SUCCESS) {
    return ret;
  }
  if (len != BLAKE2B_BLOCK_SIZE) {
    return ERROR_SYSCALL;
  }

  /* Prepare sign message */
  unsigned char message[BLAKE2B_BLOCK_SIZE];
  blake2b_state blake2b_ctx;
  blake2b_init(&blake2b_ctx, BLAKE2B_BLOCK_SIZE);
  blake2b_update(&blake2b_ctx, tx_hash, BLAKE2B_BLOCK_SIZE);

  /* Clear lock field to zero, then digest the first witness */
  memset((void *)lock_bytes_seg.ptr, 0, lock_bytes_seg.size);
  blake2b_update(&blake2b_ctx, (char *)&witness_len, sizeof(uint64_t));
  blake2b_update(&blake2b_ctx, temp, read_len);

  // remaining of first witness
  if (read_len < witness_len) {
    ret = load_and_hash_witness(&blake2b_ctx, read_len, 0,
                                CKB_SOURCE_GROUP_INPUT, false);
    if (ret != CKB_SUCCESS) {
      return ERROR_SYSCALL;
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
      return ERROR_SYSCALL;
    }
    i += 1;
  }

  // Digest witnesses that not covered by inputs
  i = ckb_calculate_inputs_len();
  while (1) {
    ret = load_and_hash_witness(&blake2b_ctx, 0, i, CKB_SOURCE_INPUT, true);
    if (ret == CKB_INDEX_OUT_OF_BOUND) {
      break;
    }
    if (ret != CKB_SUCCESS) {
      return ERROR_SYSCALL;
    }
    i += 1;
  }

  blake2b_final(&blake2b_ctx, message, BLAKE2B_BLOCK_SIZE);

  /* Load signature */
  secp256k1_context context;
  uint8_t secp_data[CKB_SECP256K1_DATA_SIZE];
  ret = ckb_secp256k1_custom_verify_only_initialize(&context, secp_data);
  if (ret != 0) {
    return ret;
  }

  secp256k1_ecdsa_recoverable_signature signature;
  if (secp256k1_ecdsa_recoverable_signature_parse_compact(
          &context, &signature, lock_bytes, lock_bytes[RECID_INDEX]) == 0) {
    return ERROR_SECP_PARSE_SIGNATURE;
  }

  /* Recover pubkey */
  secp256k1_pubkey pubkey;
  if (secp256k1_ecdsa_recover(&context, &pubkey, &signature, message) != 1) {
    return ERROR_SECP_RECOVER_PUBKEY;
  }

  /* Check pubkey hash */
  size_t pubkey_size = PUBKEY_SIZE;
  if (secp256k1_ec_pubkey_serialize(&context, temp, &pubkey_size, &pubkey,
                                    SECP256K1_EC_COMPRESSED) != 1) {
    return ERROR_SECP_SERIALIZE_PUBKEY;
  }

  blake2b_init(&blake2b_ctx, BLAKE2B_BLOCK_SIZE);
  blake2b_update(&blake2b_ctx, temp, pubkey_size);
  blake2b_final(&blake2b_ctx, temp, BLAKE2B_BLOCK_SIZE);

  if (memcmp(pubkey_hash, temp, BLAKE160_SIZE) != 0) {
    return ERROR_PUBKEY_BLAKE160_HASH;
  }

  return 0;
}

#ifdef CKB_USE_SIM
int simulator_main() {
#else
int main() {
#endif
  printf("simulator_main\n");
  // parse lock script's args
  int err = 0;
  ArgsType args = {0};
  err = parse_args(&args);
  printf("parse_args return %d\n", err);
  CHECK(err);

  if (args.flags == FlagsTypePlain || args.flags == FlagsTypeRc) {
    err = verify_secp256k1_blake160_sighash_all(args.pubkey_hash);
    printf("verify_secp256k1_blake160_sighash_all : %d\n", err);
    CHECK(err);
  } else {
    err = ERROR_UNKNOWN_FLAGS;
    CHECK(err);
  }

  if (args.flags == FlagsTypeRc) {
    // collect input lock script hashes
    smt_pair_t entries[MAX_LOCK_SCRIPT_HASH_COUNT];
    smt_state_t states;
    smt_state_init(&states, entries, MAX_LOCK_SCRIPT_HASH_COUNT);
    err = collect_input_lock_script_hash(&states);
    CHECK(err);

    // collect rc rules
    RceState rce_state;
    rce_init_state(&rce_state);
    err = rce_gather_rcrules_recursively(&rce_state, args.rc_root, 0);
    CHECK(err);

    // verify input lock script hashes against proof, using rc rules
  }

exit:
  return err;
}
