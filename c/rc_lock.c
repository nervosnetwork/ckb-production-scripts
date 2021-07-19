// uncomment to enable printf in CKB-VM
// #define CKB_C_STDLIB_PRINTF

// it's used by blockchain-api2.h, the behavior when panic
#ifndef MOL2_EXIT
#define MOL2_EXIT ckb_exit
#endif
int ckb_exit(signed char);

// clang-format off
#include <stdio.h>
#include "blockchain-api2.h"
#include "blockchain.h"
#include "ckb_consts.h"

#if defined(CKB_USE_SIM)
// exclude ckb_dlfcn.h
#define CKB_C_STDLIB_CKB_DLFCN_H_
#include "ckb_syscall_rc_lock_sim.h"
#else
#include "ckb_syscalls.h"
#endif
// secp256k1_helper.h is not part of ckb-c-stdlib, can't be included in ckb_identity.h
#include "secp256k1_helper.h"
#include "ckb_swappable_signatures.h"
#include "validate_signature_rsa.h"

#include "ckb_identity.h"
#include "ckb_smt.h"

// CHECK is defined in secp256k1
#undef CHECK
#include "rce.h"
#include "rc_lock_mol2.h"

#include "rc_lock_acp.h"
#include "rc_lock_time_lock.h"

// clang-format on

#define SCRIPT_SIZE 32768
#define MAX_LOCK_SCRIPT_HASH_COUNT 2048
#define MAX_SIGNATURE_SIZE 1024
#define MAX_PREIMAGE_SIZE 1024
#define MAX_CODE_SIZE (1024 * 400)

enum IdentityFlagsExtraType {
  IdentityFlagsRsaDl = 3,
  IdentityFlagsRsaExec = 4,
  IdentityFlagsIso9796_2Dl = 5,
  IdentityFlagsIso9796_2Exec = 6,
};

enum RcLockErrorCode {
  // rc lock error code is starting from 80
  ERROR_UNKNOWN_FLAGS = 80,
  ERROR_PROOF_LENGTH_MISMATCHED,
  ERROR_NO_RCRULE,
  ERROR_NO_WHITE_LIST,
  ERROR_INVALID_RC_IDENTITY_ID,
  ERROR_INVALID_PREIMAGE,
  ERROR_INVALID_ARGS,
  ERROR_ISO9796_2_VERIFY,
};

// parsed from args in lock script
typedef struct ArgsType {
  CkbIdentityType id;
  uint8_t rc_root[32];
  bool has_since;
  uint64_t since;
  int ckb_minimum;  // Used for ACP
  int udt_minimum;  // used for ACP
} ArgsType;

// parsed from lock in witness
typedef struct WitnessLockType {
  bool has_rc_identity;
  bool has_signature;

  CkbIdentityType id;
  uint32_t signature_size;
  uint8_t signature[MAX_SIGNATURE_SIZE];
  uint32_t preimage_size;
  uint8_t preimage[MAX_PREIMAGE_SIZE];

  SmtProofEntryVecType proofs;
} WitnessLockType;

uint32_t calculate_rsa_info_length(int key_size) { return 8 + key_size / 4; }

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

// make compiler happy
int make_cursor_from_witness(WitnessArgsType *witness, bool *_input) {
  return -1;
}

//
// move cur by offset within seg.
// return NULL if out of bounds.
uint8_t *safe_move_to(mol_seg_t seg, uint8_t *cur, uint32_t offset) {
  uint8_t *end = seg.ptr + seg.size;

  if (cur < seg.ptr || cur >= end) {
    return NULL;
  }
  uint8_t *next = cur + offset;
  if (next < seg.ptr || next >= end) {
    return NULL;
  }
  return next;
}

bool is_memory_enough(mol_seg_t seg, const uint8_t *cur, uint32_t len) {
  uint8_t *end = seg.ptr + seg.size;

  if (cur < seg.ptr || cur >= end) {
    return false;
  }
  const uint8_t *next = cur + len;
  // == end is allowed
  if (next < seg.ptr || next > end) {
    return false;
  }
  return true;
}

// memory layout of args:
// 1 byte flag
// 20 bytes blake160
// extra 2 bytes for ACP
// 32 bytes rc_root
// 8 bytes since, optional. Used for time lock
int parse_args(ArgsType *args) {
  int err = 0;
  uint8_t script[SCRIPT_SIZE];
  uint64_t len = SCRIPT_SIZE;
  err = ckb_checked_load_script(script, &len, 0);
  CHECK(err);

  mol_seg_t script_seg;
  script_seg.ptr = script;
  script_seg.size = (mol_num_t)len;

  mol_errno mol_err = MolReader_Script_verify(&script_seg, false);
  CHECK2(mol_err == MOL_OK, ERROR_ENCODING);

  mol_seg_t args_seg = MolReader_Script_get_args(&script_seg);
  mol_seg_t args_bytes_seg = MolReader_Bytes_raw_bytes(&args_seg);

  uint8_t *cur = args_bytes_seg.ptr;

  // parse flags
  CHECK2(is_memory_enough(args_bytes_seg, cur, 1), ERROR_INVALID_MOL_FORMAT);
  uint8_t flags = *cur;
  CHECK2(flags == IdentityFlagsPubkeyHash || flags == IdentityFlagsOwnerLock ||
             flags == IdentityFlagsAcp,
         ERROR_UNKNOWN_FLAGS);
  args->id.flags = flags;
  cur = safe_move_to(args_bytes_seg, cur, 1);
  CHECK2(cur != NULL, ERROR_INVALID_MOL_FORMAT);

  // parse blake160
  CHECK2(is_memory_enough(args_bytes_seg, cur, 20), ERROR_INVALID_MOL_FORMAT);
  memcpy(args->id.blake160, cur, BLAKE160_SIZE);
  cur = safe_move_to(args_bytes_seg, cur, 20);
  CHECK2(cur != NULL, ERROR_INVALID_MOL_FORMAT);

  // parse ACP's extra 2 minimums
  if (flags == IdentityFlagsAcp) {
    CHECK2(is_memory_enough(args_bytes_seg, cur, 2), ERROR_INVALID_MOL_FORMAT);
    args->ckb_minimum = cur[0];
    args->udt_minimum = cur[1];
    cur = safe_move_to(args_bytes_seg, cur, 2);
    CHECK2(cur != NULL, ERROR_INVALID_MOL_FORMAT);
  }
  // parse RC cell type hash
  CHECK2(is_memory_enough(args_bytes_seg, cur, 32), ERROR_INVALID_MOL_FORMAT);
  memcpy(args->rc_root, cur, sizeof(args->rc_root));
  cur = safe_move_to(args_bytes_seg, cur, 32);

  // optional since
  if (cur != NULL) {
    CHECK2(is_memory_enough(args_bytes_seg, cur, 8), ERROR_INVALID_MOL_FORMAT);
    args->since = *(uint64_t *)cur;
    cur = safe_move_to(args_bytes_seg, cur, 8);
    args->has_since = true;
  } else {
    args->since = 0;
    args->has_since = false;
  }
  // make sure args is consumed exactly
  CHECK2(cur == NULL, ERROR_INVALID_MOL_FORMAT);

exit:
  return err;
}

static uint32_t read_from_witness(uintptr_t arg[], uint8_t *ptr, uint32_t len,
                                  uint32_t offset) {
  int err;
  uint64_t output_len = len;
  err = ckb_load_witness(ptr, &output_len, offset, arg[0], arg[1]);
  if (err != 0) {
    return 0;
  }
  if (output_len > len) {
    return len;
  } else {
    return (uint32_t)output_len;
  }
}

uint8_t g_witness_data_source[DEFAULT_DATA_SOURCE_LENGTH];
int make_witness(WitnessArgsType *witness) {
  int err = 0;
  uint64_t witness_len = 0;
  size_t source = CKB_SOURCE_GROUP_INPUT;
  err = ckb_load_witness(NULL, &witness_len, 0, 0, source);
  // when witness is missing, empty or not accessible, make it zero length.
  // don't fail, because owner lock without rc doesn't require witness.
  // when it's zero length, any further actions on witness will fail.
  if (err != 0) {
    witness_len = 0;
  }

  mol2_cursor_t cur;

  cur.offset = 0;
  cur.size = (mol_num_t)witness_len;

  mol2_data_source_t *ptr = (mol2_data_source_t *)g_witness_data_source;

  ptr->read = read_from_witness;
  ptr->total_size = (uint32_t)witness_len;
  // pass index and source as args
  ptr->args[0] = 0;
  ptr->args[1] = source;

  ptr->cache_size = 0;
  ptr->start_point = 0;
  ptr->max_cache_size = MAX_CACHE_SIZE;
  cur.data_source = ptr;

  *witness = make_WitnessArgs(&cur);

  return 0;
}

int smt_verify_identity(CkbIdentityType *id, SmtProofEntryVecType *proofs,
                        RceState *rce_state) {
  int err = 0;
  uint32_t proof_len = proofs->t->len(proofs);
  CHECK2(proof_len == rce_state->rcrules_count, ERROR_PROOF_LENGTH_MISMATCHED);

  uint8_t key[SMT_KEY_BYTES] = {0};
  key[0] = id->flags;
  memcpy(key + 1, id->blake160, BLAKE160_SIZE);

  smt_pair_t entries[1];
  smt_state_t states;
  smt_state_init(&states, entries, 1);
  smt_state_insert(&states, key, SMT_VALUE_EMPTY);

  uint8_t proof_mask = 0x3;  // both
  for (uint32_t i = 0; i < proof_len; i++) {
    bool existing = false;
    SmtProofEntryType proof_entry = proofs->t->get(proofs, i, &existing);
    CHECK2(existing, ERROR_INVALID_MOL_FORMAT);
    mol2_cursor_t proof = proof_entry.t->proof(&proof_entry);

    const RCRule *current_rule = &rce_state->rcrules[i];
    err = rce_verify_one_rule(rce_state, &states, NULL, NULL, proof_mask, proof,
                              current_rule);
    CHECK(err);
  }
  if (rce_state->has_wl) {
    if (rce_state->both_on_wl) {
      err = 0;
    } else {
      err = ERROR_NOT_ON_WHITE_LIST;
    }
  } else {
    // all black list, it's not allowed
    err = ERROR_NO_WHITE_LIST;
  }
exit:
  return err;
}

int parse_witness_lock(WitnessLockType *witness_lock) {
  int err = 0;
  witness_lock->has_signature = false;
  witness_lock->has_rc_identity = false;

  bool witness_existing = false;

  WitnessArgsType witness_args;
  err = make_witness(&witness_args);
  CHECK(err);
  witness_existing = witness_args.cur.size > 0;

  // witness or witness lock can be empty if owner lock without rc is used
  if (!witness_existing) return err;

  BytesOptType mol_lock = witness_args.t->lock(&witness_args);
  if (mol_lock.t->is_none(&mol_lock)) return err;

  mol2_cursor_t mol_lock_bytes = mol_lock.t->unwrap(&mol_lock);
  // convert Bytes to RcLockWitnessLock
  RcLockWitnessLockType mol_witness_lock =
      make_RcLockWitnessLock(&mol_lock_bytes);
  RcIdentityOptType rc_identity_opt =
      mol_witness_lock.t->rc_identity(&mol_witness_lock);
  witness_lock->has_rc_identity = rc_identity_opt.t->is_some(&rc_identity_opt);
  if (witness_lock->has_rc_identity) {
    RcIdentityType rc_identity = rc_identity_opt.t->unwrap(&rc_identity_opt);
    mol2_cursor_t id_cur = rc_identity.t->identity(&rc_identity);

    uint8_t buff[CKB_IDENTITY_LEN] = {0};
    uint32_t read_len = mol2_read_at(&id_cur, buff, sizeof(buff));
    CHECK2(read_len == CKB_IDENTITY_LEN, ERROR_INVALID_MOL_FORMAT);
    witness_lock->id.flags = buff[0];
    memcpy(witness_lock->id.blake160, buff + 1, CKB_IDENTITY_LEN - 1);

    witness_lock->proofs = rc_identity.t->proofs(&rc_identity);
  }

  BytesOptType signature_opt = mol_witness_lock.t->signature(&mol_witness_lock);
  witness_lock->has_signature = signature_opt.t->is_some(&signature_opt);
  if (witness_lock->has_signature) {
    mol2_cursor_t signature_cursor = signature_opt.t->unwrap(&signature_opt);
    witness_lock->signature_size = mol2_read_at(
        &signature_cursor, witness_lock->signature, signature_cursor.size);
    CHECK2(signature_cursor.size == witness_lock->signature_size,
           ERROR_INVALID_MOL_FORMAT);
  }
  BytesOptType preimage_opt = mol_witness_lock.t->preimage(&mol_witness_lock);
  if (preimage_opt.t->is_some(&preimage_opt)) {
    mol2_cursor_t preimage_cursor = preimage_opt.t->unwrap(&preimage_opt);
    witness_lock->preimage_size = mol2_read_at(
        &preimage_cursor, witness_lock->preimage, preimage_cursor.size);
    CHECK2(preimage_cursor.size == witness_lock->preimage_size,
           ERROR_INVALID_MOL_FORMAT);
  } else {
    witness_lock->preimage_size = 0;
  }

exit:
  return err;
}

int verify_rsa_via_dl(CkbIdentityType *id, uint8_t *sig, uint32_t sig_len,
                      uint8_t *preimage, uint32_t preimage_len,
                      CkbSwappableSignatureInstance *inst) {
  int err = 0;
  uint8_t hash[BLAKE2B_BLOCK_SIZE];

  // code hash: 32 bytes
  // hash type: 1 byte
  // pubkey hash: 20 bytes
  CHECK2(preimage_len == (32 + 1 + 20), ERROR_INVALID_PREIMAGE);

  blake2b_state ctx;
  blake2b_init(&ctx, BLAKE2B_BLOCK_SIZE);
  blake2b_update(&ctx, preimage, preimage_len);
  blake2b_final(&ctx, hash, BLAKE2B_BLOCK_SIZE);
  CHECK2(memcmp(hash, id->blake160, BLAKE160_SIZE) == 0,
         ERROR_INVALID_PREIMAGE);

  uint8_t *code_hash = preimage;
  uint8_t hash_type = *(preimage + 32);
  uint8_t *pubkey_hash = preimage + 32 + 1;

  err = ckb_initialize_swappable_signature(code_hash, hash_type, inst);
  CHECK(err);

  err = verify_sighash_all(pubkey_hash, sig, sig_len, inst->verify_func);
  CHECK(err);

exit:
  return err;
}

// this function is different from verify_sighash_all:
// One function call of validate_siganture_t can only validate 8 bytes of data.
// It costs 4 calls to validate full 32-bytes message.
// The layout of buffer "sig" should be:
// RsaInfo + sig[key_size/8] + sig[key_size/8] + sig[key_size/8]
int verify_iso9796_2_sighash_all(uint8_t *pubkey_hash, uint8_t *sig,
                                 uint32_t sig_len, validate_signature_t func) {
  int err = 0;

  RsaInfo *info = (RsaInfo *)sig;
  uint32_t key_size = get_key_size(info->key_size);
  CHECK2(key_size != 0, ERROR_INVALID_ARGS);
  uint32_t one_sig_len = calculate_rsa_info_length(key_size);
  uint32_t raw_sig_len = key_size / 8;

  uint32_t expected_sig_len = one_sig_len + 3 * raw_sig_len;
  CHECK2(sig_len == expected_sig_len, ERROR_INVALID_ARGS);

  uint8_t msg[BLAKE2B_BLOCK_SIZE];
  err = generate_sighash_all(msg, sizeof(msg));
  CHECK(err);

  for (int index = 0; index < 4; index++) {
    uint8_t sig_shard[one_sig_len];
    uint8_t output_pubkey_hash[BLAKE160_SIZE];
    uint8_t *msg_shard = msg + index * 8;
    size_t output_len = BLAKE160_SIZE;
    uint32_t sig_shard_len = one_sig_len;

    memcpy(sig_shard, sig, 8);
    memcpy(sig_shard + 8, sig + 8 + index * raw_sig_len, raw_sig_len);

    err = func(NULL, sig_shard, sig_shard_len, msg_shard, 8, output_pubkey_hash,
               &output_len);
    CHECK(err);
    CHECK2(output_len >= BLAKE160_SIZE, ERROR_ISO9796_2_VERIFY);

    if (memcmp(pubkey_hash, output_pubkey_hash, BLAKE160_SIZE) != 0) {
      return ERROR_IDENTITY_PUBKEY_BLAKE160_HASH;
    }
  }

exit:
  return 0;
}

int verify_iso9796_2_via_dl(CkbIdentityType *id, uint8_t *sig, uint32_t sig_len,
                            uint8_t *preimage, uint32_t preimage_len,
                            CkbSwappableSignatureInstance *inst) {
  int err = 0;
  uint8_t hash[BLAKE2B_BLOCK_SIZE];

  // code hash: 32 bytes
  // hash type: 1 byte
  // pubkey hash: 20 bytes
  CHECK2(preimage_len == (32 + 1 + 20), ERROR_INVALID_PREIMAGE);

  blake2b_state ctx;
  blake2b_init(&ctx, BLAKE2B_BLOCK_SIZE);
  blake2b_update(&ctx, preimage, preimage_len);
  blake2b_final(&ctx, hash, BLAKE2B_BLOCK_SIZE);
  CHECK2(memcmp(hash, id->blake160, BLAKE160_SIZE) == 0,
         ERROR_INVALID_PREIMAGE);

  uint8_t *code_hash = preimage;
  uint8_t hash_type = *(preimage + 32);
  uint8_t *pubkey_hash = preimage + 32 + 1;

  err = ckb_initialize_swappable_signature(code_hash, hash_type, inst);
  CHECK(err);

  err = verify_iso9796_2_sighash_all(pubkey_hash, sig, sig_len,
                                     inst->verify_func);
  CHECK(err);

exit:
  return err;
}

#ifdef CKB_USE_SIM
int simulator_main() {
#else
int main() {
#endif
  int err = 0;
  uint8_t code_buffer[MAX_CODE_SIZE];
  CkbSwappableSignatureInstance swappable_inst = {
      .code_buffer = code_buffer,
      .code_buffer_size = MAX_CODE_SIZE,
      .prefilled_data_buffer = NULL,
      .prefilled_buffer_size = 0,
      .verify_func = NULL};

  WitnessLockType witness_lock = {0};
  ArgsType args = {0};
  // this identity can be either from witness lock (witness_lock.id) or script
  // args (args.id)
  CkbIdentityType identity = {0};

  err = parse_witness_lock(&witness_lock);
  CHECK(err);

  err = parse_args(&args);
  CHECK(err);
  if (witness_lock.has_rc_identity) {
    identity = witness_lock.id;
    // The unlock methods used in rc_identity should be chosen carefully.
    CHECK2(identity.flags == IdentityFlagsPubkeyHash ||
               identity.flags == IdentityFlagsOwnerLock,
           ERROR_INVALID_RC_IDENTITY_ID);
  } else {
    identity = args.id;
    // time lock is not used for administrators
    if (args.has_since) {
      err = check_since(args.since);
      CHECK(err);
    }
  }

  // regulation compliance
  if (witness_lock.has_rc_identity) {
    // collect rc rules
    RceState rce_state;
    rce_init_state(&rce_state);
    err = rce_gather_rcrules_recursively(&rce_state, args.rc_root, 0);
    CHECK(err);
    CHECK2(rce_state.rcrules_count > 0, ERROR_NO_RCRULE);
    CHECK2(rce_state.has_wl, ERROR_NO_WHITE_LIST);

    // verify blake160 against proof, using rc rules
    err = smt_verify_identity(&identity, &witness_lock.proofs, &rce_state);
    CHECK(err);
  }

  if (identity.flags == IdentityFlagsPubkeyHash) {
    CHECK2(witness_lock.has_signature, ERROR_INVALID_MOL_FORMAT);
    CHECK2(witness_lock.signature_size == SECP256K1_SIGNATURE_SIZE,
           ERROR_INVALID_MOL_FORMAT);
  }

  if (identity.flags == IdentityFlagsAcp) {
    err = acp_main(&identity, witness_lock.has_signature,
                   witness_lock.signature, witness_lock.signature_size,
                   args.ckb_minimum, args.udt_minimum);
  } else if (identity.flags == IdentityFlagsRsaDl) {
    err = verify_rsa_via_dl(&identity, witness_lock.signature,
                            witness_lock.signature_size, witness_lock.preimage,
                            witness_lock.preimage_size, &swappable_inst);
  } else if (identity.flags == IdentityFlagsIso9796_2Dl) {
    err = verify_iso9796_2_via_dl(
        &identity, witness_lock.signature, witness_lock.signature_size,
        witness_lock.preimage, witness_lock.preimage_size, &swappable_inst);
  } else {
    err = ckb_verify_identity(&identity, witness_lock.signature,
                              witness_lock.signature_size);
  }
  CHECK(err);

exit:
  return err;
}
