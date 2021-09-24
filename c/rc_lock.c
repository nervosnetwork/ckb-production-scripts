// uncomment to enable printf in CKB-VM
// #define CKB_C_STDLIB_PRINTF

// it's used by blockchain-api2.h, the behavior when panic
#ifndef MOL2_EXIT
#define MOL2_EXIT ckb_exit
#endif
int ckb_exit(signed char);
// in secp256k1_ctz64_var: we don't have __builtin_ctzl in gcc for RISC-V
#define __builtin_ctzl secp256k1_ctz64_var_debruijn

// clang-format off
#include <stdio.h>
#include "blockchain-api2.h"
#define MOLECULEC_VERSION 7000
#include "blockchain.h"
#include "ckb_consts.h"

#if defined(CKB_USE_SIM)
// exclude ckb_dlfcn.h
#define CKB_C_STDLIB_CKB_DLFCN_H_
#include "ckb_syscall_rc_lock_sim.h"
#else
#include "ckb_syscalls.h"
#endif
// secp256k1_helper_20210801.h is not part of ckb-c-stdlib, can't be included in ckb_identity.h
// An upgraded version is provided.
#include "secp256k1_helper_20210801.h"
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
#include "rc_lock_supply.h"

// clang-format on

#define SCRIPT_SIZE 32768
#define MAX_LOCK_SCRIPT_HASH_COUNT 2048
#define MAX_SIGNATURE_SIZE 1024
#define RC_ROOT_MASK 1
#define ACP_MASK (1 << 1)
#define SINCE_MASK (1 << 2)
#define SUPPLY_MASK (1 << 3)

#define MAX_CODE_SIZE (1024 * 400)

enum RcLockErrorCode {
  // rc lock error code is starting from 80
  ERROR_UNKNOWN_FLAGS = 80,
  ERROR_PROOF_LENGTH_MISMATCHED,
  ERROR_NO_RCRULE,
  ERROR_NO_WHITE_LIST,
  ERROR_INVALID_RC_IDENTITY_ID,
  ERROR_INVALID_RC_LOCK_ARGS,
  ERROR_ISO9796_2_VERIFY,
  ERROR_ARGS_FORMAT,
};

// parsed from args in lock script
typedef struct ArgsType {
  CkbIdentityType id;

  uint8_t rc_lock_flags;

  bool has_rc_root;
  uint8_t rc_root[32];

  bool has_since;
  uint64_t since;

  bool has_acp;
  int ckb_minimum;  // Used for ACP
  int udt_minimum;  // used for ACP

  bool has_supply;
  uint8_t info_cell[32];  // type script hash
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
// <identity, 21 bytes> <rc_lock args>
// <rc_lock flags, 1 byte>  <RC cell type id, 32 bytes, optional> <ckb/udt min,
// 2 bytes, optional> <since, 8 bytes, optional>
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
  mol_seg_t seg = MolReader_Bytes_raw_bytes(&args_seg);

  uint8_t *cur = seg.ptr;

  // parse flags
  CHECK2(is_memory_enough(seg, cur, 1), ERROR_ARGS_FORMAT);
  uint8_t flags = *cur;
  args->id.flags = flags;
  cur = safe_move_to(seg, cur, 1);
  CHECK2(cur != NULL, ERROR_ARGS_FORMAT);

  // parse blake160
  CHECK2(is_memory_enough(seg, cur, 20), ERROR_ARGS_FORMAT);
  memcpy(args->id.id, cur, BLAKE160_SIZE);
  cur = safe_move_to(seg, cur, 20);
  CHECK2(cur != NULL, ERROR_ARGS_FORMAT);

  CHECK2(is_memory_enough(seg, cur, 1), ERROR_ARGS_FORMAT);
  args->rc_lock_flags = *cur;
  cur = safe_move_to(seg, cur, 1);

  args->has_rc_root = args->rc_lock_flags & RC_ROOT_MASK;
  args->has_acp = args->rc_lock_flags & ACP_MASK;
  args->has_since = args->rc_lock_flags & SINCE_MASK;
  args->has_supply = args->rc_lock_flags & SUPPLY_MASK;
  uint32_t expected_size = 0;
  if (args->has_rc_root) {
    expected_size += 32;
  }
  if (args->has_acp) {
    expected_size += 2;
  }
  if (args->has_since) {
    expected_size += 8;
  }
  if (args->has_supply) {
    expected_size += 32;
  }

  if (expected_size == 0) {
    CHECK2(cur == NULL, ERROR_ARGS_FORMAT);
  } else {
    CHECK2(cur != NULL, ERROR_ARGS_FORMAT);
    CHECK2(is_memory_enough(seg, cur, expected_size), ERROR_ARGS_FORMAT);
    if (args->has_rc_root) {
      memcpy(args->rc_root, cur, 32);
      cur += 32;  // it's safe to move, already checked
    }
    if (args->has_acp) {
      args->ckb_minimum = cur[0];
      args->udt_minimum = cur[1];
      cur += 2;
    }
    if (args->has_since) {
      args->since = *(uint64_t *)cur;
      cur += 8;
    }
    if (args->has_supply) {
      memcpy(args->info_cell, cur, 32);
      cur += 32;
    }
    CHECK2(cur == (seg.ptr + seg.size), ERROR_INVALID_MOL_FORMAT);
  }

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
  memcpy(key + 1, id->id, BLAKE160_SIZE);

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
    memcpy(witness_lock->id.id, buff + 1, CKB_IDENTITY_LEN - 1);

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

#ifdef CKB_USE_SIM
int simulator_main() {
#else
int main() {
#endif
  // don't move code_buff into global variable. It doesn't work.
  // it's a ckb-vm bug: the global variable will be freezed:
  // https://github.com/nervosnetwork/ckb-vm/blob/d43f58d6bf8cc6210721fdcdb6e5ecba513ade0c/src/machine/elf_adaptor.rs#L28-L32
  // The code can't be loaded into frozen memory.
  uint8_t code_buff[MAX_CODE_SIZE] __attribute__((aligned(RISCV_PGSIZE)));

  int err = 0;

  WitnessLockType witness_lock = {0};
  ArgsType args = {0};
  // this identity can be either from witness lock (witness_lock.id) or script
  // args (args.id)
  CkbIdentityType identity = {0};

  err = parse_witness_lock(&witness_lock);
  CHECK(err);

  err = parse_args(&args);
  CHECK(err);

  if (args.has_rc_root) {
    if (witness_lock.has_rc_identity) {
      identity = witness_lock.id;
    } else {
      identity = args.id;
    }
  } else {
    identity = args.id;
  }

  // regulation compliance, also as administrators
  if (args.has_rc_root) {
    RceState rce_state;
    rce_init_state(&rce_state);
    rce_state.rcrules_in_input_cell = true;
    err = rce_gather_rcrules_recursively(&rce_state, args.rc_root, 0);
    CHECK(err);
    CHECK2(rce_state.rcrules_count > 0, ERROR_NO_RCRULE);
    CHECK2(rce_state.has_wl, ERROR_NO_WHITE_LIST);

    // verify blake160 against proof, using rc rules
    err = smt_verify_identity(&identity, &witness_lock.proofs, &rce_state);
    CHECK(err);
  } else {
    // time lock is not used for administrators
    if (args.has_since) {
      err = check_since(args.since);
      CHECK(err);
    }
    if (args.has_supply) {
      err = check_supply(args.info_cell);
      CHECK(err);
    }
    // ACP without signature is not used for administrators
    if (args.has_acp && !witness_lock.has_signature) {
      uint64_t min_ckb_amount = 0;
      uint128_t min_udt_amount = 0;
      process_amount(args.ckb_minimum, args.udt_minimum, &min_ckb_amount,
                     &min_udt_amount);
      // skip checking identity to follow ACP
      return check_payment_unlock(min_ckb_amount, min_udt_amount);
    }
  }
  ckb_identity_init_code_buffer(code_buff, MAX_CODE_SIZE);
  err = ckb_verify_identity(&identity, witness_lock.signature,
                            witness_lock.signature_size, witness_lock.preimage,
                            witness_lock.preimage_size);
  CHECK(err);
exit:
  return err;
}
