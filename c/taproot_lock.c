// uncomment to enable printf in CKB-VM
// #define CKB_C_STDLIB_PRINTF

// it's used by blockchain-api2.h, the behavior when panic
#ifndef MOL2_EXIT
#define MOL2_EXIT ckb_exit
#endif
int ckb_exit(signed char);

// configuration for secp256k1
#define ENABLE_MODULE_EXTRAKEYS
#define ENABLE_MODULE_SCHNORRSIG
#define SECP256K1_BUILD
// in secp256k1_ctz64_var: we don't have __builtin_ctzl in gcc for RISC-V
#define __builtin_ctzl secp256k1_ctz64_var_debruijn

// clang-format off
#include <stdio.h>
#include "blockchain-api2.h"
#define MOLECULEC_VERSION 7002
#include "blockchain.h"
#include "ckb_consts.h"

#if defined(CKB_USE_SIM)
// exclude ckb_dlfcn.h
#define CKB_C_STDLIB_CKB_DLFCN_H_
#include "ckb_syscall_taproot_lock_sim.h"
#else
#include "ckb_syscalls.h"
#endif
// secp256k1_helper_20210801.h is not part of ckb-c-stdlib, can't be included in ckb_identity.h
// An upgraded version is provided.
#include "secp256k1_helper_20210801.h"
#include "include/secp256k1_schnorrsig.h"
#include "ckb_swappable_signatures.h"
#include "ckb_identity.h"
#include "ckb_smt.h"

// CHECK is defined in secp256k1
#include "taproot_lock_mol2.h"
// clang-format on
#undef CHECK
#undef CHECK2
#define CHECK2(cond, code) \
  do {                     \
    if (!(cond)) {         \
      err = code;          \
      ASSERT(0);           \
      goto exit;           \
    }                      \
  } while (0)

#define CHECK(_code)    \
  do {                  \
    int code = (_code); \
    if (code != 0) {    \
      err = code;       \
      ASSERT(0);        \
      goto exit;        \
    }                   \
  } while (0)

#define SCRIPT_SIZE 32768
#define SCHNORR_SIGNATURE_SIZE (32 + 64)
#define SCHNORR_PUBKEY_SIZE 32
#define MAX_ARGS_SIZE 4096

enum TaprootLockErrorCode {
  // taproot lock error code is starting from 60
  ERROR_UNKNOWN_FLAGS = 60,
  ERROR_MOL,
  ERROR_ARGS,
  ERROR_SCHNORR,
};

// parsed from lock in witness
typedef struct WitnessLockType {
  bool has_signature;
  uint8_t signature[SCHNORR_SIGNATURE_SIZE];

  bool has_script_path;
  uint8_t taproot_output_key[32];
  uint8_t taproot_internal_key[32];
  uint8_t smt_root[32];
  int y_parity;
  uint8_t code_hash[32];
  uint8_t hash_type;
  uint8_t args[MAX_ARGS_SIZE];
  uint8_t args2[MAX_ARGS_SIZE];
} WitnessLockType;

int parse_args(CkbIdentityType *identity) {
  int err = 0;
  uint8_t script[SCRIPT_SIZE];
  uint64_t len = SCRIPT_SIZE;
  err = ckb_checked_load_script(script, &len, 0);
  CHECK(err);

  mol_seg_t script_seg;
  script_seg.ptr = script;
  script_seg.size = (mol_num_t)len;

  mol_errno mol_err = MolReader_Script_verify(&script_seg, false);
  CHECK2(mol_err == MOL_OK, ERROR_MOL);

  mol_seg_t args_seg = MolReader_Script_get_args(&script_seg);
  mol_seg_t seg = MolReader_Bytes_raw_bytes(&args_seg);
  CHECK2(seg.size == 21, ERROR_MOL);

  identity->flags = seg.ptr[0];
  memcpy(identity->id, seg.ptr + 1, 20);

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
  if (err != 0) {
    return err;
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

int parse_witness_lock(WitnessLockType *witness_lock) {
  int err = 0;

  WitnessArgsType witness_args;
  err = make_witness(&witness_args);
  CHECK(err);

  BytesOptType mol_lock = witness_args.t->lock(&witness_args);
  if (mol_lock.t->is_none(&mol_lock)) return err;

  mol2_cursor_t mol_lock_bytes = mol_lock.t->unwrap(&mol_lock);
  // convert Bytes to RcLockWitnessLock
  TaprootLockWitnessLockType mol_witness_lock =
      make_TaprootLockWitnessLock(&mol_lock_bytes);

  BytesOptType sig_opt = mol_witness_lock.t->signature(&mol_witness_lock);
  TaprootScriptPathOptType script_path_opt =
      mol_witness_lock.t->script_path(&mol_witness_lock);

  if (sig_opt.t->is_some(&sig_opt)) {
    CHECK2(script_path_opt.t->is_none(&script_path_opt), ERROR_MOL);
    mol2_cursor_t sig_bytes = sig_opt.t->unwrap(&sig_opt);
    CHECK2(sig_bytes.size == SCHNORR_SIGNATURE_SIZE, ERROR_MOL);
    uint32_t read_len = mol2_read_at(&sig_bytes, witness_lock->signature,
                                     SCHNORR_SIGNATURE_SIZE);
    CHECK2(read_len == SCHNORR_SIGNATURE_SIZE, ERROR_MOL);

    witness_lock->has_signature = true;
  } else if (script_path_opt.t->is_some(&script_path_opt)) {
    CHECK2(sig_opt.t->is_none(&sig_opt), ERROR_MOL);

  } else {
    CHECK2(false, ERROR_MOL);
  }
exit:
  return err;
}

int validate_signature_schnorr(void *prefilled_data, const uint8_t *sig,
                               size_t sig_len, const uint8_t *msg,
                               size_t msg_len, uint8_t *output,
                               size_t *output_len) {
  int err = 0;
  int success = 0;

  if (*output_len < BLAKE160_SIZE) {
    return ERROR_IDENTITY_ARGUMENTS_LEN;
  }
  if (sig_len != SCHNORR_SIGNATURE_SIZE || msg_len != 32) {
    return ERROR_IDENTITY_ARGUMENTS_LEN;
  }

  secp256k1_context ctx;
  uint8_t secp_data[CKB_SECP256K1_DATA_SIZE];
  err = ckb_secp256k1_custom_verify_only_initialize(&ctx, secp_data);
  CHECK(err);

  secp256k1_xonly_pubkey pk;
  success = secp256k1_xonly_pubkey_parse(&ctx, &pk, sig);
  CHECK2(success, ERROR_SCHNORR);
  success =
      secp256k1_schnorrsig_verify(&ctx, sig + SCHNORR_PUBKEY_SIZE, msg, &pk);
  CHECK2(success, ERROR_SCHNORR);

  blake2b_state blake2b_ctx;
  blake2b_init(&blake2b_ctx, BLAKE2B_BLOCK_SIZE);
  blake2b_update(&blake2b_ctx, sig, SCHNORR_PUBKEY_SIZE);
  blake2b_final(&blake2b_ctx, output, BLAKE2B_BLOCK_SIZE);
  *output_len = BLAKE160_SIZE;

exit:
  return err;
}

#ifdef CKB_USE_SIM
int simulator_main() {
#else
int main() {
#endif
  int err = 0;

  WitnessLockType witness_lock = {0};
  CkbIdentityType identity = {0};
  err = parse_args(&identity);
  CHECK(err);

  err = parse_witness_lock(&witness_lock);
  CHECK(err);

  if (witness_lock.has_signature) {
    // key path spending
    err = verify_sighash_all(identity.id, witness_lock.signature,
                             SCHNORR_SIGNATURE_SIZE, validate_signature_schnorr,
                             _ckb_convert_copy);
    CHECK(err);
  } else if (witness_lock.has_script_path) {
    // script path spending
  } else {
    CHECK2(false, ERROR_ARGS);
  }

exit:
  return err;
}
