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
#include "taproot_lock_mol.h"
#include "taproot_lock_mol2.h"
#include "ckb_consts.h"

#if defined(CKB_USE_SIM)
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

// clang-format on
// CHECK is defined in secp256k1
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

void debug_print_hex(const char *prefix, const uint8_t *buf, size_t length);

#define SCRIPT_SIZE 32768
#define SCHNORR_SIGNATURE_SIZE (32 + 64)
#define SCHNORR_PUBKEY_SIZE 32
#define MAX_ARGS_SIZE 32768
#define MAX_PROOF_SIZE 32768

enum TaprootLockErrorCode {
  // taproot lock error code is starting from 60
  ERROR_UNKNOWN_FLAGS = 60,
  ERROR_MOL,
  ERROR_ARGS,
  ERROR_SCHNORR,
  ERROR_MISMATCHED,
};

enum IdentityFlagsType2 {
  IdentityFlagsSchnorr = 0x6,
};

// parsed from lock in witness
typedef struct WitnessLockType {
  bool key_path_spending;
  uint8_t signature[SCHNORR_SIGNATURE_SIZE];

  bool script_path_spending;
  uint8_t taproot_output_key[32];
  uint8_t taproot_internal_key[32];
  uint8_t smt_root[32];
  uint8_t smt_proof[MAX_PROOF_SIZE];
  uint32_t smt_proof_len;

  int y_parity;
  uint8_t code_hash[32];
  uint8_t hash_type;
  uint8_t args[MAX_ARGS_SIZE];
  uint8_t script_hash[BLAKE2B_BLOCK_SIZE];

  uint32_t args_len;
  uint8_t args2[MAX_ARGS_SIZE];
  uint32_t args2_len;
} WitnessLockType;

const uint8_t TAG_TAPTWEAK[] = "TapTweak";
const size_t TAG_TAPTWEAK_LEN = sizeof(TAG_TAPTWEAK) - 1;
const uint8_t SMT_VALUE_ONE[32] = {1};

void ckb_tagged_hash(const uint8_t *tag, size_t tag_len, const uint8_t *msg,
                     size_t msg_len, uint8_t *out) {
  blake2b_state ctx;
  blake2b_init(&ctx, BLAKE2B_BLOCK_SIZE);
  blake2b_update(&ctx, tag, tag_len);
  blake2b_update(&ctx, msg, msg_len);
  blake2b_final(&ctx, out, BLAKE2B_BLOCK_SIZE);
}

void ckb_tagged_hash_tweak(const uint8_t *msg, size_t msg_len, uint8_t *out) {
  ckb_tagged_hash(TAG_TAPTWEAK, TAG_TAPTWEAK_LEN, msg, msg_len, out);
}

static void ckb_blake160(const uint8_t *msg, uint32_t msg_len,
                         uint8_t *output) {
  uint8_t temp[BLAKE2B_BLOCK_SIZE];
  blake2b_state blake2b_ctx;
  blake2b_init(&blake2b_ctx, BLAKE2B_BLOCK_SIZE);
  blake2b_update(&blake2b_ctx, msg, SCHNORR_PUBKEY_SIZE);
  blake2b_final(&blake2b_ctx, temp, BLAKE2B_BLOCK_SIZE);
  memcpy(output, temp, BLAKE160_SIZE);
}

void init_witness_lock(WitnessLockType *witness_lock) {
  witness_lock->args_len = 0;
  witness_lock->args2_len = 0;
  witness_lock->smt_proof_len = 0;
  witness_lock->key_path_spending = false;
  witness_lock->script_path_spending = false;
}

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
  CHECK2(seg.size == CKB_IDENTITY_LEN, ERROR_MOL);

  identity->flags = seg.ptr[0];
  memcpy(identity->id, seg.ptr + 1, CKB_IDENTITY_LEN - 1);

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
  CHECK2(!mol_lock.t->is_none(&mol_lock), ERROR_MOL);

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

    witness_lock->key_path_spending = true;
  } else if (script_path_opt.t->is_some(&script_path_opt)) {
    CHECK2(sig_opt.t->is_none(&sig_opt), ERROR_MOL);
    TaprootScriptPathType script_path =
        script_path_opt.t->unwrap(&script_path_opt);

    mol2_cursor_t cur = script_path.t->taproot_output_key(&script_path);
    uint32_t read_len =
        mol2_read_at(&cur, witness_lock->taproot_output_key, 32);
    CHECK2(read_len == 32, ERROR_MOL);
    cur = script_path.t->taproot_internal_key(&script_path);
    read_len = mol2_read_at(&cur, witness_lock->taproot_internal_key, 32);
    CHECK2(read_len == 32, ERROR_MOL);

    witness_lock->y_parity = script_path.t->y_parity(&script_path);

    cur = script_path.t->smt_root(&script_path);
    read_len = mol2_read_at(&cur, witness_lock->smt_root, 32);
    CHECK2(read_len == 32, ERROR_MOL);

    cur = script_path.t->smt_proof(&script_path);
    CHECK2(cur.size < MAX_PROOF_SIZE, ERROR_MOL);
    witness_lock->smt_proof_len = cur.size;
    read_len = mol2_read_at(&cur, witness_lock->smt_proof, cur.size);
    CHECK2(read_len == cur.size, ERROR_MOL);

    ScriptType exec_script = script_path.t->exec_script(&script_path);

    // calculate script hash for future use
    CHECK2(exec_script.cur.size < SCRIPT_SIZE, ERROR_MOL);
    uint8_t script_bytes[exec_script.cur.size];
    read_len =
        mol2_read_at(&exec_script.cur, script_bytes, exec_script.cur.size);
    CHECK2(read_len == exec_script.cur.size, ERROR_MOL);
    err = blake2b(witness_lock->script_hash, BLAKE2B_BLOCK_SIZE, script_bytes,
                  exec_script.cur.size, NULL, 0);
    CHECK(err);

    cur = exec_script.t->code_hash(&exec_script);
    read_len = mol2_read_at(&cur, witness_lock->code_hash, cur.size);
    CHECK2(read_len == 32, ERROR_MOL);

    witness_lock->hash_type = exec_script.t->hash_type(&exec_script);

    cur = exec_script.t->args(&exec_script);
    CHECK2(cur.size < MAX_ARGS_SIZE, ERROR_MOL);
    witness_lock->args_len = cur.size;
    read_len = mol2_read_at(&cur, witness_lock->args, cur.size);
    CHECK2(read_len == cur.size, ERROR_MOL);

    cur = script_path.t->args2(&script_path);
    CHECK2(cur.size < MAX_ARGS_SIZE, ERROR_MOL);
    witness_lock->args2_len = cur.size;
    read_len = mol2_read_at(&cur, witness_lock->args2, cur.size);
    CHECK2(read_len == cur.size, ERROR_MOL);

    witness_lock->script_path_spending = true;
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
#if 0
  printf("validate_signature_schnorr msg = %d, %d", msg[0], msg[1]);
  printf("validate_signature_schnorr pubkey = %d, %d", sig[0], sig[1]);
  printf("validate_signature_schnorr sig = %d, %d", sig[SCHNORR_PUBKEY_SIZE], sig[SCHNORR_PUBKEY_SIZE+1]);
#endif

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

  ckb_blake160(sig, SCHNORR_PUBKEY_SIZE, output);
  *output_len = BLAKE160_SIZE;
exit:
  return err;
}

int taproot_verify_script_path(uint8_t *output_key_bytes, int y_parity,
                               uint8_t *internal_key_bytes, uint8_t *tweak32) {
  int err = 0;
  int ret = 0;
  uint8_t real_tweak32[32];
#if 0
  debug_print_hex("output_key_bytes", output_key_bytes, 4);
  printf("y_parity = %d\n", y_parity);
  debug_print_hex("internal_key_bytes", internal_key_bytes, 4);
  debug_print_hex("smt_root", tweak32, 4);
#endif

  secp256k1_context ctx;
  uint8_t secp_data[CKB_SECP256K1_DATA_SIZE];
  err = ckb_secp256k1_custom_verify_only_initialize(&ctx, secp_data);
  CHECK(err);

  secp256k1_xonly_pubkey pubkey;
  ret = secp256k1_xonly_pubkey_parse(&ctx, &pubkey, internal_key_bytes);
  CHECK2(ret, ERROR_SCHNORR);

  uint8_t tagged_msg[64];
  memcpy(tagged_msg, internal_key_bytes, 32);
  memcpy(tagged_msg + 32, tweak32, 32);

  ckb_tagged_hash_tweak(tagged_msg, sizeof(tagged_msg), real_tweak32);

  ret = secp256k1_xonly_pubkey_tweak_add_check(&ctx, output_key_bytes, y_parity,
                                               &pubkey, real_tweak32);
  CHECK2(ret, ERROR_SCHNORR);
exit:
  return err;
}

static void get_hex(uint8_t x, char *out) {
  static char s_mapping[] = {'0', '1', '2', '3', '4', '5', '6', '7',
                             '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
  out[0] = s_mapping[(x >> 4) & 0x0F];
  out[1] = s_mapping[x & 0x0F];
}

int ckb_bin2hex(uint8_t *bin, size_t bin_size, char *hex, size_t hex_size) {
  if (hex_size < (2 * bin_size + 1)) {
    return ERROR_ARGS;
  }
  for (size_t i = 0; i < bin_size; i++) {
    get_hex(bin[i], hex + i * 2);
  }
  hex[2 * bin_size] = 0;
  return 0;
}

int exec_script(uint8_t *code_hash, uint8_t hash_type, uint8_t *args,
                uint32_t args_len, uint8_t *args2, uint32_t args2_len) {
  int err = 0;
  if (args_len >= MAX_ARGS_SIZE || args2_len >= MAX_ARGS_SIZE) {
    return ERROR_ARGS;
  }
  size_t hex_args_len = args_len * 2 + 1;
  char hex_args[args_len];
  size_t hex_args2_len = args2_len * 2 + 1;
  char hex_args2[args2_len];

  err = ckb_bin2hex(args, args_len, hex_args, hex_args_len);
  CHECK(err);

  err = ckb_bin2hex(args2, args2_len, hex_args2, hex_args2_len);
  CHECK(err);

  // 5.1.2.2.1 Program startup
  //...
  //-- argv[argc] shall be a null pointer.
  const char *argv[3] = {hex_args, hex_args2, 0};
  err = ckb_exec_cell(code_hash, hash_type, 0, 0, 2, argv);
  CHECK(err);

exit:
  return err;
}

int verify_script_path(WitnessLockType *witness_lock,
                       CkbIdentityType *identity) {
  int err = 0;

  uint8_t blake160[BLAKE160_SIZE];
  ckb_blake160(witness_lock->taproot_output_key, SCHNORR_PUBKEY_SIZE, blake160);

  int equal = memcmp(blake160, identity->id, BLAKE160_SIZE);
  CHECK2(equal == 0, ERROR_MISMATCHED);

  err = taproot_verify_script_path(
      witness_lock->taproot_output_key, witness_lock->y_parity,
      witness_lock->taproot_internal_key, witness_lock->smt_root);
  CHECK(err);

  smt_state_t states;
  smt_pair_t pairs[1];
  smt_state_init(&states, pairs, 1);
  smt_state_insert(&states, witness_lock->script_hash, SMT_VALUE_ONE);
  smt_state_normalize(&states);

  err = smt_verify(witness_lock->smt_root, &states, witness_lock->smt_proof,
                   witness_lock->smt_proof_len);
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

  WitnessLockType witness_lock;
  init_witness_lock(&witness_lock);

  CkbIdentityType identity = {0};
  err = parse_args(&identity);
  CHECK(err);
  CHECK2(identity.flags == IdentityFlagsSchnorr, ERROR_ARGS);

  err = parse_witness_lock(&witness_lock);
  CHECK(err);

  if (witness_lock.key_path_spending) {
    // key path spending
    err = verify_sighash_all(identity.id, witness_lock.signature,
                             SCHNORR_SIGNATURE_SIZE, validate_signature_schnorr,
                             _ckb_convert_copy);
    CHECK(err);
  } else if (witness_lock.script_path_spending) {
    // script path spending
    err = verify_script_path(&witness_lock, &identity);
    CHECK(err);
    err = exec_script(witness_lock.code_hash, witness_lock.hash_type,
                      witness_lock.args, witness_lock.args_len,
                      witness_lock.args2, witness_lock.args2_len);
    CHECK(err);
  } else {
    CHECK2(false, ERROR_ARGS);
  }

exit:
  return err;
}
