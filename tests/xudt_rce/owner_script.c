#include "dump.h"

#ifndef MOL2_EXIT
#define MOL2_EXIT ckb_exit
#endif
int ckb_exit(signed char);

#include <stddef.h>
#include <stdint.h>

// in secp256k1_ctz64_var: we don't have __builtin_ctzl in gcc for RISC-V
#define __builtin_ctzl secp256k1_ctz64_var_debruijn

#include "ckb_swappable_signatures.h"
#include "ckb_syscalls.h"
#include "secp256k1_helper_20210801.h"
#include "validate_signature_rsa.h"

#include "blockchain.h"
#include "ckb_consts.h"
#include "ckb_identity.h"
// #include "xudt_rce_mol.h"

#define MAX_WITNESS_SIZE 32768

#define ERROR_UNREACHABLE -1;
#define ERROR_ARGUMENTS_LEN -2;
#define ERROR_PUBKEY_BLAKE160_HASH -3;
#define ERROR_ENCODING -4;
#define ERROR_SYSCALL -5;

// uint8_t g_witness_data_source[DEFAULT_DATA_SOURCE_LENGTH];
// // due to the "static" data (s_witness_data_source), the "WitnessArgsType" is
// a
// // singleton. note: mol2_data_source_t consumes a lot of memory due to the
// // "cache" field (default 2K)
// int make_cursor_from_witness(WitnessArgsType *witness, bool *use_input_type)
// {
//   int err = 0;
//   uint64_t witness_len = 0;
//   // at the beginning of the transactions including RCE,
//   // there is no "witness" in CKB_SOURCE_GROUP_INPUT
//   // here we use the first witness of CKB_SOURCE_GROUP_OUTPUT
//   // same logic is applied to rce_validator
//   size_t source = CKB_SOURCE_GROUP_INPUT;
//   err = ckb_load_witness(NULL, &witness_len, 0, 0, source);
//   if (err == CKB_INDEX_OUT_OF_BOUND) {
//     source = CKB_SOURCE_GROUP_OUTPUT;
//     err = ckb_load_witness(NULL, &witness_len, 0, 0, source);
//     *use_input_type = false;
//   } else {
//     *use_input_type = true;
//   }
//   CHECK(err);
//   CHECK2(witness_len > 0, ERROR_INVALID_MOL_FORMAT);
//
//   mol2_cursor_t cur;
//
//   cur.offset = 0;
//   cur.size = witness_len;
//
//   mol2_data_source_t *ptr = (mol2_data_source_t *)g_witness_data_source;
//
//   ptr->read = read_from_witness;
//   ptr->total_size = witness_len;
//   // pass index and source as args
//   ptr->args[0] = 0;
//   ptr->args[1] = source;
//
//   ptr->cache_size = 0;
//   ptr->start_point = 0;
//   ptr->max_cache_size = MAX_CACHE_SIZE;
//   cur.data_source = ptr;
//
//   *witness = make_WitnessArgs(&cur);
//
//   err = 0;
// exit:
//   return err;
// }
//
// int get_owner_script(uint8_t *buff, uint32_t buff_len, uint32_t *out_len) {
//   int err = 0;
//   bool use_input_type = true;
//   err = make_cursor_from_witness(&g_witness_args, &use_input_type);
//   CHECK(err);
//   CHECK2(use_input_type, ERROR_INVALID_MOL_FORMAT);
//   BytesOptType input = g_witness_args.t->input_type(&g_witness_args);
//   CHECK2(!input.t->is_none(&input), ERROR_INVALID_MOL_FORMAT);
//
//   mol2_cursor_t bytes = input.t->unwrap(&input);
//   // convert Bytes to XudtWitnessInputType
//   XudtWitnessInputType witness_input = make_XudtWitnessInput(&bytes);
//   ScriptOptType owner_script = witness_input.t->owner_script(&witness_input);
//   CHECK2(!owner_script.t->is_none(&owner_script), ERROR_INVALID_MOL_FORMAT);
//   ScriptType owner_script2 = owner_script.t->unwrap(&owner_script);
//   *out_len = mol2_read_at(&owner_script2.cur, buff, buff_len);
//   CHECK2(*out_len == owner_script2.cur.size, ERROR_INVALID_MOL_FORMAT);
//
//   err = 0;
// exit:
//   return err;
// }

/* Extract lock from WitnessArgs */
int extract_owner_signature_from_witness(uint8_t *witness, uint64_t len,
                                         mol_seg_t *signature_bytes_seg) {
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
  *signature_bytes_seg = MolReader_Bytes_raw_bytes(&lock_seg);
  return CKB_SUCCESS;
}

int get_owner_signature() {

  int ret;

  unsigned char witness_bytes[MAX_WITNESS_SIZE];
  uint64_t witness_len = MAX_WITNESS_SIZE;
  ret = ckb_load_witness(witness_bytes, &witness_len, 0, 0,
                         CKB_SOURCE_GROUP_INPUT);
  if (ret != CKB_SUCCESS) {
    return ERROR_SYSCALL;
  }

  if (witness_len > MAX_WITNESS_SIZE) {
    return ERROR_ENCODING;
  }

  /* load signature */
  mol_seg_t witness_signature_seg;
  ret = extract_owner_signature_from_witness(witness_bytes, witness_len,
                                             &witness_signature_seg);
  if (ret != 0) {
    return ERROR_ENCODING;
  }

  if (witness_signature_seg.size != SIGNATURE_SIZE) {
    return ERROR_ARGUMENTS_LEN;
  }
  return CKB_SUCCESS;
}

__attribute__((visibility("default"))) int validate(int _is_owner_mode,
                                                    size_t _extension_index,
                                                    const uint8_t *args,
                                                    size_t args_len) {
  printf("hello world\n");
  int ret = 0;
  // Read owner pk hash from args.
  if (args_len != BLAKE160_SIZE) {
    return ERROR_ARGUMENTS_LEN;
  }

  hex_dump("args", (const void *)args, args_len, 0);

  // Read signature from witness.

  const size_t sig_size = 16;
  uint8_t sig[sig_size];

  hex_dump("sig", (const void *)sig, sig_size, 0);

  // Validate signature.
  ret = verify_sighash_all((uint8_t *)args, sig, sig_size,
                           validate_signature_secp256k1, _ckb_convert_copy);
  printf("verify sighash all result %d\n", ret);
  return 0;
  return ret;
}
