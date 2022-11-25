#include "dump.h"

#ifndef MOL2_EXIT
#define MOL2_EXIT ckb_exit
#endif
int ckb_exit(signed char);

#include <stddef.h>
#include <stdint.h>

// in secp256k1_ctz64_var: we don't have __builtin_ctzl in gcc for RISC-V
#define __builtin_ctzl secp256k1_ctz64_var_debruijn

// clang-format off
#include "blockchain.h"
#include "blake2b.h"
#include "ckb_consts.h"
#include "ckb_swappable_signatures.h"
#include "ckb_syscalls.h"
#include "secp256k1_helper_20210801.h"
#include "ckb_identity.h"
#include "validate_signature_rsa.h"
#include "xudt_rce_mol.h"

#define MAX_WITNESS_SIZE 32768

#define ERROR_UNREACHABLE -100;
#define ERROR_ILLEGAL_ARGUMENTS -101;
#define ERROR_SIGNATURE_VERIFICATION -102;
#define ERROR_ENCODING -103;
#define ERROR_SYSCALL -104;

int get_owner_signature(uint8_t signature[SIGNATURE_SIZE]) {
  int ret = 0;
  unsigned char witness_bytes[MAX_WITNESS_SIZE];
  uint64_t witness_len = MAX_WITNESS_SIZE;
  ret = ckb_load_witness(witness_bytes, &witness_len, 0, 0,
                         CKB_SOURCE_GROUP_INPUT);
  if (ret != CKB_SUCCESS) {
    printf("Error while load witness: %d\n", ret);
    return ERROR_SYSCALL;
  }

  if (witness_len > MAX_WITNESS_SIZE) {
    printf("Error witness too large\n");
    return ERROR_ENCODING;
  }

  mol_seg_t witness_seg;
  witness_seg.ptr = witness_bytes;
  witness_seg.size = witness_len;

  if (MolReader_WitnessArgs_verify(&witness_seg, false) != MOL_OK) {
    printf("Error while verifying WitnessArgs\n");
    return ERROR_ENCODING;
  }

  mol_seg_t witness_input_type_seg =
      MolReader_WitnessArgs_get_input_type(&witness_seg);

  if (MolReader_BytesOpt_is_none(&witness_input_type_seg)) {
    printf("Error input_type in witness is empty\n");
    return ERROR_ENCODING;
  }

  mol_seg_t witness_input_seg =
      MolReader_Bytes_raw_bytes(&witness_input_type_seg);

  if (MolReader_XudtWitnessInput_verify(&witness_input_seg, false) != MOL_OK) {
    printf("Error while verifying XudtWitnessInput\n");
    return ERROR_ENCODING;
  }

  mol_seg_t signature_bytes_seg =
      MolReader_XudtWitnessInput_get_owner_signature(&witness_input_seg);

  if (MolReader_BytesOpt_is_none(&signature_bytes_seg)) {
    printf("Error owner_signature in witness is empty\n");
    return ERROR_ENCODING;
  }

  mol_seg_t signature_seg = MolReader_Bytes_raw_bytes(&signature_bytes_seg);

  if (signature_seg.size != SIGNATURE_SIZE) {
    printf("Error wrong signature size: got %d, expecting %d\n",
           signature_seg.size, SIGNATURE_SIZE);
    hex_dump("signature", signature_seg.ptr, signature_seg.size, 0);
    return ERROR_ENCODING;
  }

  memcpy(signature, signature_seg.ptr, signature_seg.size);
  return CKB_SUCCESS;
}

int verify_signature(uint8_t *pk_hash, uint64_t pk_hash_len, uint8_t *sig,
                     uint64_t sig_len) {
  if (pk_hash_len != BLAKE160_SIZE) {
    return ERROR_ILLEGAL_ARGUMENTS;
  }

  uint64_t tx_hash_len = BLAKE2B_BLOCK_SIZE;
  unsigned char tx_hash[BLAKE2B_BLOCK_SIZE];
  int ret = ckb_load_tx_hash(tx_hash, &tx_hash_len, 0);
  if (ret != CKB_SUCCESS) {
    return ret;
  }
  if (tx_hash_len != BLAKE2B_BLOCK_SIZE) {
    return ERROR_UNREACHABLE;
  }

  uint8_t output_pk_hash[BLAKE160_SIZE];
  uint64_t output_pk_hash_len = BLAKE160_SIZE;
  ret =
      validate_signature_secp256k1(NULL, sig, sig_len, tx_hash, sizeof(tx_hash),
                                   output_pk_hash, &output_pk_hash_len);

  if (ret != 0) {
    return ret;
  }
  if (output_pk_hash_len != BLAKE2B_BLOCK_SIZE) {
    return ERROR_UNREACHABLE;
  }

  if (memcmp(pk_hash, output_pk_hash, BLAKE160_SIZE) != 0) {
    hex_dump("pk hash in arguments", (const void *)pk_hash, pk_hash_len, 0);
    hex_dump("pk hash from output", (const void *)output_pk_hash, output_pk_hash_len, 0);
    return ERROR_SIGNATURE_VERIFICATION;
  }

  return 0;
}

__attribute__((visibility("default"))) int validate(int _is_owner_mode,
                                                    size_t _extension_index,
                                                    const uint8_t *args,
                                                    size_t args_len) {
  int ret = 0;
  uint8_t signature[SIGNATURE_SIZE];

  hex_dump("args", (const void *)args, args_len, 0);

  // Read signature from witness.
  ret = get_owner_signature(signature);
  if (ret != 0) {
    printf("Error while fetching owner signature\n", ret);
    return ret;
  }

  hex_dump("sig", (const void *)signature, SIGNATURE_SIZE, 0);

  // Validate signature.
  ret = verify_signature((uint8_t *)args, args_len, signature, SIGNATURE_SIZE);
  printf("verify sighash all result %d\n", ret);
  return ret;
}
