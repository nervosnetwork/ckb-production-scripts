// note, this macro must be same as in ckb_syscall.h
#ifndef CKB_C_STDLIB_CKB_SYSCALLS_H_
#define CKB_C_STDLIB_CKB_SYSCALLS_H_
#include <stddef.h>
#include <stdint.h>

#undef ASSERT
#include <assert.h>
#define ASSERT assert
#include "include/secp256k1.h"
#include "include/secp256k1_recovery.h"
#include "rc_lock_mol.h"
#include "xudt_rce_mol.h"

#define countof(s) (sizeof(s) / sizeof(s[0]))
mol_seg_t build_bytes(const uint8_t* data, uint32_t len);
mol_seg_t build_script(const uint8_t* code_hash, uint8_t hash_type,
                       const uint8_t* args, uint32_t args_len);
int ckb_load_tx_hash(void* addr, uint64_t* len, size_t offset);
int ckb_load_witness(void* addr, uint64_t* len, size_t offset, size_t index,
                     size_t source);
int calculate_hash(uint8_t* msg);
void secp256k1_sign(const uint8_t* msg, uint8_t* serialized_sig,
                    uint8_t* pubkey_hash);

typedef struct slice_t {
  uint8_t* ptr;
  uint32_t size;
} slice_t;

slice_t new_slice(uint32_t size) {
  slice_t res = {.ptr = malloc(size), .size = size};
  memset(res.ptr, 0, size);
  return res;
}

void delete_slice(slice_t* t) {
  free(t->ptr);
  t->ptr = NULL;
  t->size = 0;
}

// set by users
typedef struct RcLockInputType {
  uint8_t flags;               // in args in lock script
  uint8_t pubkey_hash[20];     // in args in lock script
  uint8_t rc_rule[32];         // in args in lock script
  uint8_t signature[65];       // in witness
  uint8_t lsh_in_witness[32];  // in witness
  slice_t proof[64];           // in witness
  uint32_t proof_count;

  slice_t input_lsh[64];
  uint8_t input_lsh_count;

  // test scheme
  bool wrong_signature;
  bool wrong_pubkey_hash;
} RcLockInputType;

RcLockInputType g_input;

void init_input(RcLockInputType* input) {
  memset(input, 0, sizeof(RcLockInputType));
}

// states are generated by input
typedef struct RcLockStates {
  RcLockInputType input;

  slice_t witness[32];
  uint32_t witness_count;

  slice_t script;
} RcLockStates;

RcLockStates g_states;

mol_seg_t build_proof(slice_t proof) {
  mol_builder_t builder;
  MolBuilder_SmtProofEntry_init(&builder);
  mol_seg_t bytes = build_bytes(proof.ptr, proof.size);
  MolBuilder_SmtProofEntry_set_proof(&builder, bytes.ptr, bytes.size);
  MolBuilder_SmtProofEntry_set_mask(&builder, 3);
  free(bytes.ptr);

  mol_seg_res_t res = MolBuilder_SmtProofEntry_build(builder);
  ASSERT(res.errno == 0);
  return res.seg;
}

mol_seg_t build_proof_vec(slice_t* proof, uint32_t proof_len) {
  mol_builder_t proofs;
  MolBuilder_SmtProofEntryVec_init(&proofs);

  for (uint32_t i = 0; i < proof_len; i++) {
    mol_seg_t b = build_proof(proof[i]);
    MolBuilder_SmtProofEntryVec_push(&proofs, b.ptr, b.size);
    free(b.ptr);
  }
  mol_seg_res_t res = MolBuilder_SmtProofEntryVec_build(proofs);
  ASSERT(res.errno == 0);
  return res.seg;
}

mol_seg_t build_witness_lock() {
  mol_builder_t witness_lock;
  MolBuilder_RcLockWitnessLock_init(&witness_lock);

  mol_seg_t sig_bytes =
      build_bytes(g_input.signature, sizeof(g_input.signature));
  mol_seg_t lsh_bytes =
      build_bytes(g_input.lsh_in_witness, sizeof(g_input.lsh_in_witness));
  mol_seg_t proof_bytes = build_proof_vec(g_input.proof, g_input.proof_count);

  MolBuilder_RcLockWitnessLock_set_signature(&witness_lock, sig_bytes.ptr,
                                             sig_bytes.size);
  MolBuilder_RcLockWitnessLock_set_lock_script_hash(
      &witness_lock, lsh_bytes.ptr, lsh_bytes.size);
  MolBuilder_RcLockWitnessLock_set_proofs(&witness_lock, proof_bytes.ptr,
                                          proof_bytes.size);

  free(sig_bytes.ptr);
  free(lsh_bytes.ptr);
  free(proof_bytes.ptr);
  mol_seg_res_t res = MolBuilder_RcLockWitnessLock_build(witness_lock);
  ASSERT(res.errno == 0);
  return res.seg;
}

void convert_witness(void) {
  for (size_t i = 0; i < g_states.witness_count; i++) {
    free(g_states.witness[i].ptr);
  }
  g_states.witness_count = 0;

  // Witness
  mol_seg_t witness_lock = build_witness_lock();
  mol_seg_t witness_lock_bytes =
      build_bytes(witness_lock.ptr, witness_lock.size);

  mol_builder_t witness;
  MolBuilder_WitnessArgs_init(&witness);
  MolBuilder_WitnessArgs_set_lock(&witness, witness_lock_bytes.ptr,
                                  witness_lock_bytes.size);
  // TODO put some long input in type_input and type_output
  free(witness_lock.ptr);
  free(witness_lock_bytes.ptr);

  mol_seg_res_t res = MolBuilder_WitnessArgs_build(witness);
  ASSERT(res.errno == 0);

  g_states.witness[0].ptr = res.seg.ptr;
  g_states.witness[0].size = res.seg.size;
  g_states.witness_count = 1;
}

void convert_input_to_states(void) {
  // make witness skeleton
  convert_witness();
  // sign
  uint8_t msg[32] = {0};
  uint8_t sig[65] = {0};
  uint8_t pubkey_hash[32] = {0};
  calculate_hash(msg);
  secp256k1_sign(msg, sig, pubkey_hash);

  memcpy(g_input.pubkey_hash, pubkey_hash, 20);
  if (g_input.wrong_pubkey_hash) {
    g_input.pubkey_hash[0] ^= 0x1;
  }
  memcpy(g_input.signature, sig, 65);
  if (g_input.wrong_signature) {
    g_input.signature[0] ^= 0x1;
  }
  // make witness again, with correct signature
  convert_witness();

  // Script
  uint8_t script_args[1 + 20 + 32];
  script_args[0] = g_input.flags;
  memcpy(script_args + 1, g_input.pubkey_hash, 20);
  memcpy(script_args + 1 + 20, g_input.rc_rule, 32);
  uint8_t code_hash[32] = {0};

  mol_seg_t script =
      build_script(code_hash, 0, script_args, sizeof(script_args));
  g_states.script.ptr = script.ptr;
  g_states.script.size = script.size;
}

void secp256k1_sign(const uint8_t* msg,       // 32 bytes
                    uint8_t* serialized_sig,  // 65 bytes
                    uint8_t* pubkey_hash      // 32 bytes
) {
  int ret = 0;
  secp256k1_pubkey pubkey;
  secp256k1_ecdsa_recoverable_signature sig;
  uint8_t key[32] = {0};
  for (size_t i = 0; i < sizeof(key); i++) {
    key[i] = i;
  }
  int recid = 0;

  size_t serialized_pubkeylen = 33;
  uint8_t serialized_pubkey[33];

  secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN |
                                                    SECP256K1_CONTEXT_VERIFY);
  ret = secp256k1_ecdsa_sign_recoverable(ctx, &sig, msg, key, NULL, NULL);
  ASSERT(ret);

  ret = secp256k1_ecdsa_recoverable_signature_serialize_compact(
      ctx, serialized_sig, &recid, &sig);
  ASSERT(ret);
  serialized_sig[64] = recid;

  ret = secp256k1_ec_pubkey_create(ctx, &pubkey, key);
  ASSERT(ret);
  ret = secp256k1_ec_pubkey_serialize(ctx, serialized_pubkey,
                                      &serialized_pubkeylen, &pubkey,
                                      SECP256K1_EC_COMPRESSED);
  ASSERT(ret);

  blake2b_state blake2b_ctx;
  blake2b_init(&blake2b_ctx, 32);
  blake2b_update(&blake2b_ctx, serialized_pubkey, serialized_pubkeylen);
  blake2b_final(&blake2b_ctx, pubkey_hash, 32);
  // verify, self testing
  {
    secp256k1_ecdsa_recoverable_signature signature;
    ret = secp256k1_ecdsa_recoverable_signature_parse_compact(
        ctx, &signature, serialized_sig, serialized_sig[64]);
    ASSERT(ret);

    secp256k1_pubkey pubkey2;

    ret = secp256k1_ecdsa_recover(ctx, &pubkey2, &signature, msg);
    ASSERT(ret);

    uint8_t temp[33];
    size_t pubkey_size = 33;
    ret = secp256k1_ec_pubkey_serialize(ctx, temp, &pubkey_size, &pubkey2,
                                        SECP256K1_EC_COMPRESSED);
    ASSERT(ret);
    ret = memcmp(serialized_pubkey, temp, 33);
    ASSERT(ret == 0);
  }
}

static int extract_witness_lock2(uint8_t* witness, uint64_t len,
                                 mol_seg_t* lock_bytes_seg) {
  if (len < 20) {
    return 1;
  }
  uint32_t lock_length = *((uint32_t*)(&witness[16]));
  if (len < 20 + lock_length) {
    return 1;
  } else {
    lock_bytes_seg->ptr = &witness[20];
    lock_bytes_seg->size = lock_length;
  }
  return 0;
}

int calculate_hash(uint8_t* msg) {
  int ret;
  uint64_t len = 0;
  unsigned char temp[32768 * 10];
  uint64_t witness_len = 32768 * 10;
  /* Load witness of first input */
  ret = ckb_load_witness(temp, &witness_len, 0, 0, CKB_SOURCE_GROUP_INPUT);
  ASSERT(ret == 0);

  /* load signature */
  mol_seg_t lock_bytes_seg;
  ret = extract_witness_lock2(temp, witness_len, &lock_bytes_seg);
  ASSERT(ret == 0);

  /* Load tx hash */
  unsigned char tx_hash[32];
  len = 32;
  ret = ckb_load_tx_hash(tx_hash, &len, 0);
  ASSERT(ret == 0);
  /* Prepare sign message */
  blake2b_state blake2b_ctx;
  blake2b_init(&blake2b_ctx, 32);
  blake2b_update(&blake2b_ctx, tx_hash, 32);

  /* Clear lock field to zero, then digest the first witness */
  memset((void*)lock_bytes_seg.ptr, 0, lock_bytes_seg.size);
  blake2b_update(&blake2b_ctx, (char*)&witness_len, sizeof(uint64_t));
  blake2b_update(&blake2b_ctx, temp, witness_len);

  blake2b_final(&blake2b_ctx, msg, 32);
  return 0;
}

int ckb_exit(int8_t code) {
  exit(code);
  return 0;
}

int ckb_load_tx_hash(void* addr, uint64_t* len, size_t offset) {
  ASSERT(offset == 0);
  ASSERT(*len == 32);
  for (int i = 0; i < *len; i++) {
    ((uint8_t*)addr)[i] = 0;
  }
  return 0;
}

int ckb_checked_load_script(void* addr, uint64_t* len, size_t offset);

int ckb_load_cell(void* addr, uint64_t* len, size_t offset, size_t index,
                  size_t source);

int ckb_load_input(void* addr, uint64_t* len, size_t offset, size_t index,
                   size_t source);

int ckb_load_header(void* addr, uint64_t* len, size_t offset, size_t index,
                    size_t source);

int ckb_load_script_hash(void* addr, uint64_t* len, size_t offset) { return 0; }

int ckb_checked_load_script_hash(void* addr, uint64_t* len, size_t offset) {
  uint64_t old_len = *len;
  int ret = ckb_load_script_hash(addr, len, offset);
  if (ret == CKB_SUCCESS && (*len) > old_len) {
    ret = CKB_LENGTH_NOT_ENOUGH;
  }
  return ret;
}

int ckb_load_witness(void* addr, uint64_t* len, size_t offset, size_t index,
                     size_t source) {
  if (index > 0) {
    return CKB_INDEX_OUT_OF_BOUND;
  }
  slice_t seg = g_states.witness[0];

  if (addr == NULL) {
    *len = seg.size;
    return 0;
  }
  if (seg.size <= offset) {
    *len = 0;
    return 0;
  }
  uint32_t remaining = seg.size - offset;
  if (remaining > *len) {
    memcpy(addr, seg.ptr + offset, *len);
  } else {
    memcpy(addr, seg.ptr + offset, remaining);
  }
  *len = remaining;

  return 0;
}

int ckb_checked_load_witness(void* addr, uint64_t* len, size_t offset,
                             size_t index, size_t source) {
  uint64_t old_len = *len;
  int ret = ckb_load_witness(addr, len, offset, index, source);
  if (ret == CKB_SUCCESS && (*len) > old_len) {
    ret = CKB_LENGTH_NOT_ENOUGH;
  }
  return ret;
}

mol_seg_t build_bytes(const uint8_t* data, uint32_t len) {
  mol_builder_t b;
  mol_seg_res_t res;
  MolBuilder_Bytes_init(&b);
  for (uint32_t i = 0; i < len; i++) {
    MolBuilder_Bytes_push(&b, data[i]);
  }
  res = MolBuilder_Bytes_build(b);
  return res.seg;
}

mol_seg_t build_script(const uint8_t* code_hash, uint8_t hash_type,
                       const uint8_t* args, uint32_t args_len) {
  mol_builder_t b;
  mol_seg_res_t res;
  MolBuilder_Script_init(&b);

  MolBuilder_Script_set_code_hash(&b, code_hash, 32);
  MolBuilder_Script_set_hash_type(&b, hash_type);
  mol_seg_t bytes = build_bytes(args, args_len);
  MolBuilder_Script_set_args(&b, bytes.ptr, bytes.size);

  res = MolBuilder_Script_build(b);
  assert(res.errno == 0);
  assert(MolReader_Script_verify(&res.seg, false) == 0);
  free(bytes.ptr);
  return res.seg;
}

int ckb_checked_load_script(void* addr, uint64_t* len, size_t offset) {
  ASSERT(offset == 0);
  ASSERT(*len > g_states.script.size);

  memcpy(addr, g_states.script.ptr, g_states.script.size);
  *len = g_states.script.size;
  return 0;
}

int ckb_load_cell_by_field(void* addr, uint64_t* len, size_t offset,
                           size_t index, size_t source, size_t field);

int ckb_load_header_by_field(void* addr, uint64_t* len, size_t offset,
                             size_t index, size_t source, size_t field);

int ckb_load_input_by_field(void* addr, uint64_t* len, size_t offset,
                            size_t index, size_t source, size_t field);

int ckb_load_cell_code(void* addr, size_t memory_size, size_t content_offset,
                       size_t content_size, size_t index, size_t source);

int ckb_load_cell_data(void* addr, uint64_t* len, size_t offset, size_t index,
                       size_t source) {
  if (source == CKB_SOURCE_CELL_DEP && index == 42) {
    ASSERT(*len == 1048576);
    FILE* input = fopen("../../build/secp256k1_data", "rb");
    size_t read_item = fread(addr, *len, 1, input);
    ASSERT(read_item == 1);

    return 0;
  }
  return 0;
}

int ckb_checked_load_cell_data(void* addr, uint64_t* len, size_t offset,
                               size_t index, size_t source) {
  return ckb_load_cell_data(addr, len, offset, index, source);
}

int ckb_debug(const char* s);

/* load the actual witness for the current type verify group.
   use this instead of ckb_load_witness if type contract needs args to verify
   input/output.
 */
int load_actual_type_witness(uint8_t* buf, uint64_t* len, size_t index,
                             size_t* type_source);

int ckb_look_for_dep_with_hash(const uint8_t* data_hash, size_t* index);

int ckb_calculate_inputs_len() { return 1; }

int ckb_load_cell_by_field(void* addr, uint64_t* len, size_t offset,
                           size_t index, size_t source, size_t field) {
  if (field == CKB_CELL_FIELD_LOCK_HASH) {
    if (source == CKB_SOURCE_GROUP_OUTPUT || source == CKB_SOURCE_OUTPUT) {
      ASSERT(false);
    } else if (source == CKB_SOURCE_INPUT) {
      ASSERT(offset == 0);
      ASSERT(*len >= 32);
      if (index >= g_states.input.input_lsh_count) {
        return CKB_INDEX_OUT_OF_BOUND;
      }
      memcpy(addr, g_states.input.input_lsh[index].ptr, 32);
      *len = 32;
    } else {
      ASSERT(false);
    }
  } else {
    if (source == CKB_SOURCE_CELL_DEP && field == CKB_CELL_FIELD_DATA_HASH) {
      if (index == 42) {
        static uint8_t ckb_secp256k1_data_hash[32] = {
            151, 153, 190, 226, 81,  185, 117, 184, 44, 69,  160,
            33,  84,  206, 40,  206, 200, 156, 88,  83, 236, 193,
            77,  18,  183, 184, 204, 207, 193, 158, 10, 244};
        memcpy(addr, ckb_secp256k1_data_hash, 32);
      } else {
        memset(addr, 0, 32);
      }
      return 0;
    } else {
      ASSERT(false);
    }
  }
  return 0;
}

int ckb_checked_load_cell_by_field(void* addr, uint64_t* len, size_t offset,
                                   size_t index, size_t source, size_t field) {
  uint64_t old_len = *len;
  int ret = ckb_load_cell_by_field(addr, len, offset, index, source, field);
  if (ret == 0 && (*len) > old_len) {
    ret = CKB_LENGTH_NOT_ENOUGH;
  }
  return ret;
}

int ckb_look_for_dep_with_hash2(const uint8_t* code_hash, uint8_t hash_type,
                                size_t* index) {
  *index = *(uint16_t*)code_hash;
  return 0;
}

#undef ASSERT
#define ASSERT(s) (void)0

#endif
