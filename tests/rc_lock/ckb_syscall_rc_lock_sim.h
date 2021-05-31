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

#define VERY_LONG_DATA_SIZE 655360
#define MAX_PROOF_COUNT 64
#define SPECIAL_SECP256K1_INDEX 1111

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

slice_t copy_slice(uint8_t* ptr, uint32_t size) {
  slice_t s = new_slice(size);
  memcpy(s.ptr, ptr, size);
  return s;
}

void delete_slice(slice_t* t) {
  free(t->ptr);
  t->ptr = NULL;
  t->size = 0;
}

typedef struct SIMRCRule {
  uint8_t flags;
  uint8_t smt_root[32];
} SIMRCRule;

// set by users
typedef struct RcLockSettingType {
  uint8_t flags;         // identity's flags
  uint8_t blake160[20];  // identity's blake160
  bool use_rc;  // rc or not: if yes, the identity is in witness; otherwise it's
                // in args in lock script.
  uint8_t rc_root[32];    // in args in lock script
  uint8_t signature[65];  // in witness

  slice_t proofs[MAX_PROOF_COUNT];
  uint32_t proof_count;
  SIMRCRule rc_rules[MAX_PROOF_COUNT];
  // rc_rules with same length as proof

  slice_t input_lsh[64];
  uint8_t input_lsh_count;

  // test scheme
  bool wrong_signature;
  bool wrong_pubkey_hash;
  // owner lock without rc doesn't require witness
  bool empty_witness;
} RcLockSettingType;

RcLockSettingType g_setting = {0};

void init_input(RcLockSettingType* input) {
  memset(input, 0, sizeof(RcLockSettingType));
}

// states are generated by input
typedef struct RcLockStates {
  RcLockSettingType setting;

  slice_t witness[32];
  uint32_t witness_count;

  slice_t script;

  slice_t cell_data[64];
  uint32_t cell_data_count;
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

mol_seg_t build_identity(uint8_t flags, uint8_t* blake160) {
  mol_builder_t b;
  MolBuilder_Identity_init(&b);
  b.data_ptr[0] = flags;
  memcpy(&b.data_ptr[1], blake160, 20);
  mol_seg_res_t res = MolBuilder_Identity_build(b);
  ASSERT(res.errno == 0);
  return res.seg;
}

mol_seg_t build_rc_identity(mol_seg_t* identity, mol_seg_t* proofs) {
  mol_builder_t b;
  MolBuilder_RcIdentity_init(&b);
  MolBuilder_RcIdentity_set_identity(&b, identity->ptr, identity->size);
  MolBuilder_RcIdentity_set_proofs(&b, proofs->ptr, proofs->size);

  mol_seg_res_t res = MolBuilder_RcIdentity_build(b);
  ASSERT(res.errno == 0);
  return res.seg;
}

mol_seg_t build_witness_lock() {
  mol_builder_t witness_lock;
  MolBuilder_RcLockWitnessLock_init(&witness_lock);

  mol_seg_t signature =
      build_bytes(g_setting.signature, sizeof(g_setting.signature));
  mol_seg_t proofs = build_proof_vec(g_setting.proofs, g_setting.proof_count);
  mol_seg_t identity = build_identity(g_setting.flags, g_setting.blake160);
  mol_seg_t rc_identity = build_rc_identity(&identity, &proofs);

  MolBuilder_RcLockWitnessLock_set_signature(&witness_lock, signature.ptr,
                                             signature.size);
  if (g_setting.use_rc) {
    MolBuilder_RcLockWitnessLock_set_rc_identity(&witness_lock, rc_identity.ptr,
                                                 rc_identity.size);
  }

  free(signature.ptr);
  free(proofs.ptr);
  free(identity.ptr);
  free(rc_identity.ptr);

  mol_seg_res_t res = MolBuilder_RcLockWitnessLock_build(witness_lock);
  ASSERT(res.errno == 0);
  return res.seg;
}

slice_t build_rcrule(SIMRCRule* rcrule) {
  mol_builder_t b2;
  mol_union_builder_initialize(&b2, 64, 0, MolDefault_RCRule, 33);

  mol_builder_t b;
  MolBuilder_RCRule_init(&b);
  MolBuilder_RCRule_set_flags(&b, rcrule->flags);
  MolBuilder_RCRule_set_smt_root(&b, rcrule->smt_root);
  mol_seg_res_t res = MolBuilder_RCRule_build(b);
  ASSERT(res.errno == 0);
  MolBuilder_RCData_set_RCRule(&b2, res.seg.ptr, res.seg.size);
  free(res.seg.ptr);

  mol_seg_res_t res2 = MolBuilder_RCData_build(b2);
  ASSERT(res2.errno == 0);
  slice_t ret = {.ptr = res2.seg.ptr, .size = res2.seg.size};
  return ret;
}

void convert_rcrule(uint8_t* rc_root) {
  for (uint32_t i = 0; i < g_states.cell_data_count; i++) {
    free(g_states.cell_data[i].ptr);
  }
  g_states.cell_data_count = 0;

  mol_builder_t b2;
  mol_union_builder_initialize(&b2, 64, 0, MolDefault_RCRule, 33);

  mol_builder_t b;
  MolBuilder_RCCellVec_init(&b);
  for (uint32_t i = 0; i < g_setting.proof_count; i++) {
    uint8_t hash[32] = {0};
    // very small 2 byte index as hash
    *((uint16_t*)hash) = i;
    MolBuilder_RCCellVec_push(&b, hash);

    g_states.cell_data[i] = build_rcrule(g_setting.rc_rules + i);
  }
  mol_seg_res_t res = MolBuilder_RCCellVec_build(b);
  ASSERT(res.errno == 0);
  MolBuilder_RCData_set_RCCellVec(&b2, res.seg.ptr, res.seg.size);
  free(res.seg.ptr);

  mol_seg_res_t res2 = MolBuilder_RCData_build(b2);
  ASSERT(res2.errno == 0);
  slice_t ret = {.ptr = res2.seg.ptr, .size = res2.seg.size};

  g_states.cell_data[g_setting.proof_count] = ret;
  g_states.cell_data_count = g_setting.proof_count + 1;

  *((uint16_t*)rc_root) = g_setting.proof_count;
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
  uint8_t random_data[VERY_LONG_DATA_SIZE] = {1};
  mol_seg_t witness_input_type = build_bytes(random_data, sizeof(random_data));
  MolBuilder_WitnessArgs_set_input_type(&witness, witness_input_type.ptr,
                                        witness_input_type.size);

  free(witness_input_type.ptr);
  free(witness_lock.ptr);
  free(witness_lock_bytes.ptr);

  mol_seg_res_t res = MolBuilder_WitnessArgs_build(witness);
  ASSERT(res.errno == 0);

  g_states.witness[0].ptr = res.seg.ptr;
  g_states.witness[0].size = res.seg.size;
  g_states.witness_count = 1;
}

void convert_setting_to_states(void) {
  g_states.setting = g_setting;
  // IdentityFlagsPubkeyHash
  if (g_setting.flags == 0) {
    // make witness skeleton
    convert_witness();
    // sign
    uint8_t msg[32] = {0};
    uint8_t sig[65] = {0};
    uint8_t pubkey_hash[32] = {0};
    calculate_hash(msg);
    secp256k1_sign(msg, sig, pubkey_hash);

    memcpy(g_setting.blake160, pubkey_hash, 20);
    if (g_setting.wrong_pubkey_hash) {
      g_setting.blake160[0] ^= 0x1;
    }
    memcpy(g_setting.signature, sig, 65);
    if (g_setting.wrong_signature) {
      g_setting.signature[0] ^= 0x1;
    }
  }
  // will use rcrule, set rc root manually
  if (g_setting.use_rc) {
    convert_rcrule(g_setting.rc_root);
  }
  // make witness again, with correct signature
  convert_witness();

  // Script
  uint8_t script_args[1 + 20 + 32] = {0};
  if (g_setting.use_rc) {
    memcpy(script_args + 1 + 20, g_setting.rc_root, 32);
  } else {
    script_args[0] = g_setting.flags;
    memcpy(script_args + 1, g_setting.blake160, 20);
  }

  uint8_t code_hash[32] = {0};

  mol_seg_t script =
      build_script(code_hash, 0, script_args, sizeof(script_args));
  g_states.script.ptr = script.ptr;
  g_states.script.size = script.size;
}

void secp256k1_sign(const uint8_t* msg, uint8_t* serialized_sig,
                    uint8_t* pubkey_hash) {
  int ret = 0;
  secp256k1_pubkey pubkey;
  secp256k1_ecdsa_recoverable_signature sig;
  uint8_t key[32] = {0};
  for (size_t i = 0; i < sizeof(key); i++) {
    key[i] = i;
  }
  int recid = 0;

  size_t serialized_pubkey_len = 33;
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
                                      &serialized_pubkey_len, &pubkey,
                                      SECP256K1_EC_COMPRESSED);
  ASSERT(ret);

  blake2b_state blake2b_ctx;
  blake2b_init(&blake2b_ctx, 32);
  blake2b_update(&blake2b_ctx, serialized_pubkey, serialized_pubkey_len);
  blake2b_final(&blake2b_ctx, pubkey_hash, 32);

#if 0
  printf("{");
  for (int i = 0; i < 20; i++) {
    printf("%d,", pubkey_hash[i]);
  }
  printf("}\n");
#endif
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
    size_t temp_size = sizeof(temp);
    ret = secp256k1_ec_pubkey_serialize(ctx, temp, &temp_size, &pubkey2,
                                        SECP256K1_EC_COMPRESSED);
    ASSERT(ret);
    ASSERT(temp_size == 33);
    ret = memcmp(serialized_pubkey, temp, temp_size);
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
  unsigned char temp[VERY_LONG_DATA_SIZE + 1024];
  uint64_t witness_len = VERY_LONG_DATA_SIZE + 1024;
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

  if (g_setting.empty_witness) {
    *len = 0;
    return 0;
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
  if (source == CKB_SOURCE_CELL_DEP && index == SPECIAL_SECP256K1_INDEX) {
    ASSERT(*len == 1048576);
    FILE* input = fopen("build/secp256k1_data", "rb");
    size_t read_item = fread(addr, *len, 1, input);
    ASSERT(read_item == 1);

    return 0;
  }

  if (source == CKB_SOURCE_CELL_DEP) {
    ASSERT(index < g_states.cell_data_count);
    slice_t* cur = g_states.cell_data + index;
    if (addr == NULL) {
      *len = cur->size;
      return 0;
    }
    if (cur->size <= offset) {
      *len = 0;
      return 0;
    }
    uint32_t remaining = cur->size - offset;
    if (remaining > *len) {
      memcpy(addr, cur->ptr + offset, *len);
    } else {
      memcpy(addr, cur->ptr + offset, remaining);
    }
    *len = remaining;
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
      if (index >= g_states.setting.input_lsh_count) {
        return CKB_INDEX_OUT_OF_BOUND;
      }
      memcpy(addr, g_states.setting.input_lsh[index].ptr, 32);
      *len = 32;
    } else {
      ASSERT(false);
    }
  } else {
    if (source == CKB_SOURCE_CELL_DEP && field == CKB_CELL_FIELD_DATA_HASH) {
      if (index == SPECIAL_SECP256K1_INDEX) {
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
