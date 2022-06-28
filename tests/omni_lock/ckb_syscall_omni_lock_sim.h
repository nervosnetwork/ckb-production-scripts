// note, this macro must be same as in ckb_syscall.h
#ifndef CKB_C_STDLIB_CKB_SYSCALLS_H_
#define CKB_C_STDLIB_CKB_SYSCALLS_H_
#include <stddef.h>
#include <stdint.h>

#undef ASSERT
#include <assert.h>
#define ASSERT assert
#include <blake2b.h>

#include "include/secp256k1.h"
#include "include/secp256k1_recovery.h"
#include "omni_lock_mol.h"
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

  // info cell
  bool use_supply;
  unsigned __int128 input_current_supply;
  unsigned __int128 input_max_supply;
  unsigned __int128 output_current_supply;
  unsigned __int128 output_max_supply;
  unsigned __int128 input_sudt;
  unsigned __int128 output_sudt;

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

// input cell, output cell
typedef struct RcLockCellType {
  uint8_t type_script_hash[32];
  slice_t data;
} RcLockCellType;

// states are generated by input
typedef struct RcLockStates {
  RcLockSettingType setting;

  slice_t witness[32];
  uint32_t witness_count;

  slice_t script;

  slice_t cell_data[64];
  uint32_t cell_data_count;

  // tsh: type script hash
  uint8_t info_cell_tsh[32];
  uint8_t sudt_script_hash[32];

  RcLockCellType input_cells[64];
  uint32_t input_cells_count;
  RcLockCellType output_cells[64];
  uint32_t output_cells_count;
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

mol_seg_t build_auth(uint8_t flags, uint8_t* blake160) {
  mol_builder_t b;
  MolBuilder_Auth_init(&b);
  b.data_ptr[0] = flags;
  memcpy(&b.data_ptr[1], blake160, 20);
  mol_seg_res_t res = MolBuilder_Auth_build(b);
  ASSERT(res.errno == 0);
  return res.seg;
}

mol_seg_t build_rc_identity(mol_seg_t* identity, mol_seg_t* proofs) {
  mol_builder_t b;
  MolBuilder_Identity_init(&b);
  MolBuilder_Identity_set_identity(&b, identity->ptr, identity->size);
  MolBuilder_Identity_set_proofs(&b, proofs->ptr, proofs->size);

  mol_seg_res_t res = MolBuilder_Identity_build(b);
  ASSERT(res.errno == 0);
  return res.seg;
}

mol_seg_t build_witness_lock() {
  mol_builder_t witness_lock;
  MolBuilder_OmniLockWitnessLock_init(&witness_lock);

  mol_seg_t signature =
      build_bytes(g_setting.signature, sizeof(g_setting.signature));
  mol_seg_t proofs = build_proof_vec(g_setting.proofs, g_setting.proof_count);
  mol_seg_t identity = build_auth(g_setting.flags, g_setting.blake160);
  mol_seg_t rc_identity = build_rc_identity(&identity, &proofs);

  MolBuilder_OmniLockWitnessLock_set_signature(&witness_lock, signature.ptr,
                                               signature.size);
  if (g_setting.use_rc) {
    MolBuilder_OmniLockWitnessLock_set_omni_identity(
        &witness_lock, rc_identity.ptr, rc_identity.size);
  }

  free(signature.ptr);
  free(proofs.ptr);
  free(identity.ptr);
  free(rc_identity.ptr);

  mol_seg_res_t res = MolBuilder_OmniLockWitnessLock_build(witness_lock);
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

slice_t make_info_cell(unsigned __int128 current_supply,
                       unsigned __int128 max_supply,
                       uint8_t* sudt_script_hash) {
  slice_t s = new_slice(65);
  s.ptr[0] = 0;
  memcpy(&s.ptr[1], &current_supply, 16);
  memcpy(&s.ptr[17], &max_supply, 16);
  memcpy(&s.ptr[33], sudt_script_hash, 32);
  return s;
}

slice_t make_sudt_cell(unsigned __int128 amount) {
  slice_t s = new_slice(16);
  memcpy(s.ptr, &amount, 16);
  return s;
}

void convert_cell() {
  for (uint32_t i = 0; i < g_states.input_cells_count; i++) {
    free(g_states.input_cells[i].data.ptr);
  }
  g_states.input_cells_count = 0;

  for (uint32_t i = 0; i < g_states.output_cells_count; i++) {
    free(g_states.output_cells[i].data.ptr);
  }
  g_states.output_cells_count = 0;

  // special type script hash
  g_states.info_cell_tsh[0] = 1;
  g_states.sudt_script_hash[0] = 2;

  g_states.input_cells_count = 2;
  memcpy(g_states.input_cells[0].type_script_hash, g_states.info_cell_tsh, 32);
  g_states.input_cells[0].data = make_info_cell(
      g_states.setting.input_current_supply, g_states.setting.input_max_supply,
      g_states.sudt_script_hash);
  memcpy(g_states.input_cells[1].type_script_hash, g_states.sudt_script_hash,
         32);
  g_states.input_cells[1].data = make_sudt_cell(g_setting.input_sudt);

  g_states.output_cells_count = 2;
  memcpy(g_states.output_cells[0].type_script_hash, g_states.info_cell_tsh, 32);
  g_states.output_cells[0].data = make_info_cell(
      g_states.setting.output_current_supply,
      g_states.setting.output_max_supply, g_states.sudt_script_hash);
  memcpy(g_states.output_cells[1].type_script_hash, g_states.sudt_script_hash,
         32);
  g_states.output_cells[1].data = make_sudt_cell(g_setting.output_sudt);
}

void convert_setting_to_states(void) {
  g_states.setting = g_setting;
  convert_cell();
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
  uint8_t script_args[1 + 20 + 1 + 32 + 2 + 8] = {0};
  uint32_t script_args_len = 22;

  if (g_setting.use_rc) {
    memcpy(script_args + 1 + 20 + 1, g_setting.rc_root, 32);
    script_args[1 + 20] |= 1;
    script_args_len += 32;
  } else if (g_setting.use_supply) {
    script_args[0] = g_setting.flags;
    memcpy(script_args + 1, g_setting.blake160, 20);

    memcpy(script_args + 1 + 20 + 1, g_states.info_cell_tsh, 32);
    script_args[1 + 20] |= 1 << 3;
    script_args_len += 32;
  } else {
    script_args[0] = g_setting.flags;
    memcpy(script_args + 1, g_setting.blake160, 20);
  }

  uint8_t code_hash[32] = {0};

  mol_seg_t script = build_script(code_hash, 0, script_args, script_args_len);
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

int ckb_load_script(void* addr, uint64_t* len, size_t offset) {
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
                            size_t index, size_t source, size_t field) {
  return -1;
}

int ckb_load_cell_code(void* addr, size_t memory_size, size_t content_offset,
                       size_t content_size, size_t index, size_t source);

// follow store_data<Mac: SupportMachine>(machine: &mut Mac, data: &[u8])
int store_data(slice_t* cur, void* addr, uint64_t* len, size_t offset) {
  if (addr == NULL) {
    *len = cur->size - offset;
    return 0;
  }
  offset = cur->size > offset ? offset : cur->size;
  uint32_t full_size = cur->size - offset;
  uint32_t real_size = *len > full_size ? full_size : *len;
  memcpy(addr, cur->ptr + offset, real_size);
  *len = full_size;
  return 0;
}

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
    return store_data(cur, addr, len, offset);
  }
  if (source == CKB_SOURCE_OUTPUT || source == CKB_SOURCE_INPUT) {
    slice_t* cur = NULL;
    if (source == CKB_SOURCE_INPUT) {
      if (index < g_states.input_cells_count) {
        cur = &g_states.input_cells[index].data;
      } else {
        return CKB_INDEX_OUT_OF_BOUND;
      }
    }
    if (source == CKB_SOURCE_OUTPUT) {
      if (index < g_states.output_cells_count) {
        cur = &g_states.output_cells[index].data;
      } else {
        return CKB_INDEX_OUT_OF_BOUND;
      }
    }
    return store_data(cur, addr, len, offset);
  }
  return CKB_LENGTH_NOT_ENOUGH;
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
    return 0;
  } else if (source == CKB_SOURCE_CELL_DEP &&
             field == CKB_CELL_FIELD_DATA_HASH) {
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
  } else if (field == CKB_CELL_FIELD_TYPE_HASH) {
    if (source == CKB_SOURCE_INPUT) {
      if (index < g_states.input_cells_count) {
        ASSERT(*len >= 32 && offset == 0);
        memcpy(addr, g_states.input_cells[index].type_script_hash, 32);
        *len = 32;
        return 0;
      } else {
        return CKB_INDEX_OUT_OF_BOUND;
      }
    } else if (source == CKB_SOURCE_OUTPUT) {
      if (index < g_states.output_cells_count) {
        ASSERT(*len >= 32 && offset == 0);
        memcpy(addr, g_states.output_cells[index].type_script_hash, 32);
        *len = 32;
        return 0;
      } else {
        return CKB_INDEX_OUT_OF_BOUND;
      }
    } else {
      ASSERT(false);
    }
    return 0;
  } else {
    ASSERT(false);
  }
  return -1;
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

int ckb_checked_load_input_by_field(void* addr, uint64_t* len, size_t offset,
                                    size_t index, size_t source, size_t field) {
  return 0;
}

long __internal_syscall(long n, long _a0, long _a1, long _a2, long _a3,
                        long _a4, long _a5) {
  return 0;
}

#define syscall(n, a, b, c, d, e, f)                                           \
  __internal_syscall(n, (long)(a), (long)(b), (long)(c), (long)(d), (long)(e), \
                     (long)(f))

#include <dlfcn.h>

#define ERROR_MEMORY_NOT_ENOUGH -23
#define ERROR_DYNAMIC_LOADING -24
#define RISCV_PGSIZE 4096
#define ROUNDUP(a, b) ((((a)-1) / (b) + 1) * (b))
#define MAX_PATH_SIZE 1024

typedef struct LibMappingEntry {
  uint8_t dep_cell_hash[32];
  char path[MAX_PATH_SIZE];
} LibMappingEntry;

#define MAX_LIB_MAPPING_COUNT 1024
LibMappingEntry g_lib_mapping[MAX_LIB_MAPPING_COUNT];
int g_lib_size = 0;

void ckbsim_map_lib(const uint8_t* dep_cell_hash, const char* path) {
  if (g_lib_size >= MAX_LIB_MAPPING_COUNT) {
    ASSERT(false);
    return;
  }
  ASSERT(strlen(path) < MAX_PATH_SIZE);

  memcpy(g_lib_mapping[g_lib_size].dep_cell_hash, dep_cell_hash, 32);
  strcpy(g_lib_mapping[g_lib_size].path, path);

  g_lib_size++;
}

bool file_exists(const char* path) {
  FILE* fp = fopen(path, "r");
  if (fp != NULL) {
    fclose(fp);
  };
  return fp != NULL;
}

void file_with_so(const char* input, char* output, uint32_t output_len) {
  strcpy(output, input);
  char* pos = strchr(output, '.');
  if (pos != NULL) {
    *pos = 0;
    strcat(output, ".so");
  }
}

int ckbsim_get_lib(const uint8_t* dep_cell_hash, char* path) {
  for (int i = 0; i < g_lib_size; i++) {
    if (memcmp(g_lib_mapping[i].dep_cell_hash, dep_cell_hash, 32) == 0) {
      const char* target = g_lib_mapping[i].path;
      if (file_exists(target)) {
        strcpy(path, target);
      } else {
        char output[1024] = {0};
        file_with_so(target, output, sizeof(output));
        if (file_exists(output)) {
          strcpy(path, output);
        } else {
          ASSERT(false);
          return -1;
        }
      }
      return 0;
    }
  }
  return 1;
}

size_t get_file_size(const char* path) {
  FILE* fp = fopen(path, "r");
  ASSERT(fp != NULL);
  fseek(fp, 0L, SEEK_END);
  long size = ftell(fp);
  fclose(fp);

  return size;
}

int ckb_dlopen2(const uint8_t* dep_cell_hash, uint8_t hash_type,
                uint8_t* aligned_addr, size_t aligned_size, void** handle,
                size_t* consumed_size) {
  int err = 0;
  (void)hash_type;
  (void)aligned_size;

  char path[MAX_PATH_SIZE] = {0};
  ASSERT((aligned_size % RISCV_PGSIZE) == 0);
  ASSERT(((size_t)aligned_addr) % RISCV_PGSIZE == 0);

  err = ckbsim_get_lib(dep_cell_hash, path);
  ASSERT(err == 0);

  *handle = dlopen(path, RTLD_NOW);
  *consumed_size = 0;

  if (*handle == NULL) {
    printf("Error occurs in dlopen: %s\n", dlerror());
    ASSERT(false);
    return -1;
  }
  return 0;
}

void* ckb_dlsym(void* handle, const char* symbol) {
  void* ret = dlsym(handle, symbol);
  ASSERT(ret != NULL);
  return ret;
}

int ckb_exec_cell(const uint8_t* code_hash, uint8_t hash_type, uint32_t offset,
                  uint32_t length, int argc, const char* argv[]) {
  return 0;
}

#undef ASSERT
#define ASSERT(s) (void)0

#endif
