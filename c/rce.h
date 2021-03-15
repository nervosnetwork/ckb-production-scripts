#ifndef XUDT_RCE_SIMULATOR_C_RCE_H_
#define XUDT_RCE_SIMULATOR_C_RCE_H_
#include "ckb_smt.h"

int get_extesion_data(uint32_t index, mol_seg_t* item);

#define MAX_RCRULES_COUNT 8192

// RC stands for Regulation Compliance
typedef struct RCRule {
  uint8_t smt_root[32];
  uint8_t flags;
} RCRule;

RCRule g_rcrules[MAX_RCRULES_COUNT];
uint32_t g_rcrules_count = 0;

// molecule doesn't provide names
typedef enum RCDataUnionType {
  RDUT_RCRule = 0,
  RDUT_RCCellVec = 1
} RCDataUnionType;

// RCE scripts leverage optimized sparse merkle tree
// (https://github.com/jjyr/sparse-merkle-tree)(SMT) extensively to reduce
// storage costs. For each sparse merkle tree used here, the key will be lock
// script hash, values are either 0 or 1: 0 represents the corresponding lock
// hash is missing in the sparse merkle tree, whereas 1 means the lock hash is
// included in the sparse merkle tree.
uint8_t SMT_VALUE_NOT_EXISTING[SMT_VALUE_BYTES] = {0};
uint8_t SMT_VALUE_EXISTING[SMT_VALUE_BYTES] = {1};

bool is_white_list(uint8_t flags) { return flags & 0x2; }

bool is_emergency_halt_mode(uint8_t flags) { return flags & 0x1; }

// Note: RCRules is ordered as depth-first search
int gather_rcrules_recursively(const uint8_t* rce_cell_hash, int depth) {
  int err = 0;

  // TODO:
  if (depth > 10) return ERROR_RCRULES_TOO_DEEP;

  size_t index = 0;
  // note: RCE Cell is with hash_type = 1
  err = ckb_look_for_dep_with_hash2(rce_cell_hash, 1, &index);
  if (err != 0) return err;

  // pre-fetch the length, reduce stack size
  uint64_t cell_data_len = 0;
  err = ckb_load_cell_data(NULL, &cell_data_len, 0, index, CKB_SOURCE_CELL_DEP);
  if (err != 0) return err;

  uint8_t cell_data[cell_data_len];

  err = ckb_checked_load_cell_data(cell_data, &cell_data_len, 0, index,
                                   CKB_SOURCE_CELL_DEP);
  CHECK(err);

  mol_seg_t seg;
  seg.ptr = cell_data;
  seg.size = cell_data_len;

  CHECK2(MolReader_RCData_verify(&seg, false) == MOL_OK,
         ERROR_INVALID_MOL_FORMAT);
  mol_union_t u = MolReader_RCData_unpack(&seg);
  if (u.item_id == RDUT_RCRule) {
    CHECK2(MolReader_RCRule_verify(&u.seg, false) == MOL_OK,
           ERROR_INVALID_MOL_FORMAT);

    mol_seg_t smt_root = MolReader_RCRule_get_smt_root(&u.seg);
    mol_seg_t flags = MolReader_RCRule_get_flags(&u.seg);
    // "Any more RCRule structures will result in an immediate failure."
    CHECK2(g_rcrules_count < MAX_RCRULES_COUNT, ERROR_TOO_MANY_RCRULES);
    g_rcrules[g_rcrules_count].flags = *(flags.ptr);
    memcpy(g_rcrules[g_rcrules_count].smt_root, smt_root.ptr, SMT_KEY_BYTES);

    g_rcrules_count++;
  } else if (u.item_id == RDUT_RCCellVec) {
    CHECK2(MolReader_RCCellVec_verify(&u.seg, false) == MOL_OK,
           ERROR_INVALID_MOL_FORMAT);

    uint32_t len = MolReader_RCCellVec_length(&u.seg);
    for (uint32_t i = 0; i < len; i++) {
      mol_seg_res_t cell = MolReader_RCCellVec_get(&u.seg, i);
      CHECK2(cell.errno == MOL_OK, ERROR_INVALID_MOL_FORMAT);
      CHECK2(seg.size == SMT_KEY_BYTES, ERROR_INVALID_MOL_FORMAT);

      err = gather_rcrules_recursively(seg.ptr, depth + 1);
      CHECK(err);
    }
  } else {
    CHECK2(false, ERROR_INVALID_MOL_FORMAT);
  }

  err = 0;
exit:
  return err;
}

int collect_hashes(smt_state_t* bl_states, smt_state_t* wl_states) {
  int err = 0;
  uint32_t index = 0;

  uint8_t lock_script_hash[SMT_KEY_BYTES];
  uint64_t lock_script_hash_len = SMT_KEY_BYTES;

  index = 0;
  while (true) {
    err = ckb_checked_load_cell_by_field(
        lock_script_hash, &lock_script_hash_len, 0, index,
        CKB_SOURCE_GROUP_INPUT, CKB_CELL_FIELD_LOCK_HASH);
    if (err == CKB_INDEX_OUT_OF_BOUND) {
      break;
    }
    err = smt_state_insert(wl_states, lock_script_hash, SMT_VALUE_EXISTING);
    CHECK(err);
    err = smt_state_insert(bl_states, lock_script_hash, SMT_VALUE_NOT_EXISTING);
    CHECK(err);
    index++;
  }
  index = 0;
  while (true) {
    err = ckb_checked_load_cell_by_field(
        lock_script_hash, &lock_script_hash_len, 0, index,
        CKB_SOURCE_GROUP_OUTPUT, CKB_CELL_FIELD_LOCK_HASH);
    if (err == CKB_INDEX_OUT_OF_BOUND) {
      break;
    }
    err = smt_state_insert(wl_states, lock_script_hash, SMT_VALUE_EXISTING);
    CHECK(err);
    err = smt_state_insert(bl_states, lock_script_hash, SMT_VALUE_NOT_EXISTING);
    CHECK(err);
    index++;
  }

  err = 0;
exit:
  return err;
}

int rce_validate(int is_owner_mode, size_t extension_index, const uint8_t* args,
                 size_t args_len) {
  int err = 0;
  uint32_t index = 0;

  CHECK2(args_len == BLAKE2B_BLOCK_SIZE, ERROR_INVALID_MOL_FORMAT);
  CHECK2(args != NULL, ERROR_INVALID_ARGS);
  // TODO: RCE under owner mode
  if (is_owner_mode) return 0;

  g_rcrules_count = 0;
  err = gather_rcrules_recursively(args, 0);
  CHECK(err);

  mol_seg_t structure = {0};
  err = get_extesion_data(extension_index, &structure);
  CHECK(err);

  CHECK2(MolReader_Bytes_verify(&structure, false) == MOL_OK,
         ERROR_INVALID_MOL_FORMAT);
  mol_seg_t proofs = MolReader_Bytes_raw_bytes(&structure);
  CHECK2(MolReader_SmtProofVec_verify(&proofs, false) == MOL_OK,
         ERROR_INVALID_MOL_FORMAT);
  uint32_t proof_len = MolReader_SmtProofVec_length(&proofs);
  // count of proof should be same as size of RCRules
  CHECK2(proof_len == g_rcrules_count, ERROR_RCRULES_PROOFS_MISMATCHED);

  // TODO: limit?
  smt_pair_t wl_entries[MAX_LOCK_SCRIPT_HASH_COUNT];
  smt_pair_t bl_entries[MAX_LOCK_SCRIPT_HASH_COUNT];
  smt_state_t wl_states;
  smt_state_t bl_states;
  smt_state_init(&wl_states, wl_entries, MAX_LOCK_SCRIPT_HASH_COUNT);
  smt_state_init(&bl_states, bl_entries, MAX_LOCK_SCRIPT_HASH_COUNT);

  err = collect_hashes(&bl_states, &wl_states);
  CHECK(err);

  smt_state_normalize(&wl_states);
  smt_state_normalize(&bl_states);
  for (index = 0; index < proof_len; index++) {
    mol_seg_res_t mol_proof = MolReader_SmtProofVec_get(&proofs, index);
    CHECK(mol_proof.errno);
    mol_seg_t proof = MolReader_SmtProof_raw_bytes(&mol_proof.seg);

    const RCRule* current_rule = &g_rcrules[index];

    const uint8_t* root_hash = current_rule->smt_root;
    // "Current RCRule must not be in Emergency Halt mode."
    if (is_emergency_halt_mode(current_rule->flags)) {
      return ERROR_RCE_EMERGENCY_HATL;
    }
    if (is_white_list(current_rule->flags)) {
      err = smt_verify(root_hash, &wl_states, proof.ptr, proof.size);
    } else {
      err = smt_verify(root_hash, &bl_states, proof.ptr, proof.size);
    }
    CHECK2(err == 0, ERROR_SMT_VERIFY_FAILED);
  }
  err = 0;
exit:
  return err;
}

#endif
