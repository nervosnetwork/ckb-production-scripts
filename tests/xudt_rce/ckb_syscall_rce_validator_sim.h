// note, this macro must be same as in ckb_syscall.h
#ifndef CKB_C_STDLIB_CKB_SYSCALLS_H_
#define CKB_C_STDLIB_CKB_SYSCALLS_H_
#include <stddef.h>
#include <stdint.h>
#undef ASSERT
#include <assert.h>
#define ASSERT assert

#include "xudt_rce_mol.h"

mol_seg_t build_bytes(const uint8_t *data, uint32_t len) {
  mol_builder_t b;
  mol_seg_res_t res;
  MolBuilder_Bytes_init(&b);
  for (uint32_t i = 0; i < len; i++) {
    MolBuilder_Bytes_push(&b, data[i]);
  }
  res = MolBuilder_Bytes_build(b);
  return res.seg;
}

mol_seg_t build_script(const uint8_t *code_hash, uint8_t hash_type,
                       const uint8_t *args, uint32_t args_len) {
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

#define MAX_RCDATA_COUNT (8192 * 2)

typedef uint16_t RCHashType;

typedef struct SIMRCRule {
  uint8_t id; // id = 0
  uint8_t flags;
  uint8_t smt_root[32];
} SIMRCRule;
#define MAX_RCRULE_IN_CELL 16
typedef struct SIMRCCellVec {
  uint8_t id; // id = 1
  uint8_t hash_count;
  RCHashType hash[MAX_RCRULE_IN_CELL];
} SIMRCCellVec;

typedef union SIMRCData {
  SIMRCRule rcrule;
  SIMRCCellVec rccell_vec;
} SIMRCData;

mol_seg_t build_rcdata(SIMRCData *rcdata) {
  mol_builder_t b2;
  mol_union_builder_initialize(&b2, 64, 0, MolDefault_RCRule, 33);
  if (rcdata->rcrule.id == 0) {
    // RCRule
    mol_builder_t b;
    MolBuilder_RCRule_init(&b);
    MolBuilder_RCRule_set_flags(&b, rcdata->rcrule.flags);
    MolBuilder_RCRule_set_smt_root(&b, rcdata->rcrule.smt_root);
    mol_seg_res_t res = MolBuilder_RCRule_build(b);
    ASSERT(res.errno == 0);

    MolBuilder_RCData_set_RCRule(&b2, res.seg.ptr, res.seg.size);
    free(res.seg.ptr);
  } else if (rcdata->rcrule.id == 1) {
    // RCCellVec
    mol_builder_t b;
    MolBuilder_RCCellVec_init(&b);
    for (uint8_t i = 0; i < rcdata->rccell_vec.hash_count; i++) {
      uint8_t hash[32] = {0};
      // very small 2-byte hash
      *((RCHashType *)hash) = rcdata->rccell_vec.hash[i];
      MolBuilder_RCCellVec_push(&b, hash);
    }
    mol_seg_res_t res = MolBuilder_RCCellVec_build(b);
    ASSERT(res.errno == 0);

    MolBuilder_RCData_set_RCCellVec(&b2, res.seg.ptr, res.seg.size);
    free(res.seg.ptr);
  } else {
    ASSERT(false);
  }
  mol_seg_res_t res2 = MolBuilder_RCData_build(b2);
  ASSERT(res2.errno == 0);
  return res2.seg;
}

void load_offset(uint8_t *source_buff, uint64_t source_size, void *addr,
                 uint64_t *len, size_t offset) {
  assert(source_size > offset);
  assert(*len > 0);

  uint64_t size = MIN(source_size - offset, *len);
  memcpy(addr, source_buff + offset, size);
  *len = size;
}

uint8_t g_script_code_hash[32] = {0};
uint8_t g_script_type_id[32] = {0};
uint8_t g_script_flags = 0;
uint8_t g_script_hash_type = 0;
int g_cell_group_exists[2][2] = {{1, 0}, {1, 0}};
SIMRCData g_sim_rcdata[MAX_RCDATA_COUNT][2];
uint16_t g_sim_rcdata_count[2] = {0, 0};
uint8_t g_witness[1024 * 100] = {1};
int g_witness_size = 1024 * 100;

uint8_t k1[32] = {111};
uint8_t k2[32] = {222};
uint8_t smt_ooo_root[32] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
uint8_t smt_one_root[32] = {62,  195, 223, 65,  89,  79,  50,  133,
                            172, 95,  118, 228, 237, 101, 113, 8,
                            175, 152, 171, 153, 202, 45,  125, 177,
                            0,   236, 236, 176, 183, 31,  109, 113};
uint8_t smt_two_root[32] = {143, 95, 66, 207, 251, 51,  58,  199, 247, 61,  211,
                            60,  28, 25, 51,  99,  174, 94,  226, 239, 134, 201,
                            125, 79, 63, 194, 180, 109, 161, 2,   92,  178};
uint8_t smt_ooo_not_k1_proof[1] = {76};
uint8_t smt_one_has_k1_proof[35] = {76,  80,  7,  88,  178, 89,  155, 132, 146,
                                    222, 163, 40, 147, 106, 150, 97,  234, 134,
                                    107, 237, 60, 9,   193, 0,   16,  226, 17,
                                    209, 89,  52, 22,  71,  135, 172, 225};
uint8_t smt_one_not_k2_proof[35] = {76, 80,  7,   62,  195, 223, 65,  89,  79,
                                    50, 133, 172, 95,  118, 228, 237, 101, 113,
                                    8,  175, 152, 171, 153, 202, 45,  125, 177,
                                    0,  236, 236, 176, 183, 31,  109, 113};
uint8_t smt_tow_has_k2_proof[35] = {76, 80,  7,   62,  195, 223, 65,  89,  79,
                                    50, 133, 172, 95,  118, 228, 237, 101, 113,
                                    8,  175, 152, 171, 153, 202, 45,  125, 177,
                                    0,  236, 236, 176, 183, 31,  109, 113};

#define countof(s) (sizeof(s) / sizeof(s[0]))

int ckb_exit(int8_t code) {
  exit(code);
  return 0;
}

int ckb_load_tx_hash(void *addr, uint64_t *len, size_t offset) { return 0; }

int ckb_load_transaction(void *addr, uint64_t *len, size_t offset) { return 0; }

int ckb_load_script_hash(void *addr, uint64_t *len, size_t offset) { return 0; }

int ckb_load_script(void *addr, uint64_t *len, size_t offset) {
  uint8_t buf[33] = {};
  memcpy(buf, g_script_type_id, 32);
  buf[32] = g_script_flags;
  mol_seg_t seg =
      build_script(g_script_code_hash, g_script_hash_type, buf, sizeof(buf));
  if (addr == NULL) {
    *len = seg.size;
  } else {
    load_offset(seg.ptr, seg.size, addr, len, offset);
  };
  free(seg.ptr);
  return 0;
}

int ckb_debug(const char *s) { return 0; }

int ckb_load_cell(void *addr, uint64_t *len, size_t offset, size_t index,
                  size_t source) {
  if (source == CKB_SOURCE_GROUP_INPUT) {
    ASSERT(offset == 0);
    return g_cell_group_exists[0][index] == 0;
  } else if (source == CKB_SOURCE_GROUP_OUTPUT) {
    ASSERT(offset == 0);
    return g_cell_group_exists[1][index] == 0;
  } else if (source == CKB_SOURCE_CELL_DEP) {
    ASSERT(offset == 0);
    ASSERT(false);
  } else {
    ASSERT(false);
  }
}

int ckb_load_input(void *addr, uint64_t *len, size_t offset, size_t index,
                   size_t source) {
  return 0;
}

int ckb_load_header(void *addr, uint64_t *len, size_t offset, size_t index,
                    size_t source) {
  return 0;
}

int ckb_load_witness(void *addr, uint64_t *len, size_t offset, size_t index,
                     size_t source) {
  ASSERT(index == 0);
  if (*len != 0) {
    load_offset(g_witness, g_witness_size, addr, len, offset);
  }
  *len = g_witness_size - offset;
  return 0;
}

int ckb_load_cell_by_field(void *addr, uint64_t *len, size_t offset,
                           size_t index, size_t source, size_t field) {
  return 0;
}

int ckb_load_header_by_field(void *addr, uint64_t *len, size_t offset,
                             size_t index, size_t source, size_t field) {
  return 0;
}

int ckb_load_input_by_field(void *addr, uint64_t *len, size_t offset,
                            size_t index, size_t source, size_t field) {
  return 0;
}

int ckb_load_cell_data(void *addr, uint64_t *len, size_t offset, size_t index,
                       size_t source) {
  if (source == CKB_SOURCE_GROUP_INPUT) {
    ASSERT(index < g_sim_rcdata_count[0]);
    SIMRCData *curr = g_sim_rcdata[0] + index;
    mol_seg_t seg = build_rcdata(curr);
    if (*len != 0) {
      load_offset(seg.ptr, seg.size, addr, len, offset);
    }
    *len = seg.size - offset;
    free(seg.ptr);
  } else if (source == CKB_SOURCE_GROUP_OUTPUT) {
    ASSERT(index < g_sim_rcdata_count[1]);
    SIMRCData *curr = g_sim_rcdata[1] + index;
    mol_seg_t seg = build_rcdata(curr);
    if (*len != 0) {
      load_offset(seg.ptr, seg.size, addr, len, offset);
    }
    *len = seg.size - offset;
    free(seg.ptr);
  } else if (source == CKB_SOURCE_CELL_DEP) {
    ASSERT(false);
  } else {
    ASSERT(false);
  }
  return 0;
}

int ckb_dlopen2(const uint8_t *dep_cell_hash, uint8_t hash_type,
                uint8_t *aligned_addr, size_t aligned_size, void **handle,
                size_t *consumed_size) {
  return 0;
}

void *ckb_dlsym(void *handle, const char *symbol) { return 0; }

int ckb_checked_load_input(void *addr, uint64_t *len, size_t offset,
                           size_t index, size_t source) {
  uint64_t old_len = *len;
  int ret = ckb_load_input(addr, len, offset, index, source);
  if (ret == CKB_SUCCESS && (*len) > old_len) {
    ret = CKB_LENGTH_NOT_ENOUGH;
  }
  return ret;
}

int ckb_checked_load_script(void *addr, uint64_t *len, size_t offset) {
  uint64_t old_len = *len;
  int ret = ckb_load_script(addr, len, offset);
  if (ret == CKB_SUCCESS && (*len) > old_len) {
    ret = CKB_LENGTH_NOT_ENOUGH;
  }
  return ret;
}

int ckb_checked_load_cell_data(void *addr, uint64_t *len, size_t offset,
                               size_t index, size_t source) {
  uint64_t old_len = *len;
  int ret = ckb_load_cell_data(addr, len, offset, index, source);
  if (ret == CKB_SUCCESS && (*len) > old_len) {
    ret = CKB_LENGTH_NOT_ENOUGH;
  }
  return ret;
}
int ckb_look_for_dep_with_hash2(const uint8_t *code_hash, uint8_t hash_type,
                                size_t *index) {
  size_t current = 0;
  size_t field =
      (hash_type == 1) ? CKB_CELL_FIELD_TYPE_HASH : CKB_CELL_FIELD_DATA_HASH;
  while (current < SIZE_MAX) {
    uint64_t len = 32;
    uint8_t hash[32];

    int ret = ckb_load_cell_by_field(hash, &len, 0, current,
                                     CKB_SOURCE_CELL_DEP, field);
    switch (ret) {
    case CKB_ITEM_MISSING:
      break;
    case CKB_SUCCESS:
      if (memcmp(code_hash, hash, 32) == 0) {
        /* Found a match */
        *index = current;
        return CKB_SUCCESS;
      }
      break;
    default:
      return CKB_INDEX_OUT_OF_BOUND;
    }
    current++;
  }
  return CKB_INDEX_OUT_OF_BOUND;
}

int ckb_checked_load_cell_by_field(void *addr, uint64_t *len, size_t offset,
                                   size_t index, size_t source, size_t field) {
  uint64_t old_len = *len;
  int ret = ckb_load_cell_by_field(addr, len, offset, index, source, field);
  if (ret == CKB_SUCCESS && (*len) > old_len) {
    ret = CKB_LENGTH_NOT_ENOUGH;
  }
  return ret;
}

int ckb_checked_load_witness(void *addr, uint64_t *len, size_t offset,
                             size_t index, size_t source) {
  uint64_t old_len = *len;
  int ret = ckb_load_witness(addr, len, offset, index, source);
  if (ret == CKB_SUCCESS && (*len) > old_len) {
    ret = CKB_LENGTH_NOT_ENOUGH;
  }
  return ret;
}

#endif

#ifdef CKB_TYPE_ID_DEBUG
#define DEBUG(s) ckb_debug(s)
#else
#define DEBUG(s)
#endif /* CKB_TYPE_ID_DEBUG */

#ifdef CKB_TYPE_ID_DECLARATION_ONLY
int ckb_validate_type_id(const uint8_t type_id[32]) { return 0; }

int _ckb_has_type_id_cell(size_t index, int is_input) {
  uint64_t len = 0;
  size_t source =
      is_input == 1 ? CKB_SOURCE_GROUP_INPUT : CKB_SOURCE_GROUP_OUTPUT;
  int ret = ckb_load_cell(NULL, &len, 0, index, source);
  return ret == CKB_SUCCESS ? 1 : 0;
}
#endif /* CKB_TYPE_ID_DECLARATION_ONLY */
