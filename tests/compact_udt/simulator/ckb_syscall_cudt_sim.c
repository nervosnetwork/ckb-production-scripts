#include "ckb_syscall_cudt_sim.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "ckb_consts.h"
#include "compact_udt_lock.h"

#include "compact_udt_cc.h"

void load_offset(uint8_t* source_buff,
                 uint64_t source_size,
                 void* addr,
                 uint64_t* len,
                 size_t offset) {
  ASSERT_DBG(source_size > offset);
  if (*len == 0) {
    *len = source_size;
    return;
  }

  uint64_t size = source_size - offset < *len ? source_size - offset : *len;
  memcpy(addr, source_buff + offset, size);
  *len = size;
}

//////////////////////////////////////////////////////////////////////
// ckb sim api

int ckb_load_script_hash(void* addr, uint64_t* len, size_t offset) {
  CUDTMOL_Data param = {0};
  param.index = 0;
  param.source = CKB_SOURCE_INPUT;
  param.type = CUDTMOLType_Witness;
  param.len = 0;
  param.index_out_of_bound = false;
  param.by_field = true;
  param.field = CKB_CELL_FIELD_TYPE_HASH;

  uint8_t* ptr = cudtmol_get_data(&param);
  if (param.index_out_of_bound)
    return CKB_INDEX_OUT_OF_BOUND;

  ASSERT_DBG(ptr);

  load_offset(ptr, param.len, addr, len, offset);
  return 0;
}

int ckb_load_cell_data(void* addr,
                       uint64_t* len,
                       size_t offset,
                       size_t index,
                       size_t source) {
  CUDTMOL_Data param = {0};
  param.index = index;
  param.source = source;
  param.type = CUDTMOLType_CellData;
  param.len = 0;
  param.index_out_of_bound = false;
  uint8_t* ptr = cudtmol_get_data(&param);
  if (param.index_out_of_bound)
    return CKB_INDEX_OUT_OF_BOUND;

  ASSERT_DBG(ptr);

  load_offset(ptr, param.len, addr, len, offset);
  return 0;
}

int ckb_load_script(void* addr, uint64_t* len, size_t offset) {
  CUDTMOL_Data param = {0};
  param.index = 0;
  param.source = CKB_SOURCE_GROUP_INPUT;
  param.type = CUDTMOLType_Scritp;
  param.len = 0;
  param.index_out_of_bound = false;
  uint8_t* ptr = cudtmol_get_data(&param);
  if (param.index_out_of_bound)
    return CKB_INDEX_OUT_OF_BOUND;

  ASSERT_DBG(ptr);

  load_offset(ptr, param.len, addr, len, offset);
  return 0;
}

int ckb_checked_load_script(void* addr, uint64_t* len, size_t offset) {
  uint64_t old_len = *len;
  int ret = ckb_load_script(addr, len, offset);
  if (ret == CUDT_SUCCESS && (*len) > old_len) {
    ret = CKB_LENGTH_NOT_ENOUGH;
  }
  return ret;
}

int ckb_load_witness(void* addr,
                     uint64_t* len,
                     size_t offset,
                     size_t index,
                     size_t source) {
  CUDTMOL_Data param = {0};
  param.index = index;
  param.source = source;
  param.type = CUDTMOLType_Witness;
  param.len = 0;
  param.index_out_of_bound = false;
  uint8_t* ptr = cudtmol_get_data(&param);
  if (param.index_out_of_bound)
    return CKB_INDEX_OUT_OF_BOUND;

  ASSERT_DBG(ptr);

  load_offset(ptr, param.len, addr, len, offset);
  return 0;
}

int ckb_checked_load_witness(void* addr,
                             uint64_t* len,
                             size_t offset,
                             size_t index,
                             size_t source) {
  uint64_t old_len = *len;
  int ret = ckb_load_witness(addr, len, offset, index, source);
  if (ret == CUDT_SUCCESS && (*len) > old_len) {
    ret = CKB_LENGTH_NOT_ENOUGH;
  }
  return ret;
}

int ckb_exit(int8_t code) {
  exit(code);
  ASSERT_DBG(false);
  return 0;
}

int ckb_load_cell_by_field(void* addr,
                           uint64_t* len,
                           size_t offset,
                           size_t index,
                           size_t source,
                           size_t field) {
  CUDTMOL_Data param = {0};
  param.index = index;
  param.source = source;
  param.type = CUDTMOLType_Witness;
  param.len = 0;
  param.index_out_of_bound = false;
  param.by_field = true;
  param.field = field;

  uint8_t* ptr = cudtmol_get_data(&param);
  if (param.index_out_of_bound)
    return CKB_INDEX_OUT_OF_BOUND;

  ASSERT_DBG(ptr);

  load_offset(ptr, param.len, addr, len, offset);
  return 0;
}
