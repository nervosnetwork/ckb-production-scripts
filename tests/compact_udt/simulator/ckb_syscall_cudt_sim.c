#include "ckb_syscall_cudt_sim.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "ckb_consts.h"
#include "compact_udt_lock.h"

#include "compact_udt_cc.h"

#include "dump_data.h"

void load_offset(CUDTMOL_Data* param,
                 void* addr,
                 uint64_t* len,
                 size_t offset) {
  ASSERT_DBG(param->out_len > offset);
  if (*len == 0) {
    *len = param->out_len - offset;
    return;
  }

  uint64_t size =
      param->out_len - offset < *len ? param->out_len - offset : *len;
  memcpy(addr, param->out_ptr + offset, size);
  *len = size;

  if (param->out_need_free) {
    free(param->out_ptr);
    param->out_ptr = NULL;
    param->out_len = 0;
  }
}

//////////////////////////////////////////////////////////////////////
// ckb sim api

int ckb_load_tx_hash(void* addr, uint64_t* len, size_t offset) {
  if (dd_using_dump()) {
    return dd_load_tx_hash(addr, len, offset);
  }
  *len = 32;
  return 0;
}

int ckb_load_script_hash(void* addr, uint64_t* len, size_t offset) {
  if (dd_using_dump()) {
    return dd_load_script_hash(addr, len, offset);
  }
  CUDTMOL_Data param = {0};
  param.index = 0;
  param.source = CKB_SOURCE_INPUT;
  param.type = CUDTMOLType_Witness;
  param.index_out_of_bound = false;
  param.by_field = true;
  param.field = CKB_CELL_FIELD_LOCK_HASH;

  bool ret = cc_get_data(&param);
  if (param.index_out_of_bound)
    return CKB_INDEX_OUT_OF_BOUND;
  ASSERT_DBG(ret);

  load_offset(&param, addr, len, offset);
  return 0;
}

int ckb_load_cell_data(void* addr,
                       uint64_t* len,
                       size_t offset,
                       size_t index,
                       size_t source) {
  if (dd_using_dump()) {
    return dd_load_cell_data(addr, len, offset, index, source);
  }
  CUDTMOL_Data param = {0};
  param.index = index;
  param.source = source;
  param.type = CUDTMOLType_CellData;
  param.index_out_of_bound = false;
  bool ret = cc_get_data(&param);
  if (param.index_out_of_bound)
    return CKB_INDEX_OUT_OF_BOUND;
  ASSERT_DBG(ret);

  load_offset(&param, addr, len, offset);
  return 0;
}

int ckb_load_script(void* addr, uint64_t* len, size_t offset) {
  if (dd_using_dump()) {
    return dd_load_script(addr, len, offset);
  }
  CUDTMOL_Data param = {0};
  param.index = 0;
  param.source = CKB_SOURCE_GROUP_INPUT;
  param.type = CUDTMOLType_Scritp;
  param.index_out_of_bound = false;
  bool ret = cc_get_data(&param);
  if (param.index_out_of_bound)
    return CKB_INDEX_OUT_OF_BOUND;

  ASSERT_DBG(ret);

  load_offset(&param, addr, len, offset);
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

int ckb_calculate_inputs_len() {
  if (dd_using_dump()) {
    return dd_calculate_inputs_len();
  }
  return cc_get_input_len();
}

int ckb_load_witness(void* addr,
                     uint64_t* len,
                     size_t offset,
                     size_t index,
                     size_t source) {
  if (dd_using_dump()) {
    return dd_load_witness(addr, len, offset, index, source);
  }
  CUDTMOL_Data param = {0};
  param.index = index;
  param.source = source;
  param.type = CUDTMOLType_Witness;
  param.index_out_of_bound = false;
  bool ret = cc_get_data(&param);
  if (param.index_out_of_bound)
    return CKB_INDEX_OUT_OF_BOUND;

  ASSERT_DBG(ret);

  load_offset(&param, addr, len, offset);
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
  if (dd_using_dump()) {
    return dd_load_cell_by_field(addr, len, offset, index, source, field);
  }
  CUDTMOL_Data param = {0};
  param.index = index;
  param.source = source;
  param.type = CUDTMOLType_Witness;
  param.index_out_of_bound = false;
  param.by_field = true;
  param.field = field;

  bool ret = cc_get_data(&param);
  if (param.index_out_of_bound)
    return CKB_INDEX_OUT_OF_BOUND;
  ASSERT_DBG(ret);

  load_offset(&param, addr, len, offset);
  return 0;
}

int ckb_checked_load_cell_by_field(void* addr,
                                   uint64_t* len,
                                   size_t offset,
                                   size_t index,
                                   size_t source,
                                   size_t field) {
  uint64_t old_len = *len;
  int ret = ckb_load_cell_by_field(addr, len, offset, index, source, field);
  if (ret == CKB_SUCCESS && (*len) > old_len) {
    ret = CKB_LENGTH_NOT_ENOUGH;
  }
  return ret;
}
