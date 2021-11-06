

#include "compact_udt_cc.h"

#include "ckb_consts.h"
#include "compact_udt_virtual_data.h"
#include "dump_data.h"

#include <stddef.h>
#include <iterator>
using namespace std;

uint8_t* cc_get_Data_by_field(CUDTMOL_Data* param) {
  auto* vd = GlobalData::get()->get_virtual_data();
  uint8_t* ptr;

  VDBinData* bin = NULL;
  if (param->source == CKB_SOURCE_INPUT) {
    auto it = vd->inputs_.begin();
    advance(it, param->index);
    bin = it->get();
  } else if (param->source == CKB_SOURCE_OUTPUT) {
    auto it = vd->outputs_.begin();
    advance(it, param->index);
    bin = it->get();
  } else {
    ASSERT_DBG(false);
    return NULL;
  }

  if (param->field == CKB_CELL_FIELD_LOCK_HASH) {
    ptr = bin->scritp_hash_.get();
    param->len = bin->scritp_hash_.len();
  } else if (param->field == CKB_CELL_FIELD_LOCK) {
    const uint8_t data[] = {
        0xFC, 0x9A, 0xBA, 0x69, 0x70, 0x10, 0xAD, 0x6D, 0x78, 0x19, 0xC6,
        0xEB, 0x9B, 0x72, 0x96, 0xCB, 0xDA, 0x61, 0x5F, 0x10, 0x2C, 0x35,
        0x1C, 0x8F, 0xC7, 0xAE, 0xF1, 0x2A, 0xEA, 0x6C, 0x9B, 0xEF,
    };
    ptr = (uint8_t*)data;
    param->len = sizeof(data);
  } else {
    ASSERT_DBG(false);
    return NULL;
  }

  return ptr;
}

uint8_t* cc_get_data_tr(CUDTMOL_Data* param) {
  auto* vd = GlobalData::get()->get_virtual_data();
  ASSERT_DBG(vd);

  if (param->index >= vd->inputs_.size()) {
    param->index_out_of_bound = true;
    return NULL;
  }

  if (param->by_field) {
    return cc_get_Data_by_field(param);
  }

  std::list<unique_ptr<VDBinData>>* bin_list = NULL;
  if (param->source == CKB_SOURCE_GROUP_INPUT ||
      param->source == CKB_SOURCE_INPUT) {
    bin_list = &(vd->inputs_);
  } else if (param->source == CKB_SOURCE_GROUP_OUTPUT ||
             param->source == CKB_SOURCE_OUTPUT) {
    bin_list = &(vd->outputs_);
  }
  ASSERT_DBG(bin_list);

  VDBinData* bin = NULL;
  if (param->source == CKB_SOURCE_GROUP_INPUT ||
      param->source == CKB_SOURCE_GROUP_OUTPUT) {
    if (param->index == 0)
      bin = bin_list->begin()->get();
    else {
      param->index_out_of_bound = true;
      return NULL;
    }
  } else if (param->source == CKB_SOURCE_INPUT ||
             param->source == CKB_SOURCE_OUTPUT) {
    auto it = bin_list->begin();
    advance(it, param->index);
    if (it == bin_list->end()) {
      ASSERT_DBG(false);
      return NULL;
    }
    bin = it->get();
  } else {
    ASSERT_DBG(false);
    return NULL;
  }

  ASSERT_DBG(vd);
  switch (param->type) {
    case CUDTMOLType_Scritp:
      param->len = bin->script_data_.size();
      return bin->script_data_.data();
    case CUDTMOLType_CellData:
      param->len = bin->cell_data_.size();
      return bin->cell_data_.data();
    case CUDTMOLType_Witness:
      param->len = bin->witness_.size();
      return bin->witness_.data();
    default:
      ASSERT_DBG(false);
      break;
  }
  return NULL;
}

extern "C" {

uint8_t* cc_get_data(CUDTMOL_Data* param) {
  return cc_get_data_tr(param);
}

uint32_t cc_get_input_len() {
  auto* vd = GlobalData::get()->get_virtual_data();
  ASSERT_DBG(vd);
  return vd->inputs_.size();
}

}  // extern "C"
