

#include "compact_udt_cc.h"

#include "ckb_consts.h"
#include "compact_udt_virtual_data.h"

#include <stddef.h>
#include <iterator>
using namespace std;

uint8_t* cc_get_Data_by_field(CUDTMOL_Data* param) {
  auto* vd = GlobalData::get()->get_virtual_data();
  uint8_t* ptr;

  VDBinData* bin = NULL;
  if (param->source == CKB_SOURCE_INPUT) {
    auto it = vd->inputs.begin();
    advance(it, param->index);
    bin = it->get();
  } else if (param->source == CKB_SOURCE_OUTPUT) {
    auto it = vd->outputs.begin();
    advance(it, param->index);
    bin = it->get();
  } else {
    ASSERT_DBG(false);
    return NULL;
  }

  if (param->field == CKB_CELL_FIELD_TYPE_HASH) {
    ptr = bin->scritp_hash.get();
    param->len = bin->scritp_hash.len();

  } else {
    ASSERT_DBG(false);
    return NULL;
  }

  return ptr;
}

uint8_t* cc_get_data_tr(CUDTMOL_Data* param) {
  auto* vd = GlobalData::get()->get_virtual_data();
  ASSERT_DBG(vd);

  if (param->index >= vd->inputs.size()) {
    param->index_out_of_bound = true;
    return NULL;
  }

  if (param->by_field) {
    return cc_get_Data_by_field(param);
  }

  std::list<unique_ptr<VDBinData>>* bin_list = NULL;
  if (param->source == CKB_SOURCE_GROUP_INPUT ||
      param->source == CKB_SOURCE_INPUT) {
    bin_list = &(vd->inputs);
  } else if (param->source == CKB_SOURCE_GROUP_OUTPUT ||
             param->source == CKB_SOURCE_OUTPUT) {
    bin_list = &(vd->outputs);
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
      param->len = bin->script_data.size();
      return bin->script_data.data();
    case CUDTMOLType_CellData:
      param->len = bin->cell_data.size();
      return bin->cell_data.data();
    case CUDTMOLType_Witness:
      param->len = bin->witness.size();
      return bin->witness.data();
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

}  // extern "C"
