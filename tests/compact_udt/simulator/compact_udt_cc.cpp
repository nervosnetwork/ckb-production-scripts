

#include "compact_udt_cc.h"

#include "ckb_consts.h"
#include "compact_udt_virtual_data.h"
#include "dump_data.h"

#include <stddef.h>
#include <iterator>
using namespace std;

bool cc_get_Data_by_field(CUDTMOL_Data* param) {
  auto* vd = GlobalData::get()->get_virtual_data();

  VDBinData* bin = NULL;
  if (param->source == CKB_SOURCE_INPUT) {
    if (param->index >= vd->inputs_.size()) {
      param->index_out_of_bound = true;
      return false;
    }

    auto it = vd->inputs_.begin();
    advance(it, param->index);
    bin = it->get();
  } else if (param->source == CKB_SOURCE_OUTPUT) {
    if (param->index >= vd->inputs_.size()) {
      param->index_out_of_bound = true;
      return false;
    }
    auto it = vd->outputs_.begin();
    advance(it, param->index);
    bin = it->get();
  } else if (param->source == CKB_SOURCE_CELL_DEP) {
    if (param->index == 20) {
      const uint8_t data[] = {151, 153, 190, 226, 81,  185, 117, 184,
                              44,  69,  160, 33,  84,  206, 40,  206,
                              200, 156, 88,  83,  236, 193, 77,  18,
                              183, 184, 204, 207, 193, 158, 10,  244};
      param->out_ptr = (uint8_t*)data;
      param->out_len = sizeof(data);
    } else {
      const uint8_t data[32] = {0};
      param->out_ptr = (uint8_t*)data;
      param->out_len = sizeof(data);
    }

  } else {
    ASSERT_DBG(false);
    return false;
  }

  if (param->field == CKB_CELL_FIELD_LOCK_HASH) {
    param->out_ptr = bin->scritp_hash_.get();
    param->out_len = bin->scritp_hash_.len();
  } else if (param->field == CKB_CELL_FIELD_LOCK) {
    const uint8_t data[] = {
        0xFC, 0x9A, 0xBA, 0x69, 0x70, 0x10, 0xAD, 0x6D, 0x78, 0x19, 0xC6,
        0xEB, 0x9B, 0x72, 0x96, 0xCB, 0xDA, 0x61, 0x5F, 0x10, 0x2C, 0x35,
        0x1C, 0x8F, 0xC7, 0xAE, 0xF1, 0x2A, 0xEA, 0x6C, 0x9B, 0xEF,
    };
    param->out_ptr = (uint8_t*)data;
    param->out_len = sizeof(data);
  } else if (param->field == CKB_CELL_FIELD_DATA_HASH) {
  } else {
    ASSERT_DBG(false);
    return false;
  }

  return true;
}

bool cc_get_deps_cells_data(CUDTMOL_Data* param) {
  if (param->source == CKB_SOURCE_CELL_DEP && param->index == 20) {
    FILE* input = fopen("../../../build/secp256k1_data", "rb");
    if (input == NULL) {
      printf(
          "please set current directory to the root of project: "
          "ckb-production-scripts");
      return false;
    }
    fseek(input, 0, SEEK_END);
    long filelen = ftell(input);
    fseek(input, 0, SEEK_SET);
    if (filelen == 0) {
      printf("build/secp256k1_data file size is zero\n");
      ASSERT_DBG(false);
    } else {
      param->out_ptr = (uint8_t*)malloc(filelen);
      size_t read_item = fread(param->out_ptr, (size_t)filelen, 1, input);
      param->out_len = filelen;
      param->out_need_free = true;
      ASSERT_DBG(read_item == 1);
    }
    return true;
  } else {
    ASSERT_DBG(false);
    return true;
  }
}

bool cc_get_data_tr(CUDTMOL_Data* param) {
  auto* vd = GlobalData::get()->get_virtual_data();
  ASSERT_DBG(vd);

  if (param->by_field) {
    return cc_get_Data_by_field(param);
  }

  if (param->source == CKB_SOURCE_CELL_DEP) {
    return cc_get_deps_cells_data(param);
  }

  if (param->index >= vd->inputs_.size()) {
    param->index_out_of_bound = true;
    return false;
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
      return false;
    }
  } else if (param->source == CKB_SOURCE_INPUT ||
             param->source == CKB_SOURCE_OUTPUT) {
    auto it = bin_list->begin();
    advance(it, param->index);
    if (it == bin_list->end()) {
      ASSERT_DBG(false);
      return false;
    }
    bin = it->get();
  } else {
    ASSERT_DBG(false);
    return false;
  }

  ASSERT_DBG(vd);
  switch (param->type) {
    case CUDTMOLType_Scritp:
      param->out_ptr = bin->script_data_.data();
      param->out_len = bin->script_data_.size();
      return true;
    case CUDTMOLType_CellData:
      param->out_ptr = bin->cell_data_.data();
      param->out_len = bin->cell_data_.size();
      return true;
    case CUDTMOLType_Witness:
      param->out_ptr = bin->witness_.data();
      param->out_len = bin->witness_.size();
      return true;
    default:
      ASSERT_DBG(false);
      break;
  }
  return true;
}

extern "C" {

bool cc_get_data(CUDTMOL_Data* param) {
  return cc_get_data_tr(param);
}

uint32_t cc_get_input_len() {
  auto* vd = GlobalData::get()->get_virtual_data();
  ASSERT_DBG(vd);
  return vd->inputs_.size();
}

}  // extern "C"
