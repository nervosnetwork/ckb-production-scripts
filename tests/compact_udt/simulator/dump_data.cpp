#include "dump_data.h"

#include "ckb_consts.h"
#include "compact_udt_lock.h"
#include "test_compact_udt_config.h"
#include "util/util.h"

#include <string.h>
#include <fstream>
#include <iostream>
#include <map>
#include <vector>

#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-local-typedefs"
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wreorder"
#endif
#include <util/json_configor/json.hpp>
#ifdef __GNUC__
#pragma GCC diagnostic pop
#pragma GCC diagnostic pop
#endif

struct CellData {
  CHash lock_hash_;
  CHash lock_code_hash_;
  CBuffer inptu_cell_data_;
  CBuffer inptu_script_data_;
  CBuffer outptu_cell_data_;
  CBuffer outptu_script_data_;
  CBuffer witness_;
};

struct DepsInfo {
  CHash data_hash;
  string path;
};

struct CDumpData::Data {
  CHash tx_hash_;
  CHash cudt_hash_;
  map<uint32_t, CellData> cells_;
  map<uint32_t, DepsInfo> deps_info_;

  unique_ptr<CBuffer> tmp_data_;
};

CDumpData::CDumpData() {}

CDumpData::~CDumpData() {}

CDumpData* CDumpData::get() {
  static CDumpData s;
  return &s;
}

bool CDumpData::using_dump() {
  return using_dump_;
}

bool CDumpData::case_success() {
  return case_suc_;
}

#define GetVecFromJson(js, out_data) \
  {                                  \
    string js_data = js;             \
    out_data = decode_hex(js_data);  \
  }
bool CDumpData::set_data(string name) {
  auto fi_suc = name.find("success_");
  auto fi_fai = name.find("failed_");
  if (fi_suc != name.npos && fi_fai != name.npos && fi_suc != fi_fai) {
    ASSERT_DBG(false);
    return false;
  }

  if (fi_suc != name.npos)
    case_suc_ = true;
  if (fi_fai != name.npos)
    case_suc_ = false;

  string path = string(COMPACT_UDT_UNITTEST_SRC_PATH) + name;

  std::ifstream ifs(path);
  configor::json j;
  ifs >> j;

  auto data = make_unique<CDumpData::Data>();

  GetVecFromJson(j["tx_hash"], data->tx_hash_);
  GetVecFromJson(j["cudt_hash"], data->cudt_hash_);

  configor::json cells = j["cells"];
  for (size_t i = 0; i < cells.size(); i++) {
    auto cell = cells[i];
    uint32_t index = cell["index"];

    CellData cell_data;

    GetVecFromJson(cell["lock_hash"], cell_data.lock_hash_);
    GetVecFromJson(cell["lock_code_hash"], cell_data.lock_code_hash_);
    GetVecFromJson(cell["inptu_cell_data"], cell_data.inptu_cell_data_);
    GetVecFromJson(cell["inptu_script_data"], cell_data.inptu_script_data_);
    GetVecFromJson(cell["outptu_cell_data"], cell_data.outptu_cell_data_);
    GetVecFromJson(cell["outptu_script_data"], cell_data.outptu_script_data_);
    GetVecFromJson(cell["witness"], cell_data.witness_);

    data->cells_.insert(make_pair(index, cell_data));
  }

  configor::json deps = j["deps"];
  for (size_t i = 0; i < deps.size(); i++) {
    auto d = deps[i];
    uint32_t index = d["index"];

    DepsInfo dep;
    GetVecFromJson(d["data_hash"], dep.data_hash);
    dep.path = d["data_path"].as_string();

    data->deps_info_.insert(make_pair(index, dep));
  }

  using_dump_ = true;
  data_ = move(data);
  return true;
}
#undef GetVecFromJson

bool CDumpData::set_group_index(int index) {
  ASSERT_DBG(data_);
  auto it = data_->cells_.find(index);
  if (it == data_->cells_.end()) {
    return false;
  }
  if (data_->cudt_hash_ != it->second.lock_code_hash_) {
    return false;
  }

  group_index_ = index;
  return true;
}

int CDumpData::get_cell_count() {
  return (int)data_->cells_.size();
}

namespace {

void load_offset(uint8_t* source_buff,
                 uint64_t source_size,
                 void* addr,
                 uint64_t* len,
                 size_t offset) {
  ASSERT_DBG(source_size > offset);
  if (*len == 0) {
    *len = source_size - offset;
    return;
  }

  uint64_t size = source_size - offset < *len ? source_size - offset : *len;
  memcpy(addr, source_buff + offset, size);
  *len = source_size - offset;
}

}  // namespace

int CDumpData::load_tx_hash(void* addr, uint64_t* len, size_t offset) {
  ASSERT_DBG(data_);
  load_offset(data_->tx_hash_.get(), data_->tx_hash_.len(), addr, len, offset);
  return 0;
}
int CDumpData::load_script_hash(void* addr, uint64_t* len, size_t offset) {
  auto it = data_->cells_.find(group_index_);
  if (it == data_->cells_.end()) {
    ASSERT_DBG(false);
    return CKB_INDEX_OUT_OF_BOUND;
  }
  auto p = it->second.lock_hash_.get();
  auto l = it->second.lock_hash_.len();

  load_offset(p, l, addr, len, offset);
  return 0;
}
int CDumpData::load_cell_data(void* addr,
                              uint64_t* len,
                              size_t offset,
                              size_t index,
                              size_t source) {
  uint8_t* p = NULL;
  size_t l = 0;

  CBuffer* buf = nullptr;

  if (source == CKB_SOURCE_INPUT) {
    auto it = data_->cells_.find(index);
    if (it == data_->cells_.end()) {
      return CKB_INDEX_OUT_OF_BOUND;
    }
    buf = &it->second.inptu_cell_data_;
  } else if (source == CKB_SOURCE_OUTPUT) {
    auto it = data_->cells_.find(index);
    if (it == data_->cells_.end()) {
      return CKB_INDEX_OUT_OF_BOUND;
    }
    buf = &it->second.outptu_cell_data_;
  } else if (source == CKB_SOURCE_GROUP_INPUT) {
    if (index >= 1)
      return CKB_INDEX_OUT_OF_BOUND;
    auto it = data_->cells_.find(group_index_);
    if (it == data_->cells_.end()) {
      return CKB_INDEX_OUT_OF_BOUND;
    }
    buf = &it->second.inptu_cell_data_;
  } else if (source == CKB_SOURCE_GROUP_OUTPUT) {
    return CKB_INDEX_OUT_OF_BOUND;
  } else if (source == CKB_SOURCE_CELL_DEP) {
    auto it = data_->deps_info_.find(index);
    if (it == data_->deps_info_.end()) {
      return CKB_INDEX_OUT_OF_BOUND;
    }
    auto cell_data = make_unique<CBuffer>(load_file(it->second.path));
    data_->tmp_data_ = move(cell_data);
    buf = data_->tmp_data_.get();
  } else {
    ASSERT_DBG(false);
  }
  ASSERT_DBG(buf);
  p = buf->data();
  l = buf->size();

  load_offset(p, l, addr, len, offset);
  return 0;
}
int CDumpData::load_script(void* addr, uint64_t* len, size_t offset) {
  auto it = data_->cells_.find(group_index_);
  if (it == data_->cells_.end()) {
    ASSERT_DBG(false);
    return CKB_INDEX_OUT_OF_BOUND;
  }

  auto p = it->second.inptu_script_data_.data();
  auto l = it->second.inptu_script_data_.size();
  load_offset(p, l, addr, len, offset);
  return 0;
}
int CDumpData::calculate_inputs_len() {
  return (int)data_->cells_.size();
}
int CDumpData::load_witness(void* addr,
                            uint64_t* len,
                            size_t offset,
                            size_t index,
                            size_t source) {
  CBuffer* buf = nullptr;
  if (source == CKB_SOURCE_GROUP_INPUT) {
    if (index >= 1)
      return CKB_INDEX_OUT_OF_BOUND;
    auto it = data_->cells_.find(group_index_);
    if (it == data_->cells_.end()) {
      ASSERT_DBG(false);
      return CKB_INDEX_OUT_OF_BOUND;
    }
    buf = &it->second.witness_;
  } else if (source == CKB_SOURCE_GROUP_OUTPUT) {
    return CKB_INDEX_OUT_OF_BOUND;
  } else if (source == CKB_SOURCE_INPUT || source == CKB_SOURCE_OUTPUT) {
    auto it = data_->cells_.find(index);
    if (it == data_->cells_.end()) {
      return CKB_INDEX_OUT_OF_BOUND;
    }
    buf = &it->second.witness_;
  } else {
    ASSERT_DBG(false);
  }

  auto p = buf->data();
  auto l = buf->size();

  load_offset(p, l, addr, len, offset);
  return 0;
}
int CDumpData::load_cell_by_field(void* addr,
                                  uint64_t* len,
                                  size_t offset,
                                  size_t index,
                                  size_t source,
                                  size_t field) {
  if (field == CKB_CELL_FIELD_LOCK_HASH) {
    return load_cell_by_field_lock_hash(addr, len, offset, index, source);
  } else if (field == CKB_CELL_FIELD_LOCK) {
    return load_cell_by_field_lock(addr, len, offset, index, source);
  } else if (field == CKB_CELL_FIELD_DATA_HASH) {
    return load_cell_by_field_data_hash(addr, len, offset, index, source);
  } else {
    ASSERT_DBG(false);
  }
  return 0;
}

int CDumpData::load_cell_by_field_lock_hash(void* addr,
                                            uint64_t* len,
                                            size_t offset,
                                            size_t index,
                                            size_t source) {
  uint8_t* p = NULL;
  size_t l = 0;
  if (source == CKB_SOURCE_GROUP_INPUT) {
    if (index >= 1)
      return CKB_INDEX_OUT_OF_BOUND;
    auto it = data_->cells_.find(group_index_);
    if (it == data_->cells_.end()) {
      ASSERT_DBG(false);
      return CKB_INDEX_OUT_OF_BOUND;
    }
    p = it->second.lock_hash_.get();
    l = it->second.lock_hash_.len();
  } else if (source == CKB_SOURCE_GROUP_OUTPUT) {
    return CKB_INDEX_OUT_OF_BOUND;
  } else if (source == CKB_SOURCE_INPUT) {
    auto it = data_->cells_.find(index);
    if (it == data_->cells_.end()) {
      return CKB_INDEX_OUT_OF_BOUND;
    }
    p = it->second.lock_hash_.get();
    l = it->second.lock_hash_.len();
  } else if (source == CKB_SOURCE_OUTPUT) {
    auto it = data_->cells_.find(index);
    if (it == data_->cells_.end()) {
      return CKB_INDEX_OUT_OF_BOUND;
    }
    p = it->second.lock_hash_.get();
    l = it->second.lock_hash_.len();
  } else {
    ASSERT_DBG(false);
  }
  load_offset(p, l, addr, len, offset);
  return 0;
}
int CDumpData::load_cell_by_field_lock(void* addr,
                                       uint64_t* len,
                                       size_t offset,
                                       size_t index,
                                       size_t source) {
  uint8_t* p = NULL;
  size_t l = 0;
  if (source == CKB_SOURCE_GROUP_INPUT) {
    if (index >= 1)
      return CKB_INDEX_OUT_OF_BOUND;
    auto it = data_->cells_.find(group_index_);
    if (it == data_->cells_.end()) {
      ASSERT_DBG(false);
      return CKB_INDEX_OUT_OF_BOUND;
    }
    p = it->second.inptu_script_data_.data();
    l = it->second.inptu_script_data_.size();
  } else if (source == CKB_SOURCE_GROUP_OUTPUT) {
    return CKB_INDEX_OUT_OF_BOUND;
  } else if (source == CKB_SOURCE_INPUT) {
    auto it = data_->cells_.find(index);
    if (it == data_->cells_.end()) {
      return CKB_INDEX_OUT_OF_BOUND;
    }
    p = it->second.inptu_script_data_.data();
    l = it->second.inptu_script_data_.size();
  } else if (source == CKB_SOURCE_OUTPUT) {
    auto it = data_->cells_.find(index);
    if (it == data_->cells_.end()) {
      return CKB_INDEX_OUT_OF_BOUND;
    }
    p = it->second.outptu_script_data_.data();
    l = it->second.outptu_script_data_.size();
  } else {
    ASSERT_DBG(false);
  }
  load_offset(p, l, addr, len, offset);
  return 0;
}
int CDumpData::load_cell_by_field_data_hash(void* addr,
                                            uint64_t* len,
                                            size_t offset,
                                            size_t index,
                                            size_t source) {
  uint8_t* p = NULL;
  size_t l = 0;
  if (source == CKB_SOURCE_CELL_DEP) {
    auto it = data_->deps_info_.find(index);
    if (it == data_->deps_info_.end()) {
      return CKB_INDEX_OUT_OF_BOUND;
    }
    p = it->second.data_hash.get();
    l = it->second.data_hash.len();
  } else {
    ASSERT_DBG(false);
  }
  load_offset(p, l, addr, len, offset);
  return 0;
}

#ifdef __cplusplus
extern "C" {
#endif  // __cplusplu

bool dd_using_dump() {
  return CDumpData::get()->using_dump();
}
int dd_load_tx_hash(void* addr, uint64_t* len, size_t offset) {
  return CDumpData::get()->load_tx_hash(addr, len, offset);
}
int dd_load_script_hash(void* addr, uint64_t* len, size_t offset) {
  return CDumpData::get()->load_script_hash(addr, len, offset);
}
int dd_load_cell_data(void* addr,
                      uint64_t* len,
                      size_t offset,
                      size_t index,
                      size_t source) {
  return CDumpData::get()->load_cell_data(addr, len, offset, index, source);
}
int dd_load_script(void* addr, uint64_t* len, size_t offset) {
  return CDumpData::get()->load_script(addr, len, offset);
}
int dd_calculate_inputs_len() {
  return CDumpData::get()->calculate_inputs_len();
}
int dd_load_witness(void* addr,
                    uint64_t* len,
                    size_t offset,
                    size_t index,
                    size_t source) {
  return CDumpData::get()->load_witness(addr, len, offset, index, source);
}
int dd_load_cell_by_field(void* addr,
                          uint64_t* len,
                          size_t offset,
                          size_t index,
                          size_t source,
                          size_t field) {
  return CDumpData::get()->load_cell_by_field(addr, len, offset, index, source,
                                              field);
}

#ifdef __cplusplus
}  // extern "C"
#endif  // __cplusplu
