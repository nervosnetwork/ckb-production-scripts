#include "dump_data.h"

#include "autogenerate_data.h"
#include "compact_udt_lock.h"

#include "ckb_consts.h"

#include <string.h>

CDumpData::CDumpData() {}

CDumpData::~CDumpData() {}

CDumpData* CDumpData::get() {
  static CDumpData s;
  return &s;
}

bool CDumpData::using_dump() {
  return using_dump_;
}

bool CDumpData::set_group_index(int index) {
  if (dump_data_cudt_lock_hash != dump_data_input_lock_hash[index]) {
    return false;
  }

  using_dump_ = true;
  group_index_ = index;
  ASSERT_DBG((index < (int)dump_data_input_lock_hash.size()));
  return true;
}

int CDumpData::get_cell_count() {
  return (int)dump_data_input_lock_hash.size();
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
  load_offset(dump_data_tx_hash.data(), dump_data_tx_hash.size(), addr, len,
              offset);
  return 0;
}
int CDumpData::load_script_hash(void* addr, uint64_t* len, size_t offset) {
  auto p = dump_data_input_lock_hash[group_index_].data();
  auto l = dump_data_input_lock_hash[group_index_].size();
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
  if (source == CKB_SOURCE_GROUP_INPUT) {
    if (index >= 1)
      return CKB_INDEX_OUT_OF_BOUND;
    p = dump_data_input_cell_data[group_index_].data();
    l = dump_data_input_cell_data[group_index_].size();
  } else if (source == CKB_SOURCE_GROUP_OUTPUT) {
    return CKB_INDEX_OUT_OF_BOUND;
  } else if (source == CKB_SOURCE_INPUT) {
    if (index >= dump_data_input_cell_data.size())
      return CKB_INDEX_OUT_OF_BOUND;
    p = dump_data_input_cell_data[index].data();
    l = dump_data_input_cell_data[index].size();
  } else if (source == CKB_SOURCE_OUTPUT) {
    if (index >= dump_data_output_cell_data.size())
      return CKB_INDEX_OUT_OF_BOUND;
    p = dump_data_output_cell_data[index].data();
    l = dump_data_output_cell_data[index].size();
  } else {
    ASSERT_DBG(false);
  }

  load_offset(p, l, addr, len, offset);
  return 0;
}
int CDumpData::load_script(void* addr, uint64_t* len, size_t offset) {
  auto p = dump_data_input_scritp_data[group_index_].data();
  auto l = dump_data_input_scritp_data[group_index_].size();
  load_offset(p, l, addr, len, offset);
  return 0;
}
int CDumpData::calculate_inputs_len() {
  return (int)dump_data_input_scritp_data.size();
}
int CDumpData::load_witness(void* addr,
                            uint64_t* len,
                            size_t offset,
                            size_t index,
                            size_t source) {
  uint8_t* p = NULL;
  size_t l = 0;
  if (source == CKB_SOURCE_GROUP_INPUT) {
    if (index >= 1)
      return CKB_INDEX_OUT_OF_BOUND;
    p = dump_data_witness[group_index_].data();
    l = dump_data_witness[group_index_].size();
  } else if (source == CKB_SOURCE_GROUP_OUTPUT) {
    return CKB_INDEX_OUT_OF_BOUND;
  } else if (source == CKB_SOURCE_INPUT || source == CKB_SOURCE_OUTPUT) {
    if (index >= dump_data_witness.size())
      return CKB_INDEX_OUT_OF_BOUND;
    p = dump_data_witness[index].data();
    l = dump_data_witness[index].size();
  } else {
    ASSERT_DBG(false);
  }

  load_offset(p, l, addr, len, offset);
  return 0;
}
int CDumpData::load_cell_by_field(void* addr,
                                  uint64_t* len,
                                  size_t offset,
                                  size_t index,
                                  size_t source,
                                  size_t field) {
  uint8_t* p = NULL;
  size_t l = 0;
  if (field == CKB_CELL_FIELD_LOCK_HASH) {
    if (source == CKB_SOURCE_GROUP_INPUT) {
      if (index >= 1)
        return CKB_INDEX_OUT_OF_BOUND;
      p = dump_data_input_lock_hash[group_index_].data();
      l = dump_data_input_lock_hash[group_index_].size();
    } else if (source == CKB_SOURCE_GROUP_OUTPUT) {
      return CKB_INDEX_OUT_OF_BOUND;
    } else if (source == CKB_SOURCE_INPUT) {
      if (index >= dump_data_input_lock_hash.size())
        return CKB_INDEX_OUT_OF_BOUND;
      p = dump_data_input_lock_hash[index].data();
      l = dump_data_input_lock_hash[index].size();
    } else if (source == CKB_SOURCE_OUTPUT) {
      if (index >= dump_data_input_lock_hash.size())
        return CKB_INDEX_OUT_OF_BOUND;
      p = dump_data_input_lock_hash[index].data();
      l = dump_data_input_lock_hash[index].size();
    } else {
      ASSERT_DBG(false);
    }
  } else if (field == CKB_CELL_FIELD_LOCK) {
    if (source == CKB_SOURCE_GROUP_INPUT) {
      if (index >= 1)
        return CKB_INDEX_OUT_OF_BOUND;
      p = dump_data_input_scritp_data[group_index_].data();
      l = dump_data_input_scritp_data[group_index_].size();
    } else if (source == CKB_SOURCE_GROUP_OUTPUT) {
      return CKB_INDEX_OUT_OF_BOUND;
    } else if (source == CKB_SOURCE_INPUT) {
      if (index >= dump_data_input_scritp_data.size())
        return CKB_INDEX_OUT_OF_BOUND;
      p = dump_data_input_scritp_data[index].data();
      l = dump_data_input_scritp_data[index].size();
    } else if (source == CKB_SOURCE_OUTPUT) {
      if (index >= dump_data_output_scritp_data.size())
        return CKB_INDEX_OUT_OF_BOUND;
      p = dump_data_output_scritp_data[index].data();
      l = dump_data_output_scritp_data[index].size();
    } else {
      ASSERT_DBG(false);
    }
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
  return 0;
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
