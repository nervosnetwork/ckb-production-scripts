#include "compact_udt_lock.c"

#include "ckb_syscall_cudt_sim.h"

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "ckb_consts.h"
#include "ckb_smt.h"

///////////////////////////////////////////////////////////////////////////////
// util

int start_cudt() {
  int argc = 1;
  char* argv[] = {"./"};
  return simulator_main(argc, argv);
}

void gen_smt_value(const uint8_t* identity,
                   uint32_t nonce,
                   uint32_t* out_value) {
  typedef struct __SMT_Value {
    uint8_t identity[16];
    uint32_t nonce;
    uint8_t reserved[12];
  } SMT_Value;

  SMT_Value* v = (SMT_Value*)out_value;

  memcpy(v->identity, identity, 16);
  v->nonce = nonce;
  memset(v->reserved, 0, 12);
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

void load_offset(uint8_t* source_buff,
                 uint64_t source_size,
                 void* addr,
                 uint64_t* len,
                 size_t offset) {
  assert(source_size > offset);
  assert(*len > 0);

  uint64_t size = MIN(source_size - offset, *len);
  memcpy(addr, source_buff + offset, size);
  *len = size;
}

///////////////////////////////////////////////////////////////////////////////
// set args

uint8_t* g_cell_data_buffer;
uint32_t g_cell_data_len;

void sim_set_data(int type, uint64_t amount, const uint8_t* smt_hash) {
  if (type == SIM_TYPE_SCRIPT_SUDT) {
    typedef struct __SUDTDATA {
      uint64_t amount_high;
      uint64_t amount_low;
      uint32_t flag;
      uint32_t smt_hash[32];
    } SUDTDATA;
    SUDTDATA* data = (SUDTDATA*)malloc(sizeof(SUDTDATA));
    memset(data, 0, sizeof(SUDTDATA));
    data->amount_low = amount;
    memcpy(data->smt_hash, smt_hash, 32);
    g_cell_data_buffer = (uint8_t*)data;
    g_cell_data_len = sizeof(SUDTDATA);
    //} else if (type == SIM_TYPE_SCRIPT_XUDT) {
  } else {
    assert(false);
  }
}

typedef struct __SimArgsData {
  uint8_t ver;
  uint8_t type_id[32];
  uint8_t identy[21];
} SimArgsData, *pSimArgsData;

typedef struct __SimData {
  SimArgsData args_data;
  bool args_data_has_identy;
} SimData;
static SimData g_sim_data;

void sim_set_args(uint8_t ver, const uint8_t* type_id, const uint8_t* identy) {
  assert(type_id);

  g_sim_data.args_data.ver = ver;
  memcpy(g_sim_data.args_data.type_id, type_id,
         sizeof(g_sim_data.args_data.type_id));
  if (identy) {
    memcpy(g_sim_data.args_data.identy, identy,
           sizeof(g_sim_data.args_data.identy));
    g_sim_data.args_data_has_identy = true;
  } else {
    g_sim_data.args_data_has_identy = false;
  }
}

void sim_set_witness() {
  mol_builder_t witness_args_builder;
  MolBuilder_WitnessArgs_init(&witness_args_builder);

  // MolBuilder_WitnessArgs_set_input_type(witness_args_builder, )
}

///////////////////////////////////////////////////////////////////////////////
// ckb sim

int ckb_load_script_hash(void* addr, uint64_t* len, size_t offset) {
  ASSERT(false);
  return 0;
}

int ckb_load_cell_data(void* addr,
                       uint64_t* len,
                       size_t offset,
                       size_t index,
                       size_t source) {
  ASSERT(false);
  return 0;
}

const uint8_t g_sim_script_code_hash[32] = {0};
const uint8_t g_sim_script_hash_type = 0;

int ckb_load_script(void* addr, uint64_t* len, size_t offset) {
  mol_seg_t seg;
  {
    mol_builder_t b;
    mol_seg_res_t res;
    MolBuilder_Script_init(&b);

    MolBuilder_Script_set_code_hash(&b, g_sim_script_code_hash,
                                    sizeof(g_sim_script_code_hash));
    MolBuilder_Script_set_hash_type(&b, g_sim_script_hash_type);
    uint8_t* args_data = (uint8_t*)&g_sim_data.args_data;
    uint32_t args_data_len = 0;
    if (g_sim_data.args_data_has_identy) {
      args_data_len = sizeof(SimArgsData);
    } else {
      args_data_len = sizeof(SimArgsData) - sizeof(g_sim_data.args_data.identy);
    }
    mol_seg_t bytes = build_bytes(args_data, args_data_len);

    MolBuilder_Script_set_args(&b, bytes.ptr, bytes.size);

    res = MolBuilder_Script_build(b);
    assert(res.errno == 0);
    int ret = MolReader_Script_verify(&res.seg, false);
    assert(ret == 0);
    free(bytes.ptr);
    seg = res.seg;
  }

  if (addr == NULL) {
    *len = seg.size;
  } else {
    load_offset(seg.ptr, seg.size, addr, len, offset);
  };
  free(seg.ptr);
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
  ASSERT(false);
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
  return 0;
}

int ckb_load_cell_by_field(void* addr,
                           uint64_t* len,
                           size_t offset,
                           size_t index,
                           size_t source,
                           size_t field) {
  ASSERT(false);
  return 0;
}
