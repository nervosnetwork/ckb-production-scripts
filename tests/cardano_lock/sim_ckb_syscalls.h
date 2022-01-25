
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "ckb_consts.h"
#include "blockchain.h"

uint8_t g_witness_data[1024] = {0};
size_t g_witness_data_len = 0;

void set_witness(uint8_t* pubkey, uint8_t* signature) {
  memset(g_witness_data, 0, sizeof(g_witness_data));

  uint32_t* len = (uint32_t*)&g_witness_data[16];
  *len = 96;

  memcpy(&g_witness_data[20], pubkey, 32);
  memcpy(&g_witness_data[52], signature, 64);
  g_witness_data_len = 20 + 32 + 64;
}

int ckb_load_witness(void* addr, uint64_t* len, size_t offset, size_t index,
                     size_t source) {
  if (offset != 0) {
    ASSERT(false);
    return CKB_INVALID_DATA;
  }
  if (source != CKB_SOURCE_GROUP_INPUT && source != CKB_SOURCE_INPUT) {
    ASSERT(false);
    return CKB_INVALID_DATA;
  }
  if (index > 0) {
    return CKB_INDEX_OUT_OF_BOUND;
  }

  if (*len < g_witness_data_len) {
    ASSERT(false);
    return CKB_INVALID_DATA;
  }

  memcpy(addr, g_witness_data, g_witness_data_len);
  *len = g_witness_data_len;
  return 0;
}

int ckb_load_tx_hash(void* addr, uint64_t* len, size_t offset) {
  uint8_t hash[32] = {0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7,
                      0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7};
  ASSERT(offset == 0);
  ASSERT(*len >= 32);
  memcpy(addr, hash, 32);
  return 0;
}

uint8_t g_script_data[1024] = {0};
size_t g_scritp_data_len = 0;

void cudtmol_Bytes(uint8_t* buf, uint32_t len, uint8_t** output,
                   size_t* output_len) {}

void set_scritp(uint8_t* pubkey_hash) {
  memset(g_script_data, 0, sizeof(g_script_data));

  uint8_t script_hash[32] = {0};

  uint8_t* args_buf = NULL;
  size_t args_buf_len = 0;
  {
    uint8_t args_data[21] = {0x7, 0};
    memcpy(&args_data[1], pubkey_hash, 20);

    mol_builder_t b;
    MolBuilder_Bytes_init(&b);

    for (uint32_t i = 0; i < sizeof(args_data); i++) {
      MolBuilder_Bytes_push(&b, args_data[i]);
    }

    mol_seg_res_t r = MolBuilder_Bytes_build(b);
    args_buf = r.seg.ptr;
    args_buf_len = r.seg.size;
  }

  uint8_t* sc_buf = NULL;
  size_t sc_buf_len = 0;
  {
    mol_builder_t b;
    mol_seg_res_t res;
    MolBuilder_Script_init(&b);

    MolBuilder_Script_set_code_hash(&b, script_hash, sizeof(script_hash));
    MolBuilder_Script_set_hash_type(&b, 0);
    MolBuilder_Script_set_args(&b, args_buf, args_buf_len);

    res = MolBuilder_Script_build(b);
    ASSERT(res.errno == 0);
    int ret = MolReader_Script_verify(&res.seg, false);
    ASSERT(sc_buf_len < sizeof(res.seg.size));
    sc_buf = res.seg.ptr;
    sc_buf_len = res.seg.size;
  }

  memcpy(g_script_data, sc_buf, sc_buf_len);
  g_scritp_data_len = sc_buf_len;
  free(sc_buf);
  free(args_buf);
}

int ckb_load_script(void* addr, uint64_t* len, size_t offset) {
  if (offset != 0) {
    ASSERT(false);
    return CKB_INVALID_DATA;
  }

  if (*len < g_scritp_data_len) {
    ASSERT(false);
    return CKB_INVALID_DATA;
  }

  memcpy(addr, g_script_data, g_scritp_data_len);
  *len = g_scritp_data_len;
  return 0;
}

int ckb_calculate_inputs_len() { return 1; }

int ckb_exit(int8_t code) { return 1; }
