
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "blockchain.h"
#include "ckb_consts.h"

#include "cardano_lock_mol.h"
#include "cardano_lock_mol2.h"

uint8_t g_witness_data[1024] = {0};
size_t g_witness_data_len = 0;

typedef struct _FmtBuf {
  uint8_t* buf;
  size_t len;
} FmtBuf;

FmtBuf _mol_get_buf(mol_seg_res_t* r) {
  FmtBuf fmtbuf = {0};
  fmtbuf.buf = r->seg.ptr;
  fmtbuf.len = r->seg.size;
  return fmtbuf;
}

void _mol_free_buf(FmtBuf* buf) {
  if (buf && buf->buf)
    free(buf->buf);
  memset(buf, 0, sizeof(FmtBuf));
}

FmtBuf _mol_fmt_bytes(uint8_t* buf, uint32_t len) {
  mol_builder_t b;
  MolBuilder_Bytes_init(&b);

  for (uint32_t i = 0; i < len; i++) {
    MolBuilder_Bytes_push(&b, buf[i]);
  }
  mol_seg_res_t r = MolBuilder_Bytes_build(b);
  return _mol_get_buf(&r);
}

void set_witness(uint8_t* pubkey,
                 uint8_t* signature,
                 uint8_t* new_msg,
                 size_t new_msg_len) {
  memset(g_witness_data, 0, sizeof(g_witness_data));
  mol_builder_t builder_witness;
  MolBuilder_WitnessArgs_init(&builder_witness);

  mol_builder_t builder_lock;
  MolBuilder_CardanoWitnessLock_init(&builder_lock);
  MolBuilder_CardanoWitnessLock_set_pubkey(&builder_lock, pubkey, 32);
  MolBuilder_CardanoWitnessLock_set_signature(&builder_lock, signature, 64);
  FmtBuf newmsg_buf = _mol_fmt_bytes(new_msg, new_msg_len);
  MolBuilder_CardanoWitnessLock_set_new_message(&builder_lock, newmsg_buf.buf,
                                                newmsg_buf.len);
  mol_seg_res_t lock_res = MolBuilder_CardanoWitnessLock_build(builder_lock);

  FmtBuf lock_buf = _mol_get_buf(&lock_res);
  FmtBuf lock_res_buf = _mol_fmt_bytes(lock_buf.buf, lock_buf.len);
  MolBuilder_WitnessArgs_set_lock(&builder_witness, lock_res_buf.buf,
                                  lock_res_buf.len);
  mol_seg_res_t r = MolBuilder_WitnessArgs_build(builder_witness);
  FmtBuf ret = _mol_get_buf(&r);
  ASSERT(ret.len <= sizeof(g_witness_data));

  memcpy(g_witness_data, ret.buf, ret.len);
  g_witness_data_len = ret.len;
  _mol_free_buf(&ret);
  _mol_free_buf(&lock_buf);
  _mol_free_buf(&lock_res_buf);
  _mol_free_buf(&newmsg_buf);
}

int ckb_load_witness(void* addr,
                     uint64_t* len,
                     size_t offset,
                     size_t index,
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
    *len = g_witness_data_len;
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

void set_scritp(uint8_t* pubkey_hash, uint8_t* stake_pubkey_hash) {
  memset(g_script_data, 0, sizeof(g_script_data));

  uint8_t script_hash[32] = {0};

  uint8_t* args_buf = NULL;
  size_t args_buf_len = 0;
  {
    uint8_t args_data[64] = {0};
    memcpy(args_data, pubkey_hash, 32);
    memcpy(&args_data[32], stake_pubkey_hash, 32);

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

int ckb_calculate_inputs_len() {
  return 1;
}

int ckb_exit(int8_t code) {
  return 1;
}
