

#include "compact_udt_lock.c"

#include "compact_udt_cc.h"
#include "compact_udt_lock_inc.h"

void test() {
  uint8_t proof[] = {
      0x4C, 0x4F, 0xA7, 0x4C, 0x4F, 0xA5, 0x4C, 0x4F, 0xA4, 0x4C,
      0x4F, 0xA4, 0x48, 0x48, 0x4F, 0x01, 0x48, 0x4F, 0x58,
  };

  uint8_t key1[] = {
      0x03, 0xD5, 0x75, 0x75, 0x4A, 0x96, 0x1D, 0x37, 0x75, 0xB8, 0xEF,
      0xC2, 0x1A, 0x91, 0xDB, 0xC4, 0x81, 0x10, 0xC6, 0x18, 0x95, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  };

  uint8_t val1[] = {
      0x0A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  };

  uint8_t key2[] = {
      0x02, 0xC0, 0xC8, 0xA5, 0x81, 0x03, 0x4B, 0xD9, 0xBA, 0xD3, 0x21,
      0xEA, 0xA4, 0xDD, 0x46, 0x4E, 0x55, 0xCF, 0x5B, 0x4E, 0xBF, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  };

  uint8_t val2[] = {
      0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x1E, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  };

  uint8_t key3[] = {
      0x03, 0x6D, 0xF2, 0xCA, 0x38, 0x79, 0x4C, 0xBD, 0x31, 0x47, 0x94,
      0x41, 0xB5, 0x22, 0x7A, 0x5C, 0xDA, 0x1A, 0x25, 0x8D, 0xA6, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  };

  uint8_t val3[] = {
      0xF4, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  };

  uint8_t key4[] = {
      0x02, 0x63, 0x5B, 0xBB, 0x8A, 0x6F, 0x58, 0x6E, 0x40, 0x77, 0xCB,
      0x18, 0xA5, 0xD1, 0x2E, 0x68, 0x17, 0xA9, 0xC6, 0xAF, 0x06, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  };

  uint8_t val4[] = {
      0x0A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x37, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  };

  smt_state_t smt_state = {0};
  smt_pair_t smt_pairs[32] = {0};
  smt_state_init(&smt_state, smt_pairs, 32);

  smt_state_insert(&smt_state, key1, val1);
  smt_state_insert(&smt_state, key2, val2);
  smt_state_insert(&smt_state, key3, val3);
  smt_state_insert(&smt_state, key4, val4);

  smt_state_normalize(&smt_state);

  uint8_t ref_hash[32] = {0};
  smt_calculate_root(ref_hash, &smt_state, proof, sizeof(proof));
  //PRINT_MEM2(ref_hash, 32);
}

int compact_udt_lock_main() {
  test();
  int argc = 1;
  char* argv[] = {"./"};
  int ret_code = simulator_main(argc, argv);
  return ret_code;
}

void* cudt_blake2b_init(size_t l) {
  blake2b_state* s = (blake2b_state*)malloc(sizeof(blake2b_state));
  ASSERT_DBG(blake2b_init(s, l) == 0);
  return s;
}
void cudt_blake2b_uninit(void* s) {
  free(s);
}
int cudt_blake2b_update(void* s, const void* d, size_t l) {
  return blake2b_update((blake2b_state*)s, d, l);
}
int cudt_blake2b_final(void* s, void* o, size_t l) {
  return blake2b_final((blake2b_state*)s, o, l);
}

typedef struct __SMTHandle {
  smt_state_t state;
  smt_pair_t* pairs;
} SMTHandle;
CUDT_SMT_H cudt_smt_init(int capacity) {
  SMTHandle* h = (SMTHandle*)malloc(sizeof(SMTHandle));
  h->pairs = (smt_pair_t*)malloc(sizeof(smt_pair_t) * capacity);
  smt_state_init(&(h->state), h->pairs, capacity);
  return h;
}
void cudt_smt_uninit(CUDT_SMT_H h) {
  ASSERT_DBG(h);
  SMTHandle* hh = (SMTHandle*)h;
  ASSERT_DBG(hh->pairs);

  free(hh->pairs);
  free(hh);
}
void cudt_smt_insert(CUDT_SMT_H h, const uint8_t* key, const uint8_t* val) {
  SMTHandle* hh = (SMTHandle*)h;
  int ret = smt_state_insert(&(hh->state), key, val);
  ASSERT_DBG(ret == 0);
}
void cudt_smt_calculate_root(CUDT_SMT_H h,
                             uint8_t* buffer,
                             const uint8_t* proof,
                             uint32_t proof_length) {
  SMTHandle* hh = (SMTHandle*)h;
  smt_state_normalize(&(hh->state));
  int ret = smt_calculate_root(buffer, &(hh->state), proof, proof_length);
  ASSERT_DBG(ret == 0);
}
bool cudt_smt_verify(CUDT_SMT_H h,
                     const uint8_t* hash,
                     const uint8_t* proof,
                     uint32_t proof_length) {
  SMTHandle* hh = (SMTHandle*)h;
  smt_state_normalize(&(hh->state));
  return smt_verify(hash, &(hh->state), proof, proof_length) == 0;
}

SBuffer cudtmol_alloc(uint32_t len) {
  SBuffer s;
  s.buf = (uint8_t*)malloc(len);
  s.len = len;
  return s;
}

SBuffer cudtmol_alloc_buf(uint8_t* buf, uint32_t len) {
  SBuffer ret = cudtmol_alloc(len);
  memcpy(ret.buf, buf, len);
  return ret;
}

SBuffer cudtmol_alloc_seg(const mol_seg_res_t* r) {
  ASSERT_DBG(!r->errno);
  return cudtmol_alloc_buf(r->seg.ptr, r->seg.size);
}

void cudtmol_free(SBuffer* buf) {
  ASSERT_DBG(buf);
  ASSERT_DBG(buf->buf);
  free(buf->buf);
}

SBuffer cudtmol_Bytes(uint8_t* buf, uint32_t len) {
  mol_builder_t b;
  MolBuilder_Bytes_init(&b);

  for (uint32_t i = 0; i < len; i++) {
    MolBuilder_Bytes_push(&b, buf[i]);
  }

  mol_seg_res_t r = MolBuilder_Bytes_build(b);
  SBuffer ret = cudtmol_alloc_seg(&r);
  return ret;
}

SBuffer cudtmol_Script(SBuffer* script_hash, uint8_t hash_type, SBuffer* args) {
  mol_builder_t b;
  mol_seg_res_t res;
  MolBuilder_Script_init(&b);

  MolBuilder_Script_set_code_hash(&b, script_hash->buf, script_hash->len);
  MolBuilder_Script_set_hash_type(&b, hash_type);
  MolBuilder_Script_set_args(&b, args->buf, args->len);

  res = MolBuilder_Script_build(b);
  ASSERT_DBG(res.errno == 0);
  int ret = MolReader_Script_verify(&res.seg, false);
  ASSERT_DBG(!ret);
  SBuffer r = cudtmol_alloc_seg(&res);
  return r;
}

typedef struct __CUDTMolTypes {
  CUDTMolFunc_Push func_push;
  CUDTMolFunc_Build func_build;
  mol_builder_t b;
} CUDTMolTypes;

CUDTMolType cudtmol_VecTemplate_Init(CUDTMolFunc_Init func_init,
                                     CUDTMolFunc_Push func_push,
                                     CUDTMolFunc_Build func_build) {
  CUDTMolTypes* t = (CUDTMolTypes*)malloc(sizeof(CUDTMolTypes));
  func_init(&(t->b));
  t->func_push = func_push;
  t->func_build = func_build;
  return t;
}
void cudtmol_VecTemplate_Push(CUDTMolType pt, uint8_t* p, uint32_t l) {
  CUDTMolTypes* t = (CUDTMolTypes*)pt;
  t->func_push(&(t->b), p, l);
}
SBuffer cudtmol_VecTemplate_Build(CUDTMolType pt) {
  CUDTMolTypes* t = (CUDTMolTypes*)pt;
  SBuffer sbuf = t->func_build(&(t->b));

  free(t);
  return sbuf;
}

// CUDTMOL_VT_FUNC(cudtmol_VT_, name, _Init)

#define CUDTMOL_VT_FUNC_IMP_INIT(name)                               \
  void CUDTMOL_VT_FUNC(cudtmol_VT_, name, _Init)(void* b) {          \
    CUDTMOL_VT_FUNC(MolBuilder_, name, Vec_init)((mol_builder_t*)b); \
  }

#define CUDTMOL_VT_FUNC_IMP_PUSH(name)                                       \
  void CUDTMOL_VT_FUNC(cudtmol_VT_, name, _Push)(void* b, uint8_t* p,        \
                                                 uint32_t len) {             \
    CUDTMOL_VT_FUNC(MolBuilder_, name, Vec_push)((mol_builder_t*)b, p, len); \
  }

#define CUDTMOL_VT_FUNC_IMP_PUSH2(name)                                 \
  void CUDTMOL_VT_FUNC(cudtmol_VT_, name, _Push)(void* b, uint8_t* p,   \
                                                 uint32_t len) {        \
    CUDTMOL_VT_FUNC(MolBuilder_, name, Vec_push)((mol_builder_t*)b, p); \
  }

#define CUDTMOL_VT_FUNC_IMP_BUILD(name)                                    \
  SBuffer CUDTMOL_VT_FUNC(cudtmol_VT_, name, _Build)(void* b) {            \
    mol_seg_res_t r =                                                      \
        CUDTMOL_VT_FUNC(MolBuilder_, name, Vec_build)(*(mol_builder_t*)b); \
    return cudtmol_alloc_seg(&r);                                          \
  }

#define CUDTMOL_VT_FUNC_IMP(name) \
  CUDTMOL_VT_FUNC_IMP_INIT(name); \
  CUDTMOL_VT_FUNC_IMP_PUSH(name); \
  CUDTMOL_VT_FUNC_IMP_BUILD(name);

#define CUDTMOL_VT_FUNC_IMP2(name) \
  CUDTMOL_VT_FUNC_IMP_INIT(name);  \
  CUDTMOL_VT_FUNC_IMP_PUSH2(name); \
  CUDTMOL_VT_FUNC_IMP_BUILD(name);

CUDTMOL_VT_FUNC_IMP(Deposit);
CUDTMOL_VT_FUNC_IMP(Transfer);
CUDTMOL_VT_FUNC_IMP2(KVPair);

SBuffer cudtmol_Deposit(SBuffer* source,
                        SBuffer* target,
                        SBuffer* amount,
                        SBuffer* fee) {
  mol_builder_t b;
  MolBuilder_Deposit_init(&b);

  MolBuilder_Deposit_set_source(&b, source->buf, source->len);
  MolBuilder_Deposit_set_target(&b, target->buf, target->len);
  MolBuilder_Deposit_set_amount(&b, amount->buf, amount->len);
  MolBuilder_Deposit_set_fee(&b, fee->buf, fee->len);

  mol_seg_res_t r = MolBuilder_Deposit_build(b);
  return cudtmol_alloc_seg(&r);
}

SBuffer cudtmol_MoveBetweenCompactSMT(SBuffer* script_hash, SBuffer* identity) {
  mol_builder_t b;
  MolBuilder_MoveBetweenCompactSMT_init(&b);

  MolBuilder_MoveBetweenCompactSMT_set_script_hash(&b, script_hash->buf,
                                                   script_hash->len);

  MolBuilder_MoveBetweenCompactSMT_set_identity(&b, identity->buf,
                                                identity->len);

  mol_seg_res_t r = MolBuilder_MoveBetweenCompactSMT_build(b);
  return cudtmol_alloc_seg(&r);
}

SBuffer cudtmol_TransferTarget(CacheTransferSourceType type, SBuffer* buf) {
  mol_builder_t b;
  MolBuilder_TransferTarget_init(&b);

  switch (type) {
    case TargetType_ScriptHash:
      MolBuilder_TransferTarget_set_ScriptHash(&b, buf->buf, buf->len);
      break;
    case TargetType_Identity:
      MolBuilder_TransferTarget_set_Identity(&b, buf->buf, buf->len);
      break;
    case TargetType_MoveBetweenCompactSMT:
      MolBuilder_TransferTarget_set_MoveBetweenCompactSMT(&b, buf->buf,
                                                          buf->len);
      break;
  }

  mol_seg_res_t r = MolBuilder_TransferTarget_build(b);
  return cudtmol_alloc_seg(&r);
}

SBuffer cudtmol_TransferRaw(SBuffer* source,
                            SBuffer* target,
                            SBuffer* amount,
                            SBuffer* fee) {
  mol_builder_t b;
  MolBuilder_RawTransfer_init(&b);

  MolBuilder_RawTransfer_set_source(&b, source->buf, source->len);
  MolBuilder_RawTransfer_set_target(&b, target->buf, target->len);
  MolBuilder_RawTransfer_set_amount(&b, amount->buf, amount->len);
  MolBuilder_RawTransfer_set_fee(&b, fee->buf, fee->len);

  mol_seg_res_t r = MolBuilder_RawTransfer_build(b);
  return cudtmol_alloc_seg(&r);
}

SBuffer cudtmol_Transfer(SBuffer* raw, SBuffer* sign) {
  mol_builder_t b;
  MolBuilder_Transfer_init(&b);

  MolBuilder_Transfer_set_raw(&b, raw->buf, raw->len);
  MolBuilder_Transfer_set_signature(&b, sign->buf, sign->len);

  mol_seg_res_t r = MolBuilder_Transfer_build(b);
  return cudtmol_alloc_seg(&r);
}

SBuffer cudtmol_KVPair(SBuffer* k, SBuffer* v) {
  mol_builder_t b;
  MolBuilder_KVPair_init(&b);

  MolBuilder_KVPair_set_k(&b, k->buf);
  MolBuilder_KVPair_set_v(&b, v->buf);

  mol_seg_res_t r = MolBuilder_KVPair_build(b);
  return cudtmol_alloc_seg(&r);
}

SBuffer cudtmol_CompactUDTEntries(SBuffer* deposits,
                                  SBuffer* transfers,
                                  SBuffer* kv_state,
                                  SBuffer* kv_proof,
                                  SBuffer* signature) {
  mol_builder_t b;
  MolBuilder_CompactUDTEntries_init(&b);

  MolBuilder_CompactUDTEntries_set_deposits(&b, deposits->buf, deposits->len);
  MolBuilder_CompactUDTEntries_set_transfers(&b, transfers->buf,
                                             transfers->len);
  MolBuilder_CompactUDTEntries_set_kv_state(&b, kv_state->buf, kv_state->len);
  MolBuilder_CompactUDTEntries_set_kv_proof(&b, kv_proof->buf, kv_proof->len);

  if (signature && signature->buf) {
    MolBuilder_CompactUDTEntries_set_signature(&b, signature->buf,
                                               signature->len);
  }

  mol_seg_res_t r = MolBuilder_CompactUDTEntries_build(b);

  return cudtmol_alloc_seg(&r);
}

SBuffer cudtmol_OptSignature(SBuffer* data) {
  mol_builder_t b;
  MolBuilder_Signature_init(&b);

  for (uint32_t i = 0; i < data->len; i++)
    MolBuilder_Signature_push(&b, data->buf[i]);
  mol_seg_res_t r = MolBuilder_Signature_build(b);
  SBuffer d = cudtmol_alloc_seg(&r);

  mol_builder_t b_opt;
  MolBuilder_SignatureOpt_init(&b_opt);
  MolBuilder_SignatureOpt_set(&b_opt, d.buf, d.len);
  mol_seg_res_t r_opt = MolBuilder_SignatureOpt_build(b_opt);
  cudtmol_free(&d);

  return cudtmol_alloc_seg(&r_opt);
}

SBuffer cudtmol_Witness(SBuffer* lock, SBuffer* input, SBuffer* output) {
  mol_builder_t b;
  MolBuilder_WitnessArgs_init(&b);

  if (lock && lock->len > 0) {
    SBuffer buf = cudtmol_Bytes(lock->buf, lock->len);
    MolBuilder_WitnessArgs_set_lock(&b, buf.buf, buf.len);
    cudtmol_free(&buf);
  }

  if (input && input->len > 0) {
    SBuffer buf = cudtmol_Bytes(input->buf, input->len);
    MolBuilder_WitnessArgs_set_input_type(&b, buf.buf, buf.len);
    cudtmol_free(&buf);
  }

  if (output && output->len > 0) {
    SBuffer buf = cudtmol_Bytes(output->buf, output->len);
    MolBuilder_WitnessArgs_set_output_type(&b, buf.buf, buf.len);
    cudtmol_free(&buf);
  }

  mol_seg_res_t r = MolBuilder_WitnessArgs_build(b);
  return cudtmol_alloc_seg(&r);
}

SBuffer cudtmol_bytes_vec(SBuffer** data, uint32_t len) {
  mol_builder_t b;
  MolBuilder_BytesVec_init(&b);

  for (uint32_t i = 0; i < len; i++) {
    MolBuilder_BytesVec_push(&b, data[i]->buf, data[i]->len);
  }

  mol_seg_res_t r = MolBuilder_BytesVec_build(b);
  return cudtmol_alloc_seg(&r);
}

SBuffer cudtmol_xudtdata(SBuffer* lock, SBuffer* data) {
  mol_builder_t b;
  MolBuilder_XudtData_init(&b);

  MolBuilder_XudtData_set_lock(&b, lock->buf, lock->len);
  MolBuilder_XudtData_set_data(&b, data->buf, data->len);

  mol_seg_res_t r = MolBuilder_XudtData_build(b);
  return cudtmol_alloc_seg(&r);
}

uint8_t* cudtmol_get_data(CUDTMOL_Data* param) {
  return cc_get_data(param);
}

uint32_t cudtmol_get_input_len() {
  return cc_get_input_len();
}
