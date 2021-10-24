#ifndef __TESTS_COMPACT_UDT_SIMULATOR_COMPACT_UDT_LOCK_INC_H_
#define __TESTS_COMPACT_UDT_SIMULATOR_COMPACT_UDT_LOCK_INC_H_

#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus

#include <stddef.h>
#include <stdint.h>

#include "compact_udt_lock.h"

int compact_udt_lock_main();

void* cudt_blake2b_init(size_t l);
void cudt_blake2b_uninit(void* s);
int cudt_blake2b_update(void* s, const void* d, size_t l);
int cudt_blake2b_final(void* s, void* o, size_t l);

typedef void* CUDT_SMT_H;
CUDT_SMT_H cudt_smt_init(int capacity);
void cudt_smt_uninit(CUDT_SMT_H h);
void cudt_smt_insert(CUDT_SMT_H h, const uint8_t* key, const uint8_t* val);
void cudt_smt_calculate_root(CUDT_SMT_H h,
                             uint8_t* buffer,
                             const uint8_t* proof,
                             uint32_t proof_length);
bool cudt_smt_verify(CUDT_SMT_H h,
                     const uint8_t* hash,
                     const uint8_t* proof,
                     uint32_t proof_length);

typedef struct __SBuffer {
  uint8_t* buf;
  uint32_t len;
} SBuffer;

SBuffer cudtmol_alloc(uint32_t len);
void cudtmol_free(SBuffer* buf);

SBuffer cudtmol_Bytes(uint8_t* buf, uint32_t len);

SBuffer cudtmol_Script(SBuffer* script_hash, uint8_t hash_type, SBuffer* args);

typedef void* CUDTMolType;
typedef void (*CUDTMolFunc_Init)(void* b);
typedef void (*CUDTMolFunc_Push)(void* b, uint8_t* p, uint32_t len);
typedef SBuffer (*CUDTMolFunc_Build)(void* b);

CUDTMolType cudtmol_VecTemplate_Init(CUDTMolFunc_Init func_init,
                                     CUDTMolFunc_Push func_push,
                                     CUDTMolFunc_Build func_build);
void cudtmol_VecTemplate_Push(CUDTMolType t, uint8_t* p, uint32_t len);
SBuffer cudtmol_VecTemplate_Build(CUDTMolType t);

#define SPLICING_FUNC_NAME1(t1, t2) t1##t2
#define SPLICING_FUNC_NAME2(t1, t2) SPLICING_FUNC_NAME1(t1, t2)

#define CUDTMOL_VT_FUNC(t1, t2, t3) \
  SPLICING_FUNC_NAME2(SPLICING_FUNC_NAME1(t1, t2), t3)

#define CUDTMOL_VT_FUNC_REG(name)                                     \
  void CUDTMOL_VT_FUNC(cudtmol_VT_, name, _Init)(void* b);            \
  void CUDTMOL_VT_FUNC(cudtmol_VT_, name, _Push)(void* b, uint8_t* p, \
                                                 uint32_t len);       \
  SBuffer CUDTMOL_VT_FUNC(cudtmol_VT_, name, _Build)(void* b);        \
  inline CUDTMolType CUDTMOL_VT_FUNC(cudtmol_, name, _Vec_Init)() {   \
    return cudtmol_VecTemplate_Init(                                  \
        CUDTMOL_VT_FUNC(cudtmol_VT_, name, _Init),                    \
        CUDTMOL_VT_FUNC(cudtmol_VT_, name, _Push),                    \
        CUDTMOL_VT_FUNC(cudtmol_VT_, name, _Build));                  \
  }

CUDTMOL_VT_FUNC_REG(Deposit);
CUDTMOL_VT_FUNC_REG(Transfer);
CUDTMOL_VT_FUNC_REG(KVPair);

SBuffer cudtmol_Deposit(SBuffer* source,
                        SBuffer* target,
                        SBuffer* amount,
                        SBuffer* fee);

SBuffer cudtmol_MoveBetweenCompactSMT(SBuffer* script_hash, SBuffer* identity);

SBuffer cudtmol_TransferTarget(CacheTransferSourceType type, SBuffer* buf);

SBuffer cudtmol_TransferRaw(SBuffer* source,
                            SBuffer* target,
                            SBuffer* amount,
                            SBuffer* fee);

SBuffer cudtmol_Transfer(SBuffer* raw, SBuffer* sign);

SBuffer cudtmol_KVPair(SBuffer* k, SBuffer* v);

SBuffer cudtmol_CompactUDTEntries(SBuffer* deposits,
                                  SBuffer* transfers,
                                  SBuffer* kv_state,
                                  SBuffer* kv_proof);

SBuffer cudtmol_Witness(SBuffer* lock, SBuffer* input, SBuffer* output);

enum __CUDTMOL_Type {
  CUDTMOLType_Scritp,
  CUDTMOLType_CellData,
  CUDTMOLType_Witness,
};
typedef uint8_t CUDTMOL_Type;

typedef struct __CUDTMOL_Data {
  CUDTMOL_Type type;
  size_t index;
  size_t source;
  uint32_t len;
  bool index_out_of_bound;

  size_t field;
  bool by_field;

} CUDTMOL_Data;

uint8_t* cudtmol_get_data(CUDTMOL_Data* param);

#ifdef __cplusplus
}
#endif  // __cplusplus

#endif  // __TESTS_COMPACT_UDT_SIMULATOR_COMPACT_UDT_LOCK_INC_H_
