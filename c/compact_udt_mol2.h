
#ifndef _COMPACT_UDT_MOL2_API2_H_
#define _COMPACT_UDT_MOL2_API2_H_

#define MOLECULEC2_VERSION 6001
#define MOLECULE2_API_VERSION_MIN 5000

#include "molecule2_reader.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

// ----forward declaration--------
struct SignatureType;
struct SignatureVTable;
struct SignatureVTable *GetSignatureVTable(void);
struct SignatureType make_Signature(mol2_cursor_t *cur);
uint32_t Signature_len_impl(struct SignatureType *);
uint8_t Signature_get_impl(struct SignatureType *, uint32_t, bool *);
struct SignatureOptType;
struct SignatureOptVTable;
struct SignatureOptVTable *GetSignatureOptVTable(void);
struct SignatureOptType make_SignatureOpt(mol2_cursor_t *cur);
bool SignatureOpt_is_none_impl(struct SignatureOptType *);
bool SignatureOpt_is_some_impl(struct SignatureOptType *);
mol2_cursor_t SignatureOpt_unwrap_impl(struct SignatureOptType *);
struct ScriptHashType;
struct ScriptHashVTable;
struct ScriptHashVTable *GetScriptHashVTable(void);
struct ScriptHashType make_ScriptHash(mol2_cursor_t *cur);
uint32_t ScriptHash_len_impl(struct ScriptHashType *);
uint8_t ScriptHash_get_impl(struct ScriptHashType *, uint32_t, bool *);
struct IdentityType;
struct IdentityVTable;
struct IdentityVTable *GetIdentityVTable(void);
struct IdentityType make_Identity(mol2_cursor_t *cur);
uint32_t Identity_len_impl(struct IdentityType *);
uint8_t Identity_get_impl(struct IdentityType *, uint32_t, bool *);
struct DepositType;
struct DepositVTable;
struct DepositVTable *GetDepositVTable(void);
struct DepositType make_Deposit(mol2_cursor_t *cur);
mol2_cursor_t Deposit_get_source_impl(struct DepositType *);
mol2_cursor_t Deposit_get_target_impl(struct DepositType *);
mol2_cursor_t Deposit_get_amount_impl(struct DepositType *);
mol2_cursor_t Deposit_get_fee_impl(struct DepositType *);
struct DepositVecType;
struct DepositVecVTable;
struct DepositVecVTable *GetDepositVecVTable(void);
struct DepositVecType make_DepositVec(mol2_cursor_t *cur);
uint32_t DepositVec_len_impl(struct DepositVecType *);
struct DepositType DepositVec_get_impl(struct DepositVecType *, uint32_t,
                                       bool *);
struct MoveBetweenCompactSMTType;
struct MoveBetweenCompactSMTVTable;
struct MoveBetweenCompactSMTVTable *GetMoveBetweenCompactSMTVTable(void);
struct MoveBetweenCompactSMTType make_MoveBetweenCompactSMT(mol2_cursor_t *cur);
mol2_cursor_t MoveBetweenCompactSMT_get_script_hash_impl(
    struct MoveBetweenCompactSMTType *);
mol2_cursor_t MoveBetweenCompactSMT_get_identity_impl(
    struct MoveBetweenCompactSMTType *);
struct TransferTargetType;
struct TransferTargetVTable;
struct TransferTargetVTable *GetTransferTargetVTable(void);
struct TransferTargetType make_TransferTarget(mol2_cursor_t *cur);
uint32_t TransferTarget_item_id_impl(struct TransferTargetType *);
mol2_cursor_t TransferTarget_as_ScriptHash_impl(struct TransferTargetType *);
mol2_cursor_t TransferTarget_as_Identity_impl(struct TransferTargetType *);
struct MoveBetweenCompactSMTType TransferTarget_as_MoveBetweenCompactSMT_impl(
    struct TransferTargetType *);
struct RawTransferType;
struct RawTransferVTable;
struct RawTransferVTable *GetRawTransferVTable(void);
struct RawTransferType make_RawTransfer(mol2_cursor_t *cur);
mol2_cursor_t RawTransfer_get_source_impl(struct RawTransferType *);
struct TransferTargetType RawTransfer_get_target_impl(struct RawTransferType *);
mol2_cursor_t RawTransfer_get_amount_impl(struct RawTransferType *);
mol2_cursor_t RawTransfer_get_fee_impl(struct RawTransferType *);
struct TransferType;
struct TransferVTable;
struct TransferVTable *GetTransferVTable(void);
struct TransferType make_Transfer(mol2_cursor_t *cur);
struct RawTransferType Transfer_get_raw_impl(struct TransferType *);
mol2_cursor_t Transfer_get_signature_impl(struct TransferType *);
struct TransferVecType;
struct TransferVecVTable;
struct TransferVecVTable *GetTransferVecVTable(void);
struct TransferVecType make_TransferVec(mol2_cursor_t *cur);
uint32_t TransferVec_len_impl(struct TransferVecType *);
struct TransferType TransferVec_get_impl(struct TransferVecType *, uint32_t,
                                         bool *);
struct KVPairType;
struct KVPairVTable;
struct KVPairVTable *GetKVPairVTable(void);
struct KVPairType make_KVPair(mol2_cursor_t *cur);
mol2_cursor_t KVPair_get_k_impl(struct KVPairType *);
mol2_cursor_t KVPair_get_v_impl(struct KVPairType *);
struct KVPairVecType;
struct KVPairVecVTable;
struct KVPairVecVTable *GetKVPairVecVTable(void);
struct KVPairVecType make_KVPairVec(mol2_cursor_t *cur);
uint32_t KVPairVec_len_impl(struct KVPairVecType *);
struct KVPairType KVPairVec_get_impl(struct KVPairVecType *, uint32_t, bool *);
struct CompactUDTEntriesType;
struct CompactUDTEntriesVTable;
struct CompactUDTEntriesVTable *GetCompactUDTEntriesVTable(void);
struct CompactUDTEntriesType make_CompactUDTEntries(mol2_cursor_t *cur);
struct DepositVecType CompactUDTEntries_get_deposits_impl(
    struct CompactUDTEntriesType *);
struct TransferVecType CompactUDTEntries_get_transfers_impl(
    struct CompactUDTEntriesType *);
struct KVPairVecType CompactUDTEntries_get_kv_state_impl(
    struct CompactUDTEntriesType *);
mol2_cursor_t CompactUDTEntries_get_kv_proof_impl(
    struct CompactUDTEntriesType *);
struct SignatureOptType CompactUDTEntries_get_signature_impl(
    struct CompactUDTEntriesType *);

// ----definition-----------------
typedef struct SignatureVTable {
  uint32_t (*len)(struct SignatureType *);
  uint8_t (*get)(struct SignatureType *, uint32_t, bool *);
} SignatureVTable;
typedef struct SignatureType {
  mol2_cursor_t cur;
  SignatureVTable *t;
} SignatureType;

typedef struct SignatureOptVTable {
  bool (*is_none)(struct SignatureOptType *);
  bool (*is_some)(struct SignatureOptType *);
  mol2_cursor_t (*unwrap)(struct SignatureOptType *);
} SignatureOptVTable;
typedef struct SignatureOptType {
  mol2_cursor_t cur;
  SignatureOptVTable *t;
} SignatureOptType;

typedef struct ScriptHashVTable {
  uint32_t (*len)(struct ScriptHashType *);
  uint8_t (*get)(struct ScriptHashType *, uint32_t, bool *);
} ScriptHashVTable;
typedef struct ScriptHashType {
  mol2_cursor_t cur;
  ScriptHashVTable *t;
} ScriptHashType;

typedef struct IdentityVTable {
  uint32_t (*len)(struct IdentityType *);
  uint8_t (*get)(struct IdentityType *, uint32_t, bool *);
} IdentityVTable;
typedef struct IdentityType {
  mol2_cursor_t cur;
  IdentityVTable *t;
} IdentityType;

typedef struct DepositVTable {
  mol2_cursor_t (*source)(struct DepositType *);
  mol2_cursor_t (*target)(struct DepositType *);
  mol2_cursor_t (*amount)(struct DepositType *);
  mol2_cursor_t (*fee)(struct DepositType *);
} DepositVTable;
typedef struct DepositType {
  mol2_cursor_t cur;
  DepositVTable *t;
} DepositType;

typedef struct DepositVecVTable {
  uint32_t (*len)(struct DepositVecType *);
  struct DepositType (*get)(struct DepositVecType *, uint32_t, bool *);
} DepositVecVTable;
typedef struct DepositVecType {
  mol2_cursor_t cur;
  DepositVecVTable *t;
} DepositVecType;

typedef struct MoveBetweenCompactSMTVTable {
  mol2_cursor_t (*script_hash)(struct MoveBetweenCompactSMTType *);
  mol2_cursor_t (*identity)(struct MoveBetweenCompactSMTType *);
} MoveBetweenCompactSMTVTable;
typedef struct MoveBetweenCompactSMTType {
  mol2_cursor_t cur;
  MoveBetweenCompactSMTVTable *t;
} MoveBetweenCompactSMTType;

typedef struct TransferTargetVTable {
  uint32_t (*item_id)(struct TransferTargetType *);
  mol2_cursor_t (*as_ScriptHash)(struct TransferTargetType *);
  mol2_cursor_t (*as_Identity)(struct TransferTargetType *);
  struct MoveBetweenCompactSMTType (*as_MoveBetweenCompactSMT)(
      struct TransferTargetType *);
} TransferTargetVTable;
typedef struct TransferTargetType {
  mol2_cursor_t cur;
  TransferTargetVTable *t;
} TransferTargetType;

typedef struct RawTransferVTable {
  mol2_cursor_t (*source)(struct RawTransferType *);
  struct TransferTargetType (*target)(struct RawTransferType *);
  mol2_cursor_t (*amount)(struct RawTransferType *);
  mol2_cursor_t (*fee)(struct RawTransferType *);
} RawTransferVTable;
typedef struct RawTransferType {
  mol2_cursor_t cur;
  RawTransferVTable *t;
} RawTransferType;

typedef struct TransferVTable {
  struct RawTransferType (*raw)(struct TransferType *);
  mol2_cursor_t (*signature)(struct TransferType *);
} TransferVTable;
typedef struct TransferType {
  mol2_cursor_t cur;
  TransferVTable *t;
} TransferType;

typedef struct TransferVecVTable {
  uint32_t (*len)(struct TransferVecType *);
  struct TransferType (*get)(struct TransferVecType *, uint32_t, bool *);
} TransferVecVTable;
typedef struct TransferVecType {
  mol2_cursor_t cur;
  TransferVecVTable *t;
} TransferVecType;

typedef struct KVPairVTable {
  mol2_cursor_t (*k)(struct KVPairType *);
  mol2_cursor_t (*v)(struct KVPairType *);
} KVPairVTable;
typedef struct KVPairType {
  mol2_cursor_t cur;
  KVPairVTable *t;
} KVPairType;

typedef struct KVPairVecVTable {
  uint32_t (*len)(struct KVPairVecType *);
  struct KVPairType (*get)(struct KVPairVecType *, uint32_t, bool *);
} KVPairVecVTable;
typedef struct KVPairVecType {
  mol2_cursor_t cur;
  KVPairVecVTable *t;
} KVPairVecType;

typedef struct CompactUDTEntriesVTable {
  struct DepositVecType (*deposits)(struct CompactUDTEntriesType *);
  struct TransferVecType (*transfers)(struct CompactUDTEntriesType *);
  struct KVPairVecType (*kv_state)(struct CompactUDTEntriesType *);
  mol2_cursor_t (*kv_proof)(struct CompactUDTEntriesType *);
  struct SignatureOptType (*signature)(struct CompactUDTEntriesType *);
} CompactUDTEntriesVTable;
typedef struct CompactUDTEntriesType {
  mol2_cursor_t cur;
  CompactUDTEntriesVTable *t;
} CompactUDTEntriesType;

#ifndef MOLECULEC_C2_DECLARATION_ONLY

// ----implementation-------------
struct SignatureType make_Signature(mol2_cursor_t *cur) {
  SignatureType ret;
  ret.cur = *cur;
  ret.t = GetSignatureVTable();
  return ret;
}
struct SignatureVTable *GetSignatureVTable(void) {
  static SignatureVTable s_vtable;
  static int inited = 0;
  if (inited) return &s_vtable;
  s_vtable.len = Signature_len_impl;
  s_vtable.get = Signature_get_impl;
  return &s_vtable;
}
uint32_t Signature_len_impl(SignatureType *this) {
  return mol2_fixvec_length(&this->cur);
}
uint8_t Signature_get_impl(SignatureType *this, uint32_t index,
                           bool *existing) {
  uint8_t ret = {0};
  mol2_cursor_res_t res = mol2_fixvec_slice_by_index(&this->cur, 1, index);
  if (res.errno != MOL2_OK) {
    *existing = false;
    return ret;
  } else {
    *existing = true;
  }
  ret = convert_to_Uint8(&res.cur);
  return ret;
}
struct SignatureOptType make_SignatureOpt(mol2_cursor_t *cur) {
  SignatureOptType ret;
  ret.cur = *cur;
  ret.t = GetSignatureOptVTable();
  return ret;
}
struct SignatureOptVTable *GetSignatureOptVTable(void) {
  static SignatureOptVTable s_vtable;
  static int inited = 0;
  if (inited) return &s_vtable;
  s_vtable.is_none = SignatureOpt_is_none_impl;
  s_vtable.is_some = SignatureOpt_is_some_impl;
  s_vtable.unwrap = SignatureOpt_unwrap_impl;
  return &s_vtable;
}
bool SignatureOpt_is_none_impl(SignatureOptType *this) {
  return mol2_option_is_none(&this->cur);
}
bool SignatureOpt_is_some_impl(SignatureOptType *this) {
  return !mol2_option_is_none(&this->cur);
}
mol2_cursor_t SignatureOpt_unwrap_impl(SignatureOptType *this) {
  mol2_cursor_t ret;
  ret = convert_to_rawbytes(&this->cur);
  return ret;
}
struct ScriptHashType make_ScriptHash(mol2_cursor_t *cur) {
  ScriptHashType ret;
  ret.cur = *cur;
  ret.t = GetScriptHashVTable();
  return ret;
}
struct ScriptHashVTable *GetScriptHashVTable(void) {
  static ScriptHashVTable s_vtable;
  static int inited = 0;
  if (inited) return &s_vtable;
  s_vtable.len = ScriptHash_len_impl;
  s_vtable.get = ScriptHash_get_impl;
  return &s_vtable;
}
uint32_t ScriptHash_len_impl(ScriptHashType *this) { return 32; }
uint8_t ScriptHash_get_impl(ScriptHashType *this, uint32_t index,
                            bool *existing) {
  uint8_t ret = {0};
  mol2_cursor_res_t res = mol2_slice_by_offset2(&this->cur, 1 * index, 1);
  if (res.errno != MOL2_OK) {
    *existing = false;
    return ret;
  } else {
    *existing = true;
  }
  ret = convert_to_Uint8(&res.cur);
  return ret;
}
struct IdentityType make_Identity(mol2_cursor_t *cur) {
  IdentityType ret;
  ret.cur = *cur;
  ret.t = GetIdentityVTable();
  return ret;
}
struct IdentityVTable *GetIdentityVTable(void) {
  static IdentityVTable s_vtable;
  static int inited = 0;
  if (inited) return &s_vtable;
  s_vtable.len = Identity_len_impl;
  s_vtable.get = Identity_get_impl;
  return &s_vtable;
}
uint32_t Identity_len_impl(IdentityType *this) { return 21; }
uint8_t Identity_get_impl(IdentityType *this, uint32_t index, bool *existing) {
  uint8_t ret = {0};
  mol2_cursor_res_t res = mol2_slice_by_offset2(&this->cur, 1 * index, 1);
  if (res.errno != MOL2_OK) {
    *existing = false;
    return ret;
  } else {
    *existing = true;
  }
  ret = convert_to_Uint8(&res.cur);
  return ret;
}
struct DepositType make_Deposit(mol2_cursor_t *cur) {
  DepositType ret;
  ret.cur = *cur;
  ret.t = GetDepositVTable();
  return ret;
}
struct DepositVTable *GetDepositVTable(void) {
  static DepositVTable s_vtable;
  static int inited = 0;
  if (inited) return &s_vtable;
  s_vtable.source = Deposit_get_source_impl;
  s_vtable.target = Deposit_get_target_impl;
  s_vtable.amount = Deposit_get_amount_impl;
  s_vtable.fee = Deposit_get_fee_impl;
  return &s_vtable;
}
mol2_cursor_t Deposit_get_source_impl(DepositType *this) {
  mol2_cursor_t ret;
  mol2_cursor_t ret2 = mol2_table_slice_by_index(&this->cur, 0);
  ret = convert_to_array(&ret2);
  return ret;
}
mol2_cursor_t Deposit_get_target_impl(DepositType *this) {
  mol2_cursor_t ret;
  mol2_cursor_t ret2 = mol2_table_slice_by_index(&this->cur, 1);
  ret = convert_to_array(&ret2);
  return ret;
}
mol2_cursor_t Deposit_get_amount_impl(DepositType *this) {
  mol2_cursor_t ret;
  mol2_cursor_t ret2 = mol2_table_slice_by_index(&this->cur, 2);
  ret = convert_to_array(&ret2);
  return ret;
}
mol2_cursor_t Deposit_get_fee_impl(DepositType *this) {
  mol2_cursor_t ret;
  mol2_cursor_t ret2 = mol2_table_slice_by_index(&this->cur, 3);
  ret = convert_to_array(&ret2);
  return ret;
}
struct DepositVecType make_DepositVec(mol2_cursor_t *cur) {
  DepositVecType ret;
  ret.cur = *cur;
  ret.t = GetDepositVecVTable();
  return ret;
}
struct DepositVecVTable *GetDepositVecVTable(void) {
  static DepositVecVTable s_vtable;
  static int inited = 0;
  if (inited) return &s_vtable;
  s_vtable.len = DepositVec_len_impl;
  s_vtable.get = DepositVec_get_impl;
  return &s_vtable;
}
uint32_t DepositVec_len_impl(DepositVecType *this) {
  return mol2_dynvec_length(&this->cur);
}
DepositType DepositVec_get_impl(DepositVecType *this, uint32_t index,
                                bool *existing) {
  DepositType ret = {0};
  mol2_cursor_res_t res = mol2_dynvec_slice_by_index(&this->cur, index);
  if (res.errno != MOL2_OK) {
    *existing = false;
    return ret;
  } else {
    *existing = true;
  }
  ret.cur = res.cur;
  ret.t = GetDepositVTable();
  return ret;
}
struct MoveBetweenCompactSMTType make_MoveBetweenCompactSMT(
    mol2_cursor_t *cur) {
  MoveBetweenCompactSMTType ret;
  ret.cur = *cur;
  ret.t = GetMoveBetweenCompactSMTVTable();
  return ret;
}
struct MoveBetweenCompactSMTVTable *GetMoveBetweenCompactSMTVTable(void) {
  static MoveBetweenCompactSMTVTable s_vtable;
  static int inited = 0;
  if (inited) return &s_vtable;
  s_vtable.script_hash = MoveBetweenCompactSMT_get_script_hash_impl;
  s_vtable.identity = MoveBetweenCompactSMT_get_identity_impl;
  return &s_vtable;
}
mol2_cursor_t MoveBetweenCompactSMT_get_script_hash_impl(
    MoveBetweenCompactSMTType *this) {
  mol2_cursor_t ret;
  mol2_cursor_t ret2 = mol2_table_slice_by_index(&this->cur, 0);
  ret = convert_to_array(&ret2);
  return ret;
}
mol2_cursor_t MoveBetweenCompactSMT_get_identity_impl(
    MoveBetweenCompactSMTType *this) {
  mol2_cursor_t ret;
  mol2_cursor_t ret2 = mol2_table_slice_by_index(&this->cur, 1);
  ret = convert_to_array(&ret2);
  return ret;
}
struct TransferTargetType make_TransferTarget(mol2_cursor_t *cur) {
  TransferTargetType ret;
  ret.cur = *cur;
  ret.t = GetTransferTargetVTable();
  return ret;
}
struct TransferTargetVTable *GetTransferTargetVTable(void) {
  static TransferTargetVTable s_vtable;
  static int inited = 0;
  if (inited) return &s_vtable;
  s_vtable.item_id = TransferTarget_item_id_impl;
  s_vtable.as_ScriptHash = TransferTarget_as_ScriptHash_impl;
  s_vtable.as_Identity = TransferTarget_as_Identity_impl;
  s_vtable.as_MoveBetweenCompactSMT =
      TransferTarget_as_MoveBetweenCompactSMT_impl;
  return &s_vtable;
}
uint32_t TransferTarget_item_id_impl(TransferTargetType *this) {
  return mol2_unpack_number(&this->cur);
}
mol2_cursor_t TransferTarget_as_ScriptHash_impl(TransferTargetType *this) {
  mol2_cursor_t ret;
  mol2_union_t u = mol2_union_unpack(&this->cur);
  ret = convert_to_array(&u.cursor);
  return ret;
}
mol2_cursor_t TransferTarget_as_Identity_impl(TransferTargetType *this) {
  mol2_cursor_t ret;
  mol2_union_t u = mol2_union_unpack(&this->cur);
  ret = convert_to_array(&u.cursor);
  return ret;
}
MoveBetweenCompactSMTType TransferTarget_as_MoveBetweenCompactSMT_impl(
    TransferTargetType *this) {
  MoveBetweenCompactSMTType ret;
  mol2_union_t u = mol2_union_unpack(&this->cur);
  ret.cur = u.cursor;
  ret.t = GetMoveBetweenCompactSMTVTable();
  return ret;
}
struct RawTransferType make_RawTransfer(mol2_cursor_t *cur) {
  RawTransferType ret;
  ret.cur = *cur;
  ret.t = GetRawTransferVTable();
  return ret;
}
struct RawTransferVTable *GetRawTransferVTable(void) {
  static RawTransferVTable s_vtable;
  static int inited = 0;
  if (inited) return &s_vtable;
  s_vtable.source = RawTransfer_get_source_impl;
  s_vtable.target = RawTransfer_get_target_impl;
  s_vtable.amount = RawTransfer_get_amount_impl;
  s_vtable.fee = RawTransfer_get_fee_impl;
  return &s_vtable;
}
mol2_cursor_t RawTransfer_get_source_impl(RawTransferType *this) {
  mol2_cursor_t ret;
  mol2_cursor_t ret2 = mol2_table_slice_by_index(&this->cur, 0);
  ret = convert_to_array(&ret2);
  return ret;
}
TransferTargetType RawTransfer_get_target_impl(RawTransferType *this) {
  TransferTargetType ret;
  mol2_cursor_t cur = mol2_table_slice_by_index(&this->cur, 1);
  ret.cur = cur;
  ret.t = GetTransferTargetVTable();
  return ret;
}
mol2_cursor_t RawTransfer_get_amount_impl(RawTransferType *this) {
  mol2_cursor_t ret;
  mol2_cursor_t ret2 = mol2_table_slice_by_index(&this->cur, 2);
  ret = convert_to_array(&ret2);
  return ret;
}
mol2_cursor_t RawTransfer_get_fee_impl(RawTransferType *this) {
  mol2_cursor_t ret;
  mol2_cursor_t ret2 = mol2_table_slice_by_index(&this->cur, 3);
  ret = convert_to_array(&ret2);
  return ret;
}
struct TransferType make_Transfer(mol2_cursor_t *cur) {
  TransferType ret;
  ret.cur = *cur;
  ret.t = GetTransferVTable();
  return ret;
}
struct TransferVTable *GetTransferVTable(void) {
  static TransferVTable s_vtable;
  static int inited = 0;
  if (inited) return &s_vtable;
  s_vtable.raw = Transfer_get_raw_impl;
  s_vtable.signature = Transfer_get_signature_impl;
  return &s_vtable;
}
RawTransferType Transfer_get_raw_impl(TransferType *this) {
  RawTransferType ret;
  mol2_cursor_t cur = mol2_table_slice_by_index(&this->cur, 0);
  ret.cur = cur;
  ret.t = GetRawTransferVTable();
  return ret;
}
mol2_cursor_t Transfer_get_signature_impl(TransferType *this) {
  mol2_cursor_t ret;
  mol2_cursor_t re2 = mol2_table_slice_by_index(&this->cur, 1);
  ret = convert_to_rawbytes(&re2);
  return ret;
}
struct TransferVecType make_TransferVec(mol2_cursor_t *cur) {
  TransferVecType ret;
  ret.cur = *cur;
  ret.t = GetTransferVecVTable();
  return ret;
}
struct TransferVecVTable *GetTransferVecVTable(void) {
  static TransferVecVTable s_vtable;
  static int inited = 0;
  if (inited) return &s_vtable;
  s_vtable.len = TransferVec_len_impl;
  s_vtable.get = TransferVec_get_impl;
  return &s_vtable;
}
uint32_t TransferVec_len_impl(TransferVecType *this) {
  return mol2_dynvec_length(&this->cur);
}
TransferType TransferVec_get_impl(TransferVecType *this, uint32_t index,
                                  bool *existing) {
  TransferType ret = {0};
  mol2_cursor_res_t res = mol2_dynvec_slice_by_index(&this->cur, index);
  if (res.errno != MOL2_OK) {
    *existing = false;
    return ret;
  } else {
    *existing = true;
  }
  ret.cur = res.cur;
  ret.t = GetTransferVTable();
  return ret;
}
struct KVPairType make_KVPair(mol2_cursor_t *cur) {
  KVPairType ret;
  ret.cur = *cur;
  ret.t = GetKVPairVTable();
  return ret;
}
struct KVPairVTable *GetKVPairVTable(void) {
  static KVPairVTable s_vtable;
  static int inited = 0;
  if (inited) return &s_vtable;
  s_vtable.k = KVPair_get_k_impl;
  s_vtable.v = KVPair_get_v_impl;
  return &s_vtable;
}
mol2_cursor_t KVPair_get_k_impl(KVPairType *this) {
  mol2_cursor_t ret;
  mol2_cursor_t ret2 = mol2_slice_by_offset(&this->cur, 0, 32);
  ret = convert_to_array(&ret2);
  return ret;
}
mol2_cursor_t KVPair_get_v_impl(KVPairType *this) {
  mol2_cursor_t ret;
  mol2_cursor_t ret2 = mol2_slice_by_offset(&this->cur, 32, 32);
  ret = convert_to_array(&ret2);
  return ret;
}
struct KVPairVecType make_KVPairVec(mol2_cursor_t *cur) {
  KVPairVecType ret;
  ret.cur = *cur;
  ret.t = GetKVPairVecVTable();
  return ret;
}
struct KVPairVecVTable *GetKVPairVecVTable(void) {
  static KVPairVecVTable s_vtable;
  static int inited = 0;
  if (inited) return &s_vtable;
  s_vtable.len = KVPairVec_len_impl;
  s_vtable.get = KVPairVec_get_impl;
  return &s_vtable;
}
uint32_t KVPairVec_len_impl(KVPairVecType *this) {
  return mol2_fixvec_length(&this->cur);
}
KVPairType KVPairVec_get_impl(KVPairVecType *this, uint32_t index,
                              bool *existing) {
  KVPairType ret = {0};
  mol2_cursor_res_t res = mol2_fixvec_slice_by_index(&this->cur, 64, index);
  if (res.errno != MOL2_OK) {
    *existing = false;
    return ret;
  } else {
    *existing = true;
  }
  ret.cur = res.cur;
  ret.t = GetKVPairVTable();
  return ret;
}
struct CompactUDTEntriesType make_CompactUDTEntries(mol2_cursor_t *cur) {
  CompactUDTEntriesType ret;
  ret.cur = *cur;
  ret.t = GetCompactUDTEntriesVTable();
  return ret;
}
struct CompactUDTEntriesVTable *GetCompactUDTEntriesVTable(void) {
  static CompactUDTEntriesVTable s_vtable;
  static int inited = 0;
  if (inited) return &s_vtable;
  s_vtable.deposits = CompactUDTEntries_get_deposits_impl;
  s_vtable.transfers = CompactUDTEntries_get_transfers_impl;
  s_vtable.kv_state = CompactUDTEntries_get_kv_state_impl;
  s_vtable.kv_proof = CompactUDTEntries_get_kv_proof_impl;
  s_vtable.signature = CompactUDTEntries_get_signature_impl;
  return &s_vtable;
}
DepositVecType CompactUDTEntries_get_deposits_impl(
    CompactUDTEntriesType *this) {
  DepositVecType ret;
  mol2_cursor_t cur = mol2_table_slice_by_index(&this->cur, 0);
  ret.cur = cur;
  ret.t = GetDepositVecVTable();
  return ret;
}
TransferVecType CompactUDTEntries_get_transfers_impl(
    CompactUDTEntriesType *this) {
  TransferVecType ret;
  mol2_cursor_t cur = mol2_table_slice_by_index(&this->cur, 1);
  ret.cur = cur;
  ret.t = GetTransferVecVTable();
  return ret;
}
KVPairVecType CompactUDTEntries_get_kv_state_impl(CompactUDTEntriesType *this) {
  KVPairVecType ret;
  mol2_cursor_t cur = mol2_table_slice_by_index(&this->cur, 2);
  ret.cur = cur;
  ret.t = GetKVPairVecVTable();
  return ret;
}
mol2_cursor_t CompactUDTEntries_get_kv_proof_impl(CompactUDTEntriesType *this) {
  mol2_cursor_t ret;
  mol2_cursor_t re2 = mol2_table_slice_by_index(&this->cur, 3);
  ret = convert_to_rawbytes(&re2);
  return ret;
}
SignatureOptType CompactUDTEntries_get_signature_impl(
    CompactUDTEntriesType *this) {
  SignatureOptType ret;
  mol2_cursor_t cur = mol2_table_slice_by_index(&this->cur, 4);
  ret.cur = cur;
  ret.t = GetSignatureOptVTable();
  return ret;
}
#endif  // MOLECULEC_C2_DECLARATION_ONLY

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif  // _COMPACT_UDT_MOL2_API2_H_
