
#ifndef _RC_LOCK_MOL2_API2_H_
#define _RC_LOCK_MOL2_API2_H_

#ifndef MOLECULEC_VERSION
#define MOLECULEC_VERSION 6001
#endif
#ifndef MOLECULE_API_VERSION_MIN
#define MOLECULE_API_VERSION_MIN 5000
#endif

#define MOLECULEC2_VERSION 6001
#define MOLECULE2_API_VERSION_MIN 5000

#include "molecule2_reader.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

// ----forward declaration--------
struct SmtProofEntryVecOptType;
struct SmtProofEntryVecOptVTable;
struct SmtProofEntryVecOptVTable *GetSmtProofEntryVecOptVTable(void);
struct SmtProofEntryVecOptType make_SmtProofEntryVecOpt(mol2_cursor_t *cur);
bool SmtProofEntryVecOpt_is_none_impl(struct SmtProofEntryVecOptType *);
bool SmtProofEntryVecOpt_is_some_impl(struct SmtProofEntryVecOptType *);
struct SmtProofEntryVecType SmtProofEntryVecOpt_unwrap_impl(
    struct SmtProofEntryVecOptType *);
struct RcLockWitnessLockType;
struct RcLockWitnessLockVTable;
struct RcLockWitnessLockVTable *GetRcLockWitnessLockVTable(void);
struct RcLockWitnessLockType make_RcLockWitnessLock(mol2_cursor_t *cur);
struct BytesOptType RcLockWitnessLock_get_signature_impl(
    struct RcLockWitnessLockType *);
struct SmtProofEntryVecOptType RcLockWitnessLock_get_proofs_impl(
    struct RcLockWitnessLockType *);

// ----definition-----------------
typedef struct SmtProofEntryVecOptVTable {
  bool (*is_none)(struct SmtProofEntryVecOptType *);
  bool (*is_some)(struct SmtProofEntryVecOptType *);
  struct SmtProofEntryVecType (*unwrap)(struct SmtProofEntryVecOptType *);
} SmtProofEntryVecOptVTable;
typedef struct SmtProofEntryVecOptType {
  mol2_cursor_t cur;
  SmtProofEntryVecOptVTable *t;
} SmtProofEntryVecOptType;

typedef struct RcLockWitnessLockVTable {
  struct BytesOptType (*signature)(struct RcLockWitnessLockType *);
  struct SmtProofEntryVecOptType (*proofs)(struct RcLockWitnessLockType *);
} RcLockWitnessLockVTable;
typedef struct RcLockWitnessLockType {
  mol2_cursor_t cur;
  RcLockWitnessLockVTable *t;
} RcLockWitnessLockType;

#ifndef MOLECULEC_C2_DECLARATION_ONLY

// ----implementation-------------
struct SmtProofEntryVecOptType make_SmtProofEntryVecOpt(mol2_cursor_t *cur) {
  SmtProofEntryVecOptType ret;
  ret.cur = *cur;
  ret.t = GetSmtProofEntryVecOptVTable();
  return ret;
}
struct SmtProofEntryVecOptVTable *GetSmtProofEntryVecOptVTable(void) {
  static SmtProofEntryVecOptVTable s_vtable;
  static int inited = 0;
  if (inited) return &s_vtable;
  s_vtable.is_none = SmtProofEntryVecOpt_is_none_impl;
  s_vtable.is_some = SmtProofEntryVecOpt_is_some_impl;
  s_vtable.unwrap = SmtProofEntryVecOpt_unwrap_impl;
  return &s_vtable;
}
bool SmtProofEntryVecOpt_is_none_impl(SmtProofEntryVecOptType *this) {
  return mol2_option_is_none(&this->cur);
}
bool SmtProofEntryVecOpt_is_some_impl(SmtProofEntryVecOptType *this) {
  return !mol2_option_is_none(&this->cur);
}
SmtProofEntryVecType SmtProofEntryVecOpt_unwrap_impl(
    SmtProofEntryVecOptType *this) {
  SmtProofEntryVecType ret;
  mol2_cursor_t cur = this->cur;
  ret.cur = cur;
  ret.t = GetSmtProofEntryVecVTable();
  return ret;
}
struct RcLockWitnessLockType make_RcLockWitnessLock(mol2_cursor_t *cur) {
  RcLockWitnessLockType ret;
  ret.cur = *cur;
  ret.t = GetRcLockWitnessLockVTable();
  return ret;
}
struct RcLockWitnessLockVTable *GetRcLockWitnessLockVTable(void) {
  static RcLockWitnessLockVTable s_vtable;
  static int inited = 0;
  if (inited) return &s_vtable;
  s_vtable.signature = RcLockWitnessLock_get_signature_impl;
  s_vtable.proofs = RcLockWitnessLock_get_proofs_impl;
  return &s_vtable;
}
BytesOptType RcLockWitnessLock_get_signature_impl(RcLockWitnessLockType *this) {
  BytesOptType ret;
  mol2_cursor_t cur = mol2_table_slice_by_index(&this->cur, 0);
  ret.cur = cur;
  ret.t = GetBytesOptVTable();
  return ret;
}
SmtProofEntryVecOptType RcLockWitnessLock_get_proofs_impl(
    RcLockWitnessLockType *this) {
  SmtProofEntryVecOptType ret;
  mol2_cursor_t cur = mol2_table_slice_by_index(&this->cur, 1);
  ret.cur = cur;
  ret.t = GetSmtProofEntryVecOptVTable();
  return ret;
}
#endif  // MOLECULEC_C2_DECLARATION_ONLY

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif  // _RC_LOCK_MOL2_API2_H_
