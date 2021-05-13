
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
struct RcLockWitnessLockType;
struct RcLockWitnessLockVTable;
struct RcLockWitnessLockVTable *GetRcLockWitnessLockVTable(void);
struct RcLockWitnessLockType make_RcLockWitnessLock(mol2_cursor_t *cur);
mol2_cursor_t RcLockWitnessLock_get_signature_impl(
    struct RcLockWitnessLockType *);
mol2_cursor_t RcLockWitnessLock_get_lock_script_hash_impl(
    struct RcLockWitnessLockType *);
struct SmtProofEntryVecType RcLockWitnessLock_get_proofs_impl(
    struct RcLockWitnessLockType *);

// ----definition-----------------
typedef struct RcLockWitnessLockVTable {
  mol2_cursor_t (*signature)(struct RcLockWitnessLockType *);
  mol2_cursor_t (*lock_script_hash)(struct RcLockWitnessLockType *);
  struct SmtProofEntryVecType (*proofs)(struct RcLockWitnessLockType *);
} RcLockWitnessLockVTable;
typedef struct RcLockWitnessLockType {
  mol2_cursor_t cur;
  RcLockWitnessLockVTable *t;
} RcLockWitnessLockType;

#ifndef MOLECULEC_C2_DECLARATION_ONLY

// ----implementation-------------
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
  s_vtable.lock_script_hash = RcLockWitnessLock_get_lock_script_hash_impl;
  s_vtable.proofs = RcLockWitnessLock_get_proofs_impl;
  return &s_vtable;
}
mol2_cursor_t RcLockWitnessLock_get_signature_impl(
    RcLockWitnessLockType *this) {
  mol2_cursor_t ret;
  mol2_cursor_t re2 = mol2_table_slice_by_index(&this->cur, 0);
  ret = convert_to_rawbytes(&re2);
  return ret;
}
mol2_cursor_t RcLockWitnessLock_get_lock_script_hash_impl(
    RcLockWitnessLockType *this) {
  mol2_cursor_t ret;
  mol2_cursor_t re2 = mol2_table_slice_by_index(&this->cur, 1);
  ret = convert_to_rawbytes(&re2);
  return ret;
}
SmtProofEntryVecType RcLockWitnessLock_get_proofs_impl(
    RcLockWitnessLockType *this) {
  SmtProofEntryVecType ret;
  mol2_cursor_t cur = mol2_table_slice_by_index(&this->cur, 2);
  ret.cur = cur;
  ret.t = GetSmtProofEntryVecVTable();
  return ret;
}
#endif  // MOLECULEC_C2_DECLARATION_ONLY

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif  // _RC_LOCK_MOL2_API2_H_
