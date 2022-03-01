
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
struct AuthType;
struct AuthVTable;
struct AuthVTable *GetAuthVTable(void);
struct AuthType make_Auth(mol2_cursor_t *cur);
uint32_t Auth_len_impl(struct AuthType *);
uint8_t Auth_get_impl(struct AuthType *, uint32_t, bool *);
struct IdentityType;
struct IdentityVTable;
struct IdentityVTable *GetIdentityVTable(void);
struct IdentityType make_Identity(mol2_cursor_t *cur);
mol2_cursor_t Identity_get_identity_impl(struct IdentityType *);
struct SmtProofEntryVecType Identity_get_proofs_impl(struct IdentityType *);
struct IdentityOptType;
struct IdentityOptVTable;
struct IdentityOptVTable *GetIdentityOptVTable(void);
struct IdentityOptType make_IdentityOpt(mol2_cursor_t *cur);
bool IdentityOpt_is_none_impl(struct IdentityOptType *);
bool IdentityOpt_is_some_impl(struct IdentityOptType *);
struct IdentityType IdentityOpt_unwrap_impl(struct IdentityOptType *);
struct OmniLockWitnessLockType;
struct OmniLockWitnessLockVTable;
struct OmniLockWitnessLockVTable *GetOmniLockWitnessLockVTable(void);
struct OmniLockWitnessLockType make_OmniLockWitnessLock(mol2_cursor_t *cur);
struct BytesOptType OmniLockWitnessLock_get_signature_impl(
    struct OmniLockWitnessLockType *);
struct IdentityOptType OmniLockWitnessLock_get_omni_identity_impl(
    struct OmniLockWitnessLockType *);
struct BytesOptType OmniLockWitnessLock_get_preimage_impl(
    struct OmniLockWitnessLockType *);

// ----definition-----------------
typedef struct AuthVTable {
  uint32_t (*len)(struct AuthType *);
  uint8_t (*get)(struct AuthType *, uint32_t, bool *);
} AuthVTable;
typedef struct AuthType {
  mol2_cursor_t cur;
  AuthVTable *t;
} AuthType;

typedef struct IdentityVTable {
  mol2_cursor_t (*identity)(struct IdentityType *);
  struct SmtProofEntryVecType (*proofs)(struct IdentityType *);
} IdentityVTable;
typedef struct IdentityType {
  mol2_cursor_t cur;
  IdentityVTable *t;
} IdentityType;

typedef struct IdentityOptVTable {
  bool (*is_none)(struct IdentityOptType *);
  bool (*is_some)(struct IdentityOptType *);
  struct IdentityType (*unwrap)(struct IdentityOptType *);
} IdentityOptVTable;
typedef struct IdentityOptType {
  mol2_cursor_t cur;
  IdentityOptVTable *t;
} IdentityOptType;

typedef struct OmniLockWitnessLockVTable {
  struct BytesOptType (*signature)(struct OmniLockWitnessLockType *);
  struct IdentityOptType (*omni_identity)(struct OmniLockWitnessLockType *);
  struct BytesOptType (*preimage)(struct OmniLockWitnessLockType *);
} OmniLockWitnessLockVTable;
typedef struct OmniLockWitnessLockType {
  mol2_cursor_t cur;
  OmniLockWitnessLockVTable *t;
} OmniLockWitnessLockType;

#ifndef MOLECULEC_C2_DECLARATION_ONLY

// ----implementation-------------
struct AuthType make_Auth(mol2_cursor_t *cur) {
  AuthType ret;
  ret.cur = *cur;
  ret.t = GetAuthVTable();
  return ret;
}
struct AuthVTable *GetAuthVTable(void) {
  static AuthVTable s_vtable;
  static int inited = 0;
  if (inited) return &s_vtable;
  s_vtable.len = Auth_len_impl;
  s_vtable.get = Auth_get_impl;
  return &s_vtable;
}
uint32_t Auth_len_impl(AuthType *this) { return 21; }
uint8_t Auth_get_impl(AuthType *this, uint32_t index, bool *existing) {
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
  s_vtable.identity = Identity_get_identity_impl;
  s_vtable.proofs = Identity_get_proofs_impl;
  return &s_vtable;
}
mol2_cursor_t Identity_get_identity_impl(IdentityType *this) {
  mol2_cursor_t ret;
  mol2_cursor_t ret2 = mol2_table_slice_by_index(&this->cur, 0);
  ret = convert_to_array(&ret2);
  return ret;
}
SmtProofEntryVecType Identity_get_proofs_impl(IdentityType *this) {
  SmtProofEntryVecType ret;
  mol2_cursor_t cur = mol2_table_slice_by_index(&this->cur, 1);
  ret.cur = cur;
  ret.t = GetSmtProofEntryVecVTable();
  return ret;
}
struct IdentityOptType make_IdentityOpt(mol2_cursor_t *cur) {
  IdentityOptType ret;
  ret.cur = *cur;
  ret.t = GetIdentityOptVTable();
  return ret;
}
struct IdentityOptVTable *GetIdentityOptVTable(void) {
  static IdentityOptVTable s_vtable;
  static int inited = 0;
  if (inited) return &s_vtable;
  s_vtable.is_none = IdentityOpt_is_none_impl;
  s_vtable.is_some = IdentityOpt_is_some_impl;
  s_vtable.unwrap = IdentityOpt_unwrap_impl;
  return &s_vtable;
}
bool IdentityOpt_is_none_impl(IdentityOptType *this) {
  return mol2_option_is_none(&this->cur);
}
bool IdentityOpt_is_some_impl(IdentityOptType *this) {
  return !mol2_option_is_none(&this->cur);
}
IdentityType IdentityOpt_unwrap_impl(IdentityOptType *this) {
  IdentityType ret;
  mol2_cursor_t cur = this->cur;
  ret.cur = cur;
  ret.t = GetIdentityVTable();
  return ret;
}
struct OmniLockWitnessLockType make_OmniLockWitnessLock(mol2_cursor_t *cur) {
  OmniLockWitnessLockType ret;
  ret.cur = *cur;
  ret.t = GetOmniLockWitnessLockVTable();
  return ret;
}
struct OmniLockWitnessLockVTable *GetOmniLockWitnessLockVTable(void) {
  static OmniLockWitnessLockVTable s_vtable;
  static int inited = 0;
  if (inited) return &s_vtable;
  s_vtable.signature = OmniLockWitnessLock_get_signature_impl;
  s_vtable.omni_identity = OmniLockWitnessLock_get_omni_identity_impl;
  s_vtable.preimage = OmniLockWitnessLock_get_preimage_impl;
  return &s_vtable;
}
BytesOptType OmniLockWitnessLock_get_signature_impl(
    OmniLockWitnessLockType *this) {
  BytesOptType ret;
  mol2_cursor_t cur = mol2_table_slice_by_index(&this->cur, 0);
  ret.cur = cur;
  ret.t = GetBytesOptVTable();
  return ret;
}
IdentityOptType OmniLockWitnessLock_get_omni_identity_impl(
    OmniLockWitnessLockType *this) {
  IdentityOptType ret;
  mol2_cursor_t cur = mol2_table_slice_by_index(&this->cur, 1);
  ret.cur = cur;
  ret.t = GetIdentityOptVTable();
  return ret;
}
BytesOptType OmniLockWitnessLock_get_preimage_impl(
    OmniLockWitnessLockType *this) {
  BytesOptType ret;
  mol2_cursor_t cur = mol2_table_slice_by_index(&this->cur, 2);
  ret.cur = cur;
  ret.t = GetBytesOptVTable();
  return ret;
}
#endif  // MOLECULEC_C2_DECLARATION_ONLY

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif  // _RC_LOCK_MOL2_API2_H_
