
#ifndef _TAPROOT_LOCK_MOL2_API2_H_
#define _TAPROOT_LOCK_MOL2_API2_H_

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
struct TaprootScriptPathType;
struct TaprootScriptPathVTable;
struct TaprootScriptPathVTable *GetTaprootScriptPathVTable(void);
struct TaprootScriptPathType make_TaprootScriptPath(mol2_cursor_t *cur);
mol2_cursor_t TaprootScriptPath_get_taproot_output_key_impl(
    struct TaprootScriptPathType *);
mol2_cursor_t TaprootScriptPath_get_taproot_internal_key_impl(
    struct TaprootScriptPathType *);
mol2_cursor_t TaprootScriptPath_get_smt_root_impl(
    struct TaprootScriptPathType *);
mol2_cursor_t TaprootScriptPath_get_smt_proof_impl(
    struct TaprootScriptPathType *);
uint8_t TaprootScriptPath_get_y_parity_impl(struct TaprootScriptPathType *);
struct ScriptType TaprootScriptPath_get_exec_script_impl(
    struct TaprootScriptPathType *);
mol2_cursor_t TaprootScriptPath_get_args2_impl(struct TaprootScriptPathType *);
struct TaprootScriptPathOptType;
struct TaprootScriptPathOptVTable;
struct TaprootScriptPathOptVTable *GetTaprootScriptPathOptVTable(void);
struct TaprootScriptPathOptType make_TaprootScriptPathOpt(mol2_cursor_t *cur);
bool TaprootScriptPathOpt_is_none_impl(struct TaprootScriptPathOptType *);
bool TaprootScriptPathOpt_is_some_impl(struct TaprootScriptPathOptType *);
struct TaprootScriptPathType TaprootScriptPathOpt_unwrap_impl(
    struct TaprootScriptPathOptType *);
struct TaprootLockWitnessLockType;
struct TaprootLockWitnessLockVTable;
struct TaprootLockWitnessLockVTable *GetTaprootLockWitnessLockVTable(void);
struct TaprootLockWitnessLockType make_TaprootLockWitnessLock(
    mol2_cursor_t *cur);
struct BytesOptType TaprootLockWitnessLock_get_signature_impl(
    struct TaprootLockWitnessLockType *);
struct TaprootScriptPathOptType TaprootLockWitnessLock_get_script_path_impl(
    struct TaprootLockWitnessLockType *);

// ----definition-----------------
typedef struct TaprootScriptPathVTable {
  mol2_cursor_t (*taproot_output_key)(struct TaprootScriptPathType *);
  mol2_cursor_t (*taproot_internal_key)(struct TaprootScriptPathType *);
  mol2_cursor_t (*smt_root)(struct TaprootScriptPathType *);
  mol2_cursor_t (*smt_proof)(struct TaprootScriptPathType *);
  uint8_t (*y_parity)(struct TaprootScriptPathType *);
  struct ScriptType (*exec_script)(struct TaprootScriptPathType *);
  mol2_cursor_t (*args2)(struct TaprootScriptPathType *);
} TaprootScriptPathVTable;
typedef struct TaprootScriptPathType {
  mol2_cursor_t cur;
  TaprootScriptPathVTable *t;
} TaprootScriptPathType;

typedef struct TaprootScriptPathOptVTable {
  bool (*is_none)(struct TaprootScriptPathOptType *);
  bool (*is_some)(struct TaprootScriptPathOptType *);
  struct TaprootScriptPathType (*unwrap)(struct TaprootScriptPathOptType *);
} TaprootScriptPathOptVTable;
typedef struct TaprootScriptPathOptType {
  mol2_cursor_t cur;
  TaprootScriptPathOptVTable *t;
} TaprootScriptPathOptType;

typedef struct TaprootLockWitnessLockVTable {
  struct BytesOptType (*signature)(struct TaprootLockWitnessLockType *);
  struct TaprootScriptPathOptType (*script_path)(
      struct TaprootLockWitnessLockType *);
} TaprootLockWitnessLockVTable;
typedef struct TaprootLockWitnessLockType {
  mol2_cursor_t cur;
  TaprootLockWitnessLockVTable *t;
} TaprootLockWitnessLockType;

#ifndef MOLECULEC_C2_DECLARATION_ONLY

// ----implementation-------------
struct TaprootScriptPathType make_TaprootScriptPath(mol2_cursor_t *cur) {
  TaprootScriptPathType ret;
  ret.cur = *cur;
  ret.t = GetTaprootScriptPathVTable();
  return ret;
}
struct TaprootScriptPathVTable *GetTaprootScriptPathVTable(void) {
  static TaprootScriptPathVTable s_vtable;
  static int inited = 0;
  if (inited) return &s_vtable;
  s_vtable.taproot_output_key = TaprootScriptPath_get_taproot_output_key_impl;
  s_vtable.taproot_internal_key =
      TaprootScriptPath_get_taproot_internal_key_impl;
  s_vtable.smt_root = TaprootScriptPath_get_smt_root_impl;
  s_vtable.smt_proof = TaprootScriptPath_get_smt_proof_impl;
  s_vtable.y_parity = TaprootScriptPath_get_y_parity_impl;
  s_vtable.exec_script = TaprootScriptPath_get_exec_script_impl;
  s_vtable.args2 = TaprootScriptPath_get_args2_impl;
  return &s_vtable;
}
mol2_cursor_t TaprootScriptPath_get_taproot_output_key_impl(
    TaprootScriptPathType *this) {
  mol2_cursor_t ret;
  mol2_cursor_t ret2 = mol2_table_slice_by_index(&this->cur, 0);
  ret = convert_to_array(&ret2);
  return ret;
}
mol2_cursor_t TaprootScriptPath_get_taproot_internal_key_impl(
    TaprootScriptPathType *this) {
  mol2_cursor_t ret;
  mol2_cursor_t ret2 = mol2_table_slice_by_index(&this->cur, 1);
  ret = convert_to_array(&ret2);
  return ret;
}
mol2_cursor_t TaprootScriptPath_get_smt_root_impl(TaprootScriptPathType *this) {
  mol2_cursor_t ret;
  mol2_cursor_t ret2 = mol2_table_slice_by_index(&this->cur, 2);
  ret = convert_to_array(&ret2);
  return ret;
}
mol2_cursor_t TaprootScriptPath_get_smt_proof_impl(
    TaprootScriptPathType *this) {
  mol2_cursor_t ret;
  mol2_cursor_t re2 = mol2_table_slice_by_index(&this->cur, 3);
  ret = convert_to_rawbytes(&re2);
  return ret;
}
uint8_t TaprootScriptPath_get_y_parity_impl(TaprootScriptPathType *this) {
  uint8_t ret;
  mol2_cursor_t ret2 = mol2_table_slice_by_index(&this->cur, 4);
  ret = convert_to_Uint8(&ret2);
  return ret;
}
ScriptType TaprootScriptPath_get_exec_script_impl(TaprootScriptPathType *this) {
  ScriptType ret;
  mol2_cursor_t cur = mol2_table_slice_by_index(&this->cur, 5);
  ret.cur = cur;
  ret.t = GetScriptVTable();
  return ret;
}
mol2_cursor_t TaprootScriptPath_get_args2_impl(TaprootScriptPathType *this) {
  mol2_cursor_t ret;
  mol2_cursor_t re2 = mol2_table_slice_by_index(&this->cur, 6);
  ret = convert_to_rawbytes(&re2);
  return ret;
}
struct TaprootScriptPathOptType make_TaprootScriptPathOpt(mol2_cursor_t *cur) {
  TaprootScriptPathOptType ret;
  ret.cur = *cur;
  ret.t = GetTaprootScriptPathOptVTable();
  return ret;
}
struct TaprootScriptPathOptVTable *GetTaprootScriptPathOptVTable(void) {
  static TaprootScriptPathOptVTable s_vtable;
  static int inited = 0;
  if (inited) return &s_vtable;
  s_vtable.is_none = TaprootScriptPathOpt_is_none_impl;
  s_vtable.is_some = TaprootScriptPathOpt_is_some_impl;
  s_vtable.unwrap = TaprootScriptPathOpt_unwrap_impl;
  return &s_vtable;
}
bool TaprootScriptPathOpt_is_none_impl(TaprootScriptPathOptType *this) {
  return mol2_option_is_none(&this->cur);
}
bool TaprootScriptPathOpt_is_some_impl(TaprootScriptPathOptType *this) {
  return !mol2_option_is_none(&this->cur);
}
TaprootScriptPathType TaprootScriptPathOpt_unwrap_impl(
    TaprootScriptPathOptType *this) {
  TaprootScriptPathType ret;
  mol2_cursor_t cur = this->cur;
  ret.cur = cur;
  ret.t = GetTaprootScriptPathVTable();
  return ret;
}
struct TaprootLockWitnessLockType make_TaprootLockWitnessLock(
    mol2_cursor_t *cur) {
  TaprootLockWitnessLockType ret;
  ret.cur = *cur;
  ret.t = GetTaprootLockWitnessLockVTable();
  return ret;
}
struct TaprootLockWitnessLockVTable *GetTaprootLockWitnessLockVTable(void) {
  static TaprootLockWitnessLockVTable s_vtable;
  static int inited = 0;
  if (inited) return &s_vtable;
  s_vtable.signature = TaprootLockWitnessLock_get_signature_impl;
  s_vtable.script_path = TaprootLockWitnessLock_get_script_path_impl;
  return &s_vtable;
}
BytesOptType TaprootLockWitnessLock_get_signature_impl(
    TaprootLockWitnessLockType *this) {
  BytesOptType ret;
  mol2_cursor_t cur = mol2_table_slice_by_index(&this->cur, 0);
  ret.cur = cur;
  ret.t = GetBytesOptVTable();
  return ret;
}
TaprootScriptPathOptType TaprootLockWitnessLock_get_script_path_impl(
    TaprootLockWitnessLockType *this) {
  TaprootScriptPathOptType ret;
  mol2_cursor_t cur = mol2_table_slice_by_index(&this->cur, 1);
  ret.cur = cur;
  ret.t = GetTaprootScriptPathOptVTable();
  return ret;
}
#endif  // MOLECULEC_C2_DECLARATION_ONLY

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif  // _TAPROOT_LOCK_MOL2_API2_H_
