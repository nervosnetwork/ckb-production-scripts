
#ifndef _BLOCKCHAIN_MOL2_API2_H_
#define _BLOCKCHAIN_MOL2_API2_H_

#define MOLECULEC2_VERSION 6001
#define MOLECULE2_API_VERSION_MIN 5000

#include "molecule2_reader.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

// ----forward declaration--------
struct Byte64Type;
struct Byte64VTable;
struct Byte64VTable *GetByte64VTable(void);
struct Byte64Type make_Byte64(mol2_cursor_t *cur);
uint32_t Byte64_len_impl(struct Byte64Type *);
uint8_t Byte64_get_impl(struct Byte64Type *, uint32_t, bool *);
struct CardanoWitnessLockType;
struct CardanoWitnessLockVTable;
struct CardanoWitnessLockVTable *GetCardanoWitnessLockVTable(void);
struct CardanoWitnessLockType make_CardanoWitnessLock(mol2_cursor_t *cur);
mol2_cursor_t CardanoWitnessLock_get_pubkey_impl(
    struct CardanoWitnessLockType *);
mol2_cursor_t CardanoWitnessLock_get_signature_impl(
    struct CardanoWitnessLockType *);
mol2_cursor_t CardanoWitnessLock_get_sig_structure_impl(
    struct CardanoWitnessLockType *);

// ----definition-----------------
typedef struct Byte64VTable {
  uint32_t (*len)(struct Byte64Type *);
  uint8_t (*get)(struct Byte64Type *, uint32_t, bool *);
} Byte64VTable;
typedef struct Byte64Type {
  mol2_cursor_t cur;
  Byte64VTable *t;
} Byte64Type;

typedef struct CardanoWitnessLockVTable {
  mol2_cursor_t (*pubkey)(struct CardanoWitnessLockType *);
  mol2_cursor_t (*signature)(struct CardanoWitnessLockType *);
  mol2_cursor_t (*sig_structure)(struct CardanoWitnessLockType *);
} CardanoWitnessLockVTable;
typedef struct CardanoWitnessLockType {
  mol2_cursor_t cur;
  CardanoWitnessLockVTable *t;
} CardanoWitnessLockType;

#ifndef MOLECULEC_C2_DECLARATION_ONLY

// ----implementation-------------
struct Byte64Type make_Byte64(mol2_cursor_t *cur) {
  Byte64Type ret;
  ret.cur = *cur;
  ret.t = GetByte64VTable();
  return ret;
}
struct Byte64VTable *GetByte64VTable(void) {
  static Byte64VTable s_vtable;
  static int inited = 0;
  if (inited) return &s_vtable;
  s_vtable.len = Byte64_len_impl;
  s_vtable.get = Byte64_get_impl;
  return &s_vtable;
}
uint32_t Byte64_len_impl(Byte64Type *this) { return 64; }
uint8_t Byte64_get_impl(Byte64Type *this, uint32_t index, bool *existing) {
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
struct CardanoWitnessLockType make_CardanoWitnessLock(mol2_cursor_t *cur) {
  CardanoWitnessLockType ret;
  ret.cur = *cur;
  ret.t = GetCardanoWitnessLockVTable();
  return ret;
}
struct CardanoWitnessLockVTable *GetCardanoWitnessLockVTable(void) {
  static CardanoWitnessLockVTable s_vtable;
  static int inited = 0;
  if (inited) return &s_vtable;
  s_vtable.pubkey = CardanoWitnessLock_get_pubkey_impl;
  s_vtable.signature = CardanoWitnessLock_get_signature_impl;
  s_vtable.sig_structure = CardanoWitnessLock_get_sig_structure_impl;
  return &s_vtable;
}
mol2_cursor_t CardanoWitnessLock_get_pubkey_impl(CardanoWitnessLockType *this) {
  mol2_cursor_t ret;
  mol2_cursor_t ret2 = mol2_table_slice_by_index(&this->cur, 0);
  ret = convert_to_array(&ret2);
  return ret;
}
mol2_cursor_t CardanoWitnessLock_get_signature_impl(
    CardanoWitnessLockType *this) {
  mol2_cursor_t ret;
  mol2_cursor_t ret2 = mol2_table_slice_by_index(&this->cur, 1);
  ret = convert_to_array(&ret2);
  return ret;
}
mol2_cursor_t CardanoWitnessLock_get_sig_structure_impl(
    CardanoWitnessLockType *this) {
  mol2_cursor_t ret;
  mol2_cursor_t re2 = mol2_table_slice_by_index(&this->cur, 2);
  ret = convert_to_rawbytes(&re2);
  return ret;
}
#endif  // MOLECULEC_C2_DECLARATION_ONLY

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif  // _BLOCKCHAIN_MOL2_API2_H_
