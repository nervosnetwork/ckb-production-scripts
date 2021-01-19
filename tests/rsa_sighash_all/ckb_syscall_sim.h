// note, this macro must be same as in ckb_syscall.h
#ifndef CKB_C_STDLIB_CKB_SYSCALLS_H_
#define CKB_C_STDLIB_CKB_SYSCALLS_H_
#include <assert.h>
#include <blockchain.h>
#include <stddef.h>
#include <stdint.h>

static inline long __internal_syscall(long n, long _a0, long _a1, long _a2,
                                      long _a3, long _a4, long _a5) {
  return 0;
}

#define syscall(n, a, b, c, d, e, f)                                           \
  __internal_syscall(n, (long)(a), (long)(b), (long)(c), (long)(d), (long)(e), \
                     (long)(f))

int ckb_exit(int8_t code);

int ckb_load_tx_hash(void* addr, uint64_t* len, size_t offset) {
  assert(offset == 0);
  uint8_t* p = (uint8_t*)addr;
  for (int i = 0; i < 32; i++) {
    p[i] = 0;
  }
  *len = 32;
  return 0;
}

int ckb_load_script_hash(void* addr, uint64_t* len, size_t offset);

int ckb_load_cell(void* addr, uint64_t* len, size_t offset, size_t index,
                  size_t source);

int ckb_load_input(void* addr, uint64_t* len, size_t offset, size_t index,
                   size_t source);

int ckb_load_header(void* addr, uint64_t* len, size_t offset, size_t index,
                    size_t source);

int ckb_load_witness(void* addr, uint64_t* len, size_t offset, size_t index,
                     size_t source) {
  mol_builder_t b;
  mol_seg_res_t res;
  RsaInfo info;
  info.algorithm_id = CKB_VERIFY_RSA;
  info.key_size = CKB_KEYSIZE_1024;
  uint8_t* ptr = (uint8_t*)&info;

  if (index > 1) {
    return 1;  // CKB_INDEX_OUT_OF_BOUND;
  }

  MolBuilder_Bytes_init(&b);
  for (int i = 0; i < sizeof(info); i++) {
    MolBuilder_Bytes_push(&b, ptr[i]);
  }

  res = MolBuilder_Bytes_build(b);
  assert(res.errno == 0);
  assert(MolReader_Bytes_verify(&res.seg, false) == 0);
  assert(*len > res.seg.size);

  mol_builder_t w;
  MolBuilder_WitnessArgs_init(&w);
  MolBuilder_WitnessArgs_set_lock(&w, res.seg.ptr, res.seg.size);
  mol_seg_res_t res2 = MolBuilder_WitnessArgs_build(w);
  assert(res2.errno == 0);

  memcpy(addr, res2.seg.ptr, res2.seg.size);
  *len = res2.seg.size;
  return 0;
}

mol_seg_t build_args_bytes() {
  // public key, size: 4+128 = 132 bytes
  const int PUBLIC_KEY_SIZE = 132;
  uint8_t public_key[132] = {1, 0, 1, 0, 0x56, 0x78};

  mol_builder_t b;
  mol_seg_res_t res;
  MolBuilder_Bytes_init(&b);
  for (int i = 0; i < PUBLIC_KEY_SIZE; i++) {
    MolBuilder_Bytes_push(&b, public_key[i]);
  }
  res = MolBuilder_Bytes_build(b);
  return res.seg;
}

int ckb_load_script(void* addr, uint64_t* len, size_t offset) {
  mol_builder_t b;
  mol_seg_res_t res;

  assert(offset == 0);

  MolBuilder_Script_init(&b);
  uint8_t code_hash[32] = {0};
  uint8_t hash_type = 0;

  MolBuilder_Script_set_code_hash(&b, code_hash, 32);
  MolBuilder_Script_set_hash_type(&b, hash_type);
  mol_seg_t bytes = build_args_bytes();
  MolBuilder_Script_set_args(&b, bytes.ptr, bytes.size);

  res = MolBuilder_Script_build(b);
  assert(res.errno == 0);

  if (*len < res.seg.size) {
    return -1;
  }
  memcpy(addr, res.seg.ptr, res.seg.size);
  *len = res.seg.size;
  return 0;
}

int ckb_load_cell_by_field(void* addr, uint64_t* len, size_t offset,
                           size_t index, size_t source, size_t field);

int ckb_load_header_by_field(void* addr, uint64_t* len, size_t offset,
                             size_t index, size_t source, size_t field);

int ckb_load_input_by_field(void* addr, uint64_t* len, size_t offset,
                            size_t index, size_t source, size_t field);

int ckb_load_cell_code(void* addr, size_t memory_size, size_t content_offset,
                       size_t content_size, size_t index, size_t source);

int ckb_load_cell_data(void* addr, uint64_t* len, size_t offset, size_t index,
                       size_t source);

int ckb_debug(const char* s);

/* load the actual witness for the current type verify group.
   use this instead of ckb_load_witness if type contract needs args to verify
   input/output.
 */
int load_actual_type_witness(uint8_t* buf, uint64_t* len, size_t index,
                             size_t* type_source);

int ckb_look_for_dep_with_hash(const uint8_t* data_hash, size_t* index);

int ckb_calculate_inputs_len() { return 0; }

#endif
