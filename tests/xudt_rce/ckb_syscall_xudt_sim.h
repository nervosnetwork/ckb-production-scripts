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
  char info[256] = {0};
  char* ptr = info;

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

int ckb_load_cell_by_field(void* addr, uint64_t* len, size_t offset,
                           size_t index, size_t source, size_t field) {
  if (source == CKB_SOURCE_CELL_DEP) {
  } else if (source == CKB_SOURCE_INPUT) {
  } else {
  }
  return 0;
}

int ckb_checked_load_cell_by_field(void* addr, uint64_t* len, size_t offset,
                                   size_t index, size_t source, size_t field) {
  uint64_t old_len = *len;
  int ret = ckb_load_cell_by_field(addr, len, offset, index, source, field);
  if (ret == 0 && (*len) > old_len) {
    ret = CKB_LENGTH_NOT_ENOUGH;
  }
  return ret;
}

// dlopen simulator
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>

#define ERROR_MEMORY_NOT_ENOUGH -23
#define ERROR_DYNAMIC_LOADING -24
#define RISCV_PGSIZE 4096
#define ROUNDUP(a, b) ((((a)-1) / (b) + 1) * (b))
#define MAX_PATH_SIZE 1024

typedef struct LibMappingEntry {
  uint8_t dep_cell_hash[32];
  char path[MAX_PATH_SIZE];
} LibMappingEntry;

#define MAX_LIB_MAPPING_COUNT 64
LibMappingEntry g_lib_mapping[MAX_LIB_MAPPING_COUNT];
int g_lib_size = 0;

void ckbsim_map_lib(const uint8_t* dep_cell_hash, const char* path) {
  if (g_lib_size >= MAX_LIB_MAPPING_COUNT) {
    ASSERT(false);
    return;
  }
  ASSERT(strlen(path) < MAX_PATH_SIZE);

  memcpy(g_lib_mapping[g_lib_size].dep_cell_hash, dep_cell_hash, 32);
  strcpy(g_lib_mapping[g_lib_size].path, path);

  g_lib_size++;
}

int ckbsim_get_lib(const uint8_t* dep_cell_hash, char* path) {
  for (int i = 0; i < g_lib_size; i++) {
    if (memcmp(g_lib_mapping[i].dep_cell_hash, dep_cell_hash, 32) == 0) {
      strcpy(path, g_lib_mapping[i].path);
      return 0;
    }
  }
  return 1;
}

size_t get_file_size(const char* path) {
  FILE* fp = fopen(path, "r");
  ASSERT(fp != NULL);
  fseek(fp, 0L, SEEK_END);
  long size = ftell(fp);
  fclose(fp);

  return size;
}

int ckb_dlopen2(const uint8_t* dep_cell_hash, uint8_t hash_type,
                uint8_t* aligned_addr, size_t aligned_size, void** handle,
                size_t* consumed_size) {
  int err = 0;
  (void)hash_type;
  (void)aligned_size;

  char path[MAX_PATH_SIZE] = {0};
  ASSERT((aligned_size % RISCV_PGSIZE) == 0);
  ASSERT(((size_t)aligned_addr) % RISCV_PGSIZE == 0);

  err = ckbsim_get_lib(dep_cell_hash, path);
  ASSERT(err == 0);

  *handle = dlopen(path, RTLD_NOW);
  *consumed_size = ROUNDUP(get_file_size(path), RISCV_PGSIZE);

  if (*consumed_size >= aligned_size) {
    ASSERT(false);
    return -1;
  }
  if (*handle == NULL) {
    printf("Error occurs in dlopen: %s\n", dlerror());
    ASSERT(false);
    return -1;
  }
  return 0;
}

void* ckb_dlsym(void* handle, const char* symbol) {
  void* ret = dlsym(handle, symbol);
  ASSERT(ret != NULL);
  return ret;
}

#endif
