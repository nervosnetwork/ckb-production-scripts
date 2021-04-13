
#ifndef CKB_C_STDLIB_CKB_SYSCALLS_H_
#define CKB_C_STDLIB_CKB_SYSCALLS_H_

#include <stdio.h>

static FILE* g_file = NULL;

int dlopen_init_riscv_binary(const char* path) {
  g_file = fopen(path, "rb");
  ASSERT(g_file);
  if (g_file == NULL) return -1;
  return 0;
}

int ckb_load_cell_data(void* addr, uint64_t* len, size_t offset, size_t index,
                       size_t source) {
  int err = fseek(g_file, offset, SEEK_SET);
  if (err != 0) return err;
  size_t read_bytes = fread(addr, 1, *len, g_file);
  *len = read_bytes;
  if (read_bytes == 0) {
    err = ferror(g_file);
    if (err != 0) return err;
  }
  return 0;
}

/*
int _ckb_load_cell_code(void *addr, size_t memory_size, size_t content_offset,
                        size_t content_size, size_t index, size_t source)
note:content_size is not available in ckb_load_cell_data
 */
static long __internal_syscall(long n, long _a0, long _a1, long _a2, long _a3,
                               long _a4, long _a5) {
  ASSERT(n == SYS_ckb_load_cell_data_as_code);
  void* addr = (void*)_a0;
  uint64_t memory_size = (uint64_t)_a1;
  size_t content_offset = (size_t)_a2;
  size_t content_size = (size_t)_a3;
  size_t index = (size_t)_a4;
  size_t source = (size_t)_a5;

  uint64_t to_read_size =
      ((memory_size < content_size) ? memory_size : content_size);
  return ckb_load_cell_data(addr, &to_read_size, content_offset, index, source);
}

#define syscall(n, a, b, c, d, e, f)                                           \
  __internal_syscall(n, (long)(a), (long)(b), (long)(c), (long)(d), (long)(e), \
                     (long)(f))

int ckb_look_for_dep_with_hash2(const uint8_t* code_hash, uint8_t hash_type,
                                size_t* index) {
  *index = 0;
  return 0;
}
#endif
