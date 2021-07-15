#ifndef CKB_C_STDLIB_MOCK_SYSCALLS_H_
#define CKB_C_STDLIB_MOCK_SYSCALLS_H_

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "ckb_consts.h"
#include "ckb_syscall_apis.h"

#ifndef MIN
#define MIN(a, b) ((a > b) ? (b) : (a))
#endif

size_t s_INPUT_SIZE = 0;
uint8_t* s_INPUT_DATA = NULL;

// Mock implementation of ckb_look_for_dep_with_hash2.
int ckb_look_for_dep_with_hash2(const uint8_t* code_hash, uint8_t hash_type,
                                size_t* index) {
  *index = 0;
  return CKB_SUCCESS;
}

// Mock implementation of ckb_load_cell_data.
int ckb_load_cell_data(void* addr, uint64_t* len, size_t offset, size_t index,
                       size_t source) {
  if (offset < s_INPUT_SIZE) {
    *len = MIN(*len, s_INPUT_SIZE - offset);
    if (offset <= offset + *len) {
      memcpy(addr, s_INPUT_DATA + offset, *len);
      return CKB_SUCCESS;
    }
  }
  return CKB_INVALID_DATA;
}

// Mock implementation of ckb_load_cell_data_as_code.
int ckb_load_cell_data_as_code(void* addr, size_t memory_size,
                               size_t content_offset, size_t content_size,
                               size_t index, size_t source) {
  if ((content_size <= memory_size) &&
      (content_offset + content_size < s_INPUT_SIZE) &&
      (content_offset <= content_offset + content_size)) {
    memcpy(addr, s_INPUT_DATA + content_offset, content_size);
    return CKB_SUCCESS;
  }
  return CKB_INVALID_DATA;
}

// Mock implementation for the SYS_ckb_load_cell_data_as_code syscall in
// _ckb_load_cell_code.
#define syscall(n, a0, a1, a2, a3, a4, a5)                              \
  __internal_syscall(n, (long)(a0), (long)(a1), (long)(a2), (long)(a3), \
                     (long)(a4), (long)(a5))

static int inline __internal_syscall(long n, long _a0, long _a1, long _a2,
                                     long _a3, long _a4, long _a5) {
  if (n == SYS_ckb_load_cell_data_as_code) {
    return ckb_load_cell_data_as_code((void*)_a0, (size_t)_a1, (size_t)_a2,
                                      (size_t)_a3, (size_t)_a4, (size_t)_a5);
  } else {
    return CKB_INVALID_DATA;
  }
}

#undef MIN

#endif /* CKB_C_STDLIB_MOCK_SYSCALLS_H_ */
