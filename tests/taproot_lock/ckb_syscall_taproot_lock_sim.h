// note, this macro must be same as in ckb_syscall.h
#ifndef CKB_C_STDLIB_CKB_SYSCALLS_H_
#define CKB_C_STDLIB_CKB_SYSCALLS_H_

#define CKB_C_STDLIB_CKB_DLFCN_H_
#include "ckb_syscall_apis.h"
int ckb_calculate_inputs_len();
int ckb_checked_load_cell_by_field(void* addr, uint64_t* len, size_t offset,
                                   size_t index, size_t source, size_t field);
int ckb_checked_load_script(void* addr, uint64_t* len, size_t offset);

#endif
