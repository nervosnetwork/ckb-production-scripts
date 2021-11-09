#ifndef _C_CKB_SYSCALL_SIM_H_
#define _C_CKB_SYSCALL_SIM_H_

#include <stddef.h>
#include <stdint.h>

#include <ckb_consts.h>

int ckb_load_tx_hash(void* addr, uint64_t* len, size_t offset);
int ckb_load_script_hash(void* addr, uint64_t* len, size_t offset);
int ckb_load_cell_data(void* addr,
                       uint64_t* len,
                       size_t offset,
                       size_t index,
                       size_t source);
int ckb_load_script(void* addr, uint64_t* len, size_t offset);
int ckb_checked_load_script(void* addr, uint64_t* len, size_t offset);
int ckb_calculate_inputs_len();
int ckb_load_witness(void* addr,
                     uint64_t* len,
                     size_t offset,
                     size_t index,
                     size_t source);
int ckb_checked_load_witness(void* addr,
                             uint64_t* len,
                             size_t offset,
                             size_t index,
                             size_t source);
int ckb_exit(int8_t code);

int ckb_load_cell_by_field(void* addr,
                           uint64_t* len,
                           size_t offset,
                           size_t index,
                           size_t source,
                           size_t field);
int ckb_checked_load_cell_by_field(void* addr, uint64_t* len, size_t offset,
                                   size_t index, size_t source, size_t field);

#endif  // _C_CKB_SYSCALL_SIM_H_
