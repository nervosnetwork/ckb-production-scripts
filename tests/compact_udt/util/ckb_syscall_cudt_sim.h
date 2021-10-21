#ifndef _C_CKB_SYSCALL_SIM_H_
#define _C_CKB_SYSCALL_SIM_H_

#include <stddef.h>
#include <stdint.h>

int start_cudt();

/// <summary>
///
/// </summary>
/// <param name="identity">must be 16 byte</param>
/// <param name="nonce"></param>
/// <param name="out_value">must be 32 byte</param>
void gen_smt_value(const uint8_t* identity,
                   uint32_t nonce,
                   uint32_t* out_value);

enum SIM_TYPE_SCRIPT_TYPE {
  SIM_TYPE_SCRIPT_SUDT = 1,
  SIM_TYPE_SCRIPT_XUDT,
};

void sim_set_data(int type, uint64_t amount, const uint8_t* smt_hash);

/// <summary>
///
/// </summary>
/// <param name="ver"></param>
/// <param name="type_id">must be 32 byte</param>
/// <param name="identy">must be 21</param>
void sim_set_args(uint8_t ver, const uint8_t* type_id, const uint8_t* identy);
void sim_set_witness();

int ckb_load_script_hash(void* addr, uint64_t* len, size_t offset);
int ckb_load_cell_data(void* addr,
                       uint64_t* len,
                       size_t offset,
                       size_t index,
                       size_t source);
int ckb_load_script(void* addr, uint64_t* len, size_t offset);
int ckb_checked_load_script(void* addr, uint64_t* len, size_t offset);
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

#endif  // _C_CKB_SYSCALL_SIM_H_
