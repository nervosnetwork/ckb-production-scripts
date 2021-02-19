#ifndef ASSERT
#define ASSERT(s) (void)0
#endif

#include <stdbool.h>
#include <string.h>
#include "ckb_consts.h"
#include "blockchain.h"
#include "blake2b.h"

#if defined(CKB_USE_SIM)
#include "ckb_syscall_xudt_sim.h"
#else
#include "ckb_syscalls.h"
#include "ckb_dlfcn.h"
#endif

#if defined(CKB_USE_SIM)
#include <stdio.h>
#define xudt_printf printf
#else
#define xudt_printf(x, ...) (void)0
#endif

enum ErrorCode {
  // 0 is the only success code. We can use 0 directly.

  // inherit from simple_udt
  ERROR_ARGUMENTS_LEN = -1,
  ERROR_ENCODING = -2,
  ERROR_SYSCALL = -3,
  ERROR_SCRIPT_TOO_LONG = -21,
  ERROR_OVERFLOWING = -51,
  ERROR_AMOUNT = -52,

  // error code is starting from 40, to avoid conflict with
  // common error code in other scripts.
  ERROR_CANT_LOAD_LIB = 40,
  ERROR_NOT_ENOUGH_BUFF,
  ERROR_INVALID_FLAG,
  ERROR_INVALID_ARGS_FORMAT,
  ERROR_INVALID_WITNESS_FORMAT,
  ERROR_INVALID_MOL_FORMAT,
  ERROR_BLAKE2B_ERROR,
  ERROR_HASH_MISMATCHED,
};

#define CHECK2(cond, code) \
  do {                     \
    if (!(cond)) {         \
      err = code;          \
      ASSERT(0);           \
      goto exit;           \
    }                      \
  } while (0)

#define CHECK(code)  \
  do {               \
    if (code != 0) { \
      err = code;    \
      ASSERT(0);     \
      goto exit;     \
    }                \
  } while (0)

#define BLAKE2B_BLOCK_SIZE 32
#define BLAKE160_SIZE 20
#define SCRIPT_SIZE 32768
#define WITNESS_SIZE 32768
#define EXPORTED_FUNC_NAME "validate"
#define MAX_CODE_SIZE (1024*1024)
#define FLAGS_SIZE 4

// global variables, type definitions, etc
uint8_t g_script[SCRIPT_SIZE] = {0};
uint8_t g_witness[WITNESS_SIZE] = {0};

uint8_t g_code_buffer[MAX_CODE_SIZE] __attribute__((aligned(RISCV_PGSIZE)));
uint32_t g_code_used = 0;
typedef int (*ValidateFuncType)(int);

typedef enum XUDTFlags {
  XUDTFlags_Plain = 0,
  XUDTFlags_InArgs = 1,
  XUDTFlags_InWitness = 2,
} XUDTFlags;

// functions
int load_validate_func(const uint8_t* hash, ValidateFuncType* func) {
  int err = 0;
  void* handle = NULL;
  size_t consumed_size = 0;

  CHECK2(MAX_CODE_SIZE > g_code_used, ERROR_NOT_ENOUGH_BUFF);
  err = ckb_dlopen2(hash, 0, &g_code_buffer[g_code_used],
              MAX_CODE_SIZE - g_code_used, &handle, &consumed_size);
  CHECK(err);
  CHECK2(handle != NULL, ERROR_CANT_LOAD_LIB);
  ASSERT(consumed_size % RISCV_PGSIZE == 0);
  g_code_used += consumed_size;

  *func = (ValidateFuncType)ckb_dlsym(handle, EXPORTED_FUNC_NAME);
  CHECK2(*func != NULL, ERROR_CANT_LOAD_LIB);

  err = 0;
exit:
  return err;
}

int verify_byte32vec(uint8_t* ptr, uint32_t size, uint32_t* real_size) {
  int err = 0;

  CHECK2(size >= MOL_NUM_T_SIZE, ERROR_INVALID_MOL_FORMAT);
  mol_num_t item_count = mol_unpack_number(ptr);
  if (item_count == 0) {
    CHECK2(size == MOL_NUM_T_SIZE, ERROR_INVALID_MOL_FORMAT);
  } else {
    *real_size = MOL_NUM_T_SIZE + 32 * item_count;
    CHECK2(*real_size <= size, ERROR_INVALID_MOL_FORMAT);
  }
  err = 0;
exit:
  return err;
}

// the *var_len may be bigger than real length of raw extension data
int load_raw_extension_data(uint8_t** var_data, uint32_t* var_len) {
  int err = 0;
  // Load witness of first input
  uint64_t witness_len = WITNESS_SIZE;
  uint32_t real_size = 0;
  err = ckb_load_witness(g_witness, &witness_len, 0, 0,
                         CKB_SOURCE_GROUP_INPUT);
  CHECK(err);

  *var_len = witness_len;
  if (*var_len > WITNESS_SIZE) {
    *var_len = WITNESS_SIZE;
  }
  *var_data = g_witness;

exit:
  return err;
}

// *var_data will point to "Raw Extension Data", which can be in args or witness
// *var_data will refer to a memory location of g_script or g_witness
int parse_args(int* owner_mode, XUDTFlags* flag, uint8_t** var_data, uint32_t* var_len) {
  int err = 0;

  uint64_t len = SCRIPT_SIZE;
  int ret = ckb_load_script(g_script, &len, 0);
  CHECK(ret);
  CHECK2(len <= SCRIPT_SIZE, ERROR_SCRIPT_TOO_LONG);

  mol_seg_t script_seg;
  script_seg.ptr = g_script;
  script_seg.size = len;

  mol_errno mol_err = MolReader_Script_verify(&script_seg, false);
  CHECK2(mol_err == MOL_OK, ERROR_ENCODING);

  mol_seg_t args_seg = MolReader_Script_get_args(&script_seg);
  mol_seg_t args_bytes_seg = MolReader_Bytes_raw_bytes(&args_seg);
  CHECK2(args_bytes_seg.size >= BLAKE2B_BLOCK_SIZE, ERROR_ARGUMENTS_LEN);

  // With owner lock script extracted, we will look through each input in the
  // current transaction to see if any unlocked cell uses owner lock.
  *owner_mode = 0;
  size_t i = 0;
  while (1) {
    uint8_t buffer[BLAKE2B_BLOCK_SIZE];
    uint64_t len2 = BLAKE2B_BLOCK_SIZE;
    // There are 2 points worth mentioning here:
    //
    // * First, we are using the checked version of CKB syscalls, the checked
    // versions will return an error if our provided buffer is not enough to
    // hold all returned data. This can help us ensure that we are processing
    // enough data here.
    // * Second, `CKB_CELL_FIELD_LOCK_HASH` is used here to directly load the
    // lock script hash, so we don't have to manually calculate the hash again
    // here.
    ret = ckb_checked_load_cell_by_field(buffer, &len2, 0, i, CKB_SOURCE_INPUT,
                                         CKB_CELL_FIELD_LOCK_HASH);
    if (ret == CKB_INDEX_OUT_OF_BOUND) {
      break;
    }
    CHECK(ret);
    CHECK2(len2 != BLAKE2B_BLOCK_SIZE, ERROR_ENCODING);

    if (memcmp(buffer, args_bytes_seg.ptr, BLAKE2B_BLOCK_SIZE) == 0) {
      *owner_mode = 1;
      break;
    }
    i += 1;
  }

  // parse xUDT args
  if ((args_bytes_seg.size - BLAKE2B_BLOCK_SIZE) < FLAGS_SIZE) {
    *var_data = NULL;
    *var_len = 0;
  } else {
    uint32_t* flag_ptr = (uint32_t*)(args_bytes_seg.ptr + BLAKE2B_BLOCK_SIZE);
    if (*flag_ptr == 0) {
      *flag = XUDTFlags_Plain;
    } else if (*flag_ptr == 1) {
      uint32_t real_size = 0;
      *flag = XUDTFlags_InArgs;
      *var_len = args_bytes_seg.size - BLAKE2B_BLOCK_SIZE - FLAGS_SIZE;
      *var_data = args_bytes_seg.ptr + BLAKE2B_BLOCK_SIZE + FLAGS_SIZE;

      err = verify_byte32vec(*var_data, *var_len, &real_size);
      CHECK(err);
      // note, it's different than "flag = 2"
      CHECK2(real_size == *var_len, ERROR_INVALID_ARGS_FORMAT);
    } else if (*flag_ptr == 2) {
      uint32_t real_size = 0;

      *flag = XUDTFlags_InWitness;
      uint32_t hash_size = args_bytes_seg.size - BLAKE2B_BLOCK_SIZE - FLAGS_SIZE;
      CHECK2(hash_size == BLAKE160_SIZE, ERROR_INVALID_FLAG);

      err = load_raw_extension_data(var_data, var_len);
      CHECK(err);

      err = verify_byte32vec(*var_data, *var_len, &real_size);
      CHECK(err);
      // note, it's different than "flag = 1"
      CHECK2(real_size <= *var_len, ERROR_INVALID_WITNESS_FORMAT);
      *var_len = real_size;

      // verify the hash
      uint8_t hash[BLAKE2B_BLOCK_SIZE] = {0};
      uint8_t* blake160_hash = args_bytes_seg.ptr + BLAKE2B_BLOCK_SIZE + FLAGS_SIZE;
      err = blake2b(hash, BLAKE2B_BLOCK_SIZE, *var_data, *var_len, NULL, 0);
      CHECK2(err == 0, ERROR_BLAKE2B_ERROR);
      CHECK2(memcmp(blake160_hash, hash, BLAKE160_SIZE) == 0, ERROR_HASH_MISMATCHED);
    } else {
      CHECK2(false, ERROR_INVALID_FLAG);
    }
  }
  err = 0;
exit:
  return err;
}

#ifdef CKB_USE_SIM
int simulator_main() {
#else
int main() {
#endif
  int err = 0;
  int owner_mode = 0;
  uint8_t* raw_extension_data = NULL;
  uint32_t raw_extension_len = 0;
  XUDTFlags flags = XUDTFlags_Plain;

  err = parse_args(&owner_mode, &flags, &raw_extension_data, &raw_extension_len);
  CHECK(err);
  CHECK2(owner_mode == 1 || owner_mode == 0, ERROR_INVALID_ARGS_FORMAT);
  CHECK2(raw_extension_data != NULL, ERROR_INVALID_ARGS_FORMAT);
  CHECK2(raw_extension_len > 0, ERROR_INVALID_ARGS_FORMAT);

  if (flags == XUDTFlags_Plain) {
    // TODO: copy simple UDT routine?
  }

  mol_seg_t raw_extension_seg = {0};
  raw_extension_seg.ptr = raw_extension_data;
  raw_extension_seg.size = raw_extension_len;
  CHECK2(MolReader_Byte32Vec_verify(&raw_extension_seg, true), ERROR_INVALID_ARGS_FORMAT);
  uint32_t size = MolReader_Byte32Vec_length(&raw_extension_seg);
  for (uint32_t i = 0; i < size; i++) {
    ValidateFuncType func;
    mol_seg_res_t res = MolReader_Byte32Vec_get(&raw_extension_seg, i);
    CHECK2(res.errno == 0, ERROR_INVALID_MOL_FORMAT);
    CHECK2(res.seg.size == 32, ERROR_INVALID_MOL_FORMAT);
    err = load_validate_func(res.seg.ptr, &func);
    CHECK(err);
    int result = func(owner_mode);
    if (result != 0) {
      xudt_printf("A non-zero returned from xUDT extension scripts.\n");
    }
    CHECK(result == 0);
  }
  err = 0;

exit:
  return err;
}
