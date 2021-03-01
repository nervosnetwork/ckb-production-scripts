#ifndef ASSERT
#define ASSERT(s) (void)0
#endif

#include <stdbool.h>
#include <string.h>
#include "ckb_consts.h"
#include "xudt_rce_mol.h"
#include "blake2b.h"


#if defined(CKB_USE_SIM)
#include "ckb_syscall_xudt_sim.h"
#include <stdio.h>
#define xudt_printf printf
#else
#include "ckb_syscalls.h"
#include "ckb_dlfcn.h"
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

#include "rce.h"

// global variables, type definitions, etc

// We will leverage gcc's 128-bit integer extension here for number crunching.
typedef unsigned __int128 uint128_t;

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
int load_validate_func(const uint8_t* hash, uint8_t hash_type, ValidateFuncType* func) {
  int err = 0;
  void* handle = NULL;
  size_t consumed_size = 0;

  CHECK2(MAX_CODE_SIZE > g_code_used, ERROR_NOT_ENOUGH_BUFF);
  err = ckb_dlopen2(hash, hash_type, &g_code_buffer[g_code_used],
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

int verify_script_vec(uint8_t* ptr, uint32_t size, uint32_t* real_size) {
  int err = 0;

  CHECK2(size >= MOL_NUM_T_SIZE, ERROR_INVALID_MOL_FORMAT);
  mol_num_t full_size = mol_unpack_number(ptr);
  *real_size = full_size;
  CHECK2(*real_size <= size, ERROR_INVALID_MOL_FORMAT);
  err = 0;
exit:
  return err;
}

// the *var_len may be bigger than real length of raw extension data
int load_raw_extension_data(uint8_t** var_data, uint32_t* var_len) {
  int err = 0;
  // Load witness of first input
  uint64_t witness_len = WITNESS_SIZE;
  err = ckb_checked_load_witness(g_witness, &witness_len, 0, 0,
                         CKB_SOURCE_GROUP_INPUT);
  CHECK(err);
  mol_seg_t seg;
  seg.ptr = g_witness;
  seg.size = witness_len;
  err = MolReader_WitnessArgs_verify(&seg, true);
  CHECK2(err == MOL_OK, ERROR_INVALID_MOL_FORMAT);
  mol_seg_t input_seg = MolReader_WitnessArgs_get_input_type(&seg);
  CHECK2(input_seg.size > 0, ERROR_INVALID_MOL_FORMAT);
  mol_seg_t extension_seg = MolReader_Bytes_raw_bytes(&input_seg);
  CHECK2(extension_seg.size > 0, ERROR_INVALID_MOL_FORMAT);

  *var_len = extension_seg.size;
  *var_data = extension_seg.ptr;

  err = 0;
exit:
  return err;
}

// *var_data will point to "Raw Extension Data", which can be in args or witness
// *var_data will refer to a memory location of g_script or g_witness
int parse_args(int* owner_mode, XUDTFlags* flag, uint8_t** var_data, uint32_t* var_len) {
  int err = 0;

  uint64_t len = SCRIPT_SIZE;
  int ret = ckb_checked_load_script(g_script, &len, 0);
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
    CHECK2(len2 == BLAKE2B_BLOCK_SIZE, ERROR_ENCODING);

    if (memcmp(buffer, args_bytes_seg.ptr, BLAKE2B_BLOCK_SIZE) == 0) {
      *owner_mode = 1;
      break;
    }
    i += 1;
  }

  // parse xUDT args
  if (args_bytes_seg.size < (FLAGS_SIZE+BLAKE2B_BLOCK_SIZE)) {
    *var_data = NULL;
    *var_len = 0;
    *flag = XUDTFlags_Plain;
  } else {
    uint32_t* flag_ptr = (uint32_t*)(args_bytes_seg.ptr + BLAKE2B_BLOCK_SIZE);
    if (*flag_ptr == 0) {
      *flag = XUDTFlags_Plain;
    } else if (*flag_ptr == 1) {
      uint32_t real_size = 0;
      *flag = XUDTFlags_InArgs;
      *var_len = args_bytes_seg.size - BLAKE2B_BLOCK_SIZE - FLAGS_SIZE;
      *var_data = args_bytes_seg.ptr + BLAKE2B_BLOCK_SIZE + FLAGS_SIZE;

      err = verify_script_vec(*var_data, *var_len, &real_size);
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

      err = verify_script_vec(*var_data, *var_len, &real_size);
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

// copied from simple_udt.c
int simple_udt(int owner_mode) {
  if (owner_mode)
    return CKB_SUCCESS;

  int ret = 0;
  // When the owner mode is not enabled, however, we will then need to ensure
  // the sum of all input tokens is not smaller than the sum of all output
  // tokens. First, let's loop through all input cells containing current UDTs,
  // and gather the sum of all input tokens.
  uint128_t input_amount = 0;
  size_t i = 0;
  uint64_t len = 0;
  while (1) {
    uint128_t current_amount = 0;
    len = 16;
    // The implementation here does not require that the transaction only
    // contains UDT cells for the current UDT type. It's perfectly fine to mix
    // the cells for multiple different types of UDT together in one
    // transaction. But that also means we need a way to tell one UDT type from
    // another UDT type. The trick is in the `CKB_SOURCE_GROUP_INPUT` value used
    // here. When using it as the source part of the syscall, the syscall would
    // only iterate through cells with the same script as the current running
    // script. Since different UDT types will naturally have different
    // script(the args part will be different), we can be sure here that this
    // loop would only iterate through UDTs that are of the same type as the one
    // identified by the current running script.
    //
    // In the case that multiple UDT types are included in the same transaction,
    // this simple UDT script will be run multiple times to validate the
    // transaction, each time with a different script containing different
    // script args, representing different UDT types.
    //
    // A different trick used here, is that our current implementation assumes
    // that the amount of UDT is stored as unsigned 128-bit little endian
    // integer in the first 16 bytes of cell data. Since RISC-V also uses little
    // endian format, we can just read the first 16 bytes of cell data into
    // `current_amount`, which is just an unsigned 128-bit integer in C. The
    // memory layout of a C program will ensure that the value is set correctly.
    ret = ckb_checked_load_cell_data((uint8_t *)&current_amount, &len, 0, i,
                             CKB_SOURCE_GROUP_INPUT);
    // When `CKB_INDEX_OUT_OF_BOUND` is reached, we know we have iterated
    // through all cells of current type.
    if (ret == CKB_INDEX_OUT_OF_BOUND) {
      break;
    }
    if (ret != CKB_SUCCESS) {
      return ret;
    }
    if (len < 16) {
      return ERROR_ENCODING;
    }
    input_amount += current_amount;
    // Like any serious smart contract out there, we will need to check for
    // overflows.
    if (input_amount < current_amount) {
      return ERROR_OVERFLOWING;
    }
    i += 1;
  }

  // With the sum of all input UDT tokens gathered, let's now iterate through
  // output cells to grab the sum of all output UDT tokens.
  uint128_t output_amount = 0;
  i = 0;
  while (1) {
    uint128_t current_amount = 0;
    len = 16;
    // Similar to the above code piece, we are also looping through output cells
    // with the same script as current running script here by using
    // `CKB_SOURCE_GROUP_OUTPUT`.
    ret = ckb_checked_load_cell_data((uint8_t *)&current_amount, &len, 0, i,
                             CKB_SOURCE_GROUP_OUTPUT);
    if (ret == CKB_INDEX_OUT_OF_BOUND) {
      break;
    }
    if (ret != CKB_SUCCESS) {
      return ret;
    }
    if (len < 16) {
      return ERROR_ENCODING;
    }
    output_amount += current_amount;
    // Like any serious smart contract out there, we will need to check for
    // overflows.
    if (output_amount < current_amount) {
      return ERROR_OVERFLOWING;
    }
    i += 1;
  }

  // When both value are gathered, we can perform the final check here to
  // prevent non-authorized token issurance.
  if (input_amount < output_amount) {
    return ERROR_AMOUNT;
  }
  return CKB_SUCCESS;
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
  if (flags != XUDTFlags_Plain) {
    CHECK2(raw_extension_data != NULL, ERROR_INVALID_ARGS_FORMAT);
    CHECK2(raw_extension_len > 0, ERROR_INVALID_ARGS_FORMAT);
  }
  err = simple_udt(owner_mode);
  CHECK(err);

  if (flags == XUDTFlags_Plain) {
    return CKB_SUCCESS;
  }

  mol_seg_t raw_extension_seg = {0};
  raw_extension_seg.ptr = raw_extension_data;
  raw_extension_seg.size = raw_extension_len;
  CHECK2(MolReader_ScriptVec_verify(&raw_extension_seg, true) == MOL_OK, ERROR_INVALID_ARGS_FORMAT);
  uint32_t size = MolReader_ScriptVec_length(&raw_extension_seg);
  for (uint32_t i = 0; i < size; i++) {
    ValidateFuncType func;
    mol_seg_res_t res = MolReader_ScriptVec_get(&raw_extension_seg, i);
    CHECK2(res.errno == 0, ERROR_INVALID_MOL_FORMAT);
    CHECK2(MolReader_Script_verify(&res.seg, false) == MOL_OK, ERROR_INVALID_MOL_FORMAT);

    mol_seg_t code_hash = MolReader_Script_get_code_hash(&res.seg);
    mol_seg_t hash_type = MolReader_Script_get_hash_type(&res.seg);
    uint8_t hash_type2 = *((uint8_t*)hash_type.ptr);

    err = load_validate_func(code_hash.ptr, hash_type2, &func);

    CHECK(err);
    int result = func(owner_mode);
    if (result != 0) {
      xudt_printf("A non-zero returned from xUDT extension scripts.\n");
    }
    CHECK(result);
  }


  err = 0;
exit:
  return err;
}
