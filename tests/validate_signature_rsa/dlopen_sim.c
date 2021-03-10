// uncomment to enable printf in CKB-VM
//#define CKB_C_STDLIB_PRINTF
//#include <stdio.h>
#define CKB_COVERAGE
#if defined(CKB_COVERAGE)
#define ASSERT(s) (void)0
#else
#include <assert.h>
#define ASSERT assert
#endif

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "ckb_consts.h"

#if defined(CKB_USE_SIM)
#include <stdio.h>

#include "ckb_syscall_dlopen_sim.h"
#define dlopen_printf printf
#else
#include "ckb_dlfcn.h"
#include "ckb_syscalls.h"
#define dlopen_printf(x, ...) (void)0
#endif

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

int ckb_dlopen2(const uint8_t *dep_cell_hash, uint8_t hash_type,
                uint8_t *aligned_addr, size_t aligned_size, void **handle,
                size_t *consumed_size);

#include "ckb_dlfcn.h"

int main(int argc, const char *argv[]) {
  int err = 0;
  if (argc != 2) {
    printf("usage: dlopen_sim <file path to RISCV-binary>\n");
  }
  err = dlopen_init_riscv_binary(argv[1]);
  if (err != 0) {
    printf("the file path of RISCV binary is invalid: %s\n", argv[1]);
    return err;
  }
  uint8_t hash[32] = {0};
  uint8_t hash_type = 1;
  size_t code_size = 1024 * 1024;
  uint8_t code_buff[code_size];
  void *handle = NULL;
  size_t consumed_size = 0;
  err = ckb_dlopen2(hash, hash_type, code_buff, code_size, &handle,
                    &consumed_size);
  CHECK(err);
  CHECK2(handle != NULL, 1);
  CHECK2(consumed_size > 0 && consumed_size < code_size, 2);
  err = 0;
exit:
  return err;
}
