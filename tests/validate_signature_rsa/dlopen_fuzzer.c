
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "ckb_consts.h"
#include "ckb_syscalls_fuzzer.h"
#define CKB_C_STDLIB_CKB_SYSCALLS_H_
#include "ckb_dlfcn.h"

#define OUTPUT_SIZE (64 * 1024 * 1024)
#define ALIGNED_SIZE (OUTPUT_SIZE - RISCV_PGSIZE)
#define ROUNDUP(a, b) ((((a)-1) / (b) + 1) * (b))
#define ROUNDDOWN(a, b) ((a) / (b) * (b))

int LLVMFuzzerTestOneInput(uint8_t *data, size_t size) {
  // Save random input from libFuzzer so it is reachable from the invoked
  // ckb_syscalls.
  s_INPUT_DATA = data;
  s_INPUT_SIZE = size;

  // Allocate output buffer and ensure that the pointer is aligned to the
  // RISCV_PGSIZE.
  uint8_t *output_data = (uint8_t *)malloc(OUTPUT_SIZE);
  assert(output_data != NULL);
  uint8_t *aligned_data =
      (uint8_t *)ROUNDUP((uint64_t)output_data, (uint64_t)RISCV_PGSIZE);

  // Invoke ckb_dlopen. Since data is loaded directly from s_INPUT_DATA, the
  // dep_cell_data_hash (NULL here) is ignored by the mock implementations of
  // the CKB syscalls.
  void *handle = NULL;
  size_t used_size = 0;
  int result =
      ckb_dlopen(aligned_data, aligned_data, ALIGNED_SIZE, &handle, &used_size);

  // If the call succeeded we expect handle to be non-null and the used_size to
  // be in the range (0, ALIGNED_SIZE].
  if (result == 0) {
    assert(handle != NULL);
    assert((0 < used_size) && (used_size <= ALIGNED_SIZE));

    // Invoke ckb_dlsym and attempt to load the symbol "validate".
    ckb_dlsym(handle, "validate_signature");
  }

  // Free output buffer and return.
  free(output_data);
  return 0;
}
