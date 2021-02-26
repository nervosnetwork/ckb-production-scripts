
// uncomment to enable printf in CKB-VM
//#define CKB_C_STDLIB_PRINTF
//#include <stdio.h>

#if defined(CKB_COVERAGE) || defined(CKB_RUN_IN_VM)
#define ASSERT(s) (void)0
#else
#include <assert.h>
#define ASSERT assert
#endif

#include "xudt_rce.c"

int main() {
  int err = 0;

  // prepare basic data
  uint8_t hash0[BLAKE2B_BLOCK_SIZE] = {0};
  uint8_t hash1[BLAKE2B_BLOCK_SIZE] = {1};
  uint8_t extension_hash[BLAKE2B_BLOCK_SIZE] = {0x66};
  xudt_begin_data();
  xudt_set_flags(1);
  // not owner mode
  xudt_set_owner_mode(hash0, hash1);
  xudt_add_extension_script_hash(
      extension_hash, 1,
      "tests/xudt_rce/cmake-build-debug/libextension_script_0.dylib");
  xudt_add_input_amount(999);
  xudt_add_output_amount(999);
  xudt_end_data();

  // flags = 1
  xudt_set_flags(1);
  err = simulator_main();
  CHECK(err);
  // flags = 2
  xudt_set_flags(2);
  err = simulator_main();
  CHECK(err);
  // flags = 0
  xudt_set_flags(0);
  err = simulator_main();
  CHECK(err);

  // owner mode is true
  xudt_set_owner_mode(hash0, hash0);
  err = simulator_main();
  CHECK(err);

  err = 0;
exit:
  if (err != 0) {
    xudt_printf("!!! Run tests in simulator failed, error code: %d\n", err);
  } else {
    xudt_printf("Run tests in simulator successfully.\n");
  }
  return err;
}
