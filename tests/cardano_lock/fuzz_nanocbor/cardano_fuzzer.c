#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#ifndef MOL2_EXIT
#define MOL2_EXIT ckb_exit
#endif
#define CKB_SUCCESS 0

int ckb_exit(int8_t code) { return 1; }

#include "cardano_lock_inc.h"

int LLVMFuzzerTestOneInput(uint8_t *data, size_t size) {
  uint8_t payload[32] = {0};
  int rc = get_payload(data, size, payload);
  return 0;
}
