#include "opentx_func.h"


int LLVMFuzzerTestOneInput(uint8_t *data, size_t size) {
  opentx_func(data, size);
  return 0;
}
