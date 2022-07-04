#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#define ASSERT(f) (void)0
#include "opentx.h"

int LLVMFuzzerTestOneInput(uint8_t *data, size_t size) {
  int err = 0;
  if (size < 2) {
    return 0;
  }
  g_data_len = (size_t) * ((uint16_t *)data);
  size -= 2;
  data += 2;

  OpenTxWitness witness = {0};
  err = opentx_parse_witness(data, size, &witness);
  if (err != 0) return err;
  uint8_t msg[32];
  err = opentx_generate_message(&witness, data, size, msg, sizeof(msg));
  if (err != 0) return err;
  return 0;
}
