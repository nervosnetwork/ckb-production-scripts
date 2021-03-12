#ifndef XUDT_RCE_SIMULATOR_TESTS_XUDT_RCE_SMT_FUZZER_SMT_FUNC_H_
#define XUDT_RCE_SIMULATOR_TESTS_XUDT_RCE_SMT_FUZZER_SMT_FUNC_H_
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include "blake2b.h"

#include "smt.h"

#define MAX_ENTRIES_COUNT 8196
int smt_func(const uint8_t* data, size_t size) {
  rce_pair_t entries[MAX_ENTRIES_COUNT];
  rce_state_t states;
  rce_state_init(&states, entries, MAX_ENTRIES_COUNT);
  const uint8_t* root_hash = NULL;
  int32_t size2 = (int32_t)size;

  if (size2 > 32) {
    root_hash = data;
  } else {
    return 1;
  }
  int32_t index = 32;
  int32_t count = 0;
  while (index < (size2-128)) {
    rce_state_insert(&states, data+index, data+index+32);
    index += 64;
    count ++;
    if (count > MAX_ENTRIES_COUNT)
      break;
  }
  rce_state_normalize(&states);
  if ((size2 - index) > 12) {
    if (rce_smt_verify(root_hash, &states, data + index, size2 - index) == 0) {
      return 0;
    } else {
      return 2;
    }
  } else {
    return 3;
  }
}
#endif //XUDT_RCE_SIMULATOR_TESTS_XUDT_RCE_SMT_FUZZER_SMT_FUNC_H_
