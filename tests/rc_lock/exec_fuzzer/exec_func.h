#ifndef XUDT_RCE_SIMULATOR_TESTS_XUDT_RCE_SMT_FUZZER_SMT_FUNC_H_
#define XUDT_RCE_SIMULATOR_TESTS_XUDT_RCE_SMT_FUZZER_SMT_FUNC_H_
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include "ckb_exec.h"


int exec_func(uint8_t* data, size_t size) {
  int err = 0;

  if (size < 200)
    return 1;

  CkbBinaryArgsType bin = {0};
  ckb_exec_reset(&bin);

  uint8_t input_len = *data % 70;
  uint8_t* end = data + size;
  uint8_t* ptr = data + 1;
  for (int i = 0; i < input_len; i++) {
    uint32_t len = *ptr;
    ptr++;
    if ((ptr + len) >= end)
      break;
    err = ckb_exec_append(&bin, ptr, len);
    if (err != 0)
      break;
  }

  CkbHexArgsType hex;
  err = ckb_exec_encode_params(&bin, &hex);
  CkbBinaryArgsType bin2 = {0};
  err = ckb_exec_decode(hex.argc, hex.argv, &bin2);

  // test ckb_exec_decode
  uint8_t data2[size];
  data2[size - 1] = 0;
  memcpy(data2, data, size);

  uint32_t argc = *data2 % 70;
  char* argv[argc];
  for (uint32_t i = 0; i < argc; i++) {
    argv[i] = (char*)(data2 + i + 1);
  }
  CkbBinaryArgsType bin3;
  ckb_exec_decode(argc, argv, &bin3);

  return 0;
}

#endif //XUDT_RCE_SIMULATOR_TESTS_XUDT_RCE_SMT_FUZZER_SMT_FUNC_H_
