#ifndef XUDT_RCE_SIMULATOR_TESTS_XUDT_RCE_SMT_FUZZER_SMT_FUNC_H_
#define XUDT_RCE_SIMULATOR_TESTS_XUDT_RCE_SMT_FUZZER_SMT_FUNC_H_
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include "ckb_exec.h"


int exec_func2(uint8_t* data, size_t size) {
  int err = 0;

  char buff[size];
  memcpy(buff, data, size);

  char* next = buff;
  uint8_t* param = NULL;
  uint32_t len = 0;

  while (true) {
    err = ckb_exec_decode_params(next, &param, &len, &next);
    if (err != 0)
      break;
  }

  return 0;
}


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
  if (err != 0)
    return err;
  char* next = hex.buff;

  uint8_t* param = NULL;
  uint32_t len = 0;
  while (true) {
    err = ckb_exec_decode_params(next, &param, &len, &next);
    if (err != 0)
      break;
  }

  return 0;
}

#endif //XUDT_RCE_SIMULATOR_TESTS_XUDT_RCE_SMT_FUZZER_SMT_FUNC_H_
