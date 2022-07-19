#define CKB_C_STDLIB_PRINTF

// it's used by blockchain-api2.h, the behavior when panic
#ifndef MOL2_EXIT
#define MOL2_EXIT ckb_exit
#endif
int ckb_exit(signed char);
// in secp256k1_ctz64_var: we don't have __builtin_ctzl in gcc for RISC-V
#define __builtin_ctzl secp256k1_ctz64_var_debruijn

#include <blake2b.h>
#include <stdio.h>

#include "blockchain-api2.h"
//#define MOLECULEC_VERSION 7000
#include "blockchain.h"
#include "ckb_consts.h"
#include "ckb_syscalls.h"

#define BLAKE2B_BLOCK_SIZE 32

void print_data(uint8_t* buf, uint64_t len, int index, const char* name) {
  if (index < 0)
    printf("%s, len:%d :\n", name, len);
  else
    printf("%s, len: %d, index: %d :\n", name, len, index);

  if (len == 0) {
    printf("null\n\n");
    return;
  }

  uint64_t i = 0;
  for (i = 0; i < len; i++) {
    printf("0x%02X, ", buf[i]);
    if (i % 16 == 15) {
      printf("\n");
    }
  }

  if (i % 16 != 0) printf("\n");
  printf("\n");
}

void print_data_hash(uint8_t* buf, uint64_t len, int index, const char* name) {
  if (index < 0)
    printf("%s, len:%d :\n", name, len);
  else
    printf("%s, len: %d, index: %d :\n", name, len, index);

  if (len == 0) {
    printf("null\n\n");
    return;
  }

  blake2b_state b2;
  blake2b_init(&b2, BLAKE2B_BLOCK_SIZE);
  blake2b_update(&b2, buf, len);

  uint8_t hash[BLAKE2B_BLOCK_SIZE];
  blake2b_final(&b2, hash, BLAKE2B_BLOCK_SIZE);

  uint64_t i = 0;
  for (i = 0; i < BLAKE2B_BLOCK_SIZE; i++) {
    printf("%02X", hash[i]);
  }
  printf("\n\n");
}

uint8_t G_BUFFER[1024 * 1024] = {0};
uint64_t G_BUFFER_LEN = sizeof(G_BUFFER);

uint64_t reset_buffer() {
  memset(G_BUFFER, 0, G_BUFFER_LEN);
  return G_BUFFER_LEN;
}

void dump_load_cell() {
  uint64_t buf_len;
  for (size_t index = 0; true; index++) {
    buf_len = reset_buffer();
    int ret = ckb_load_cell(G_BUFFER, &buf_len, 0, index, CKB_SOURCE_INPUT);
    if (ret == CKB_INDEX_OUT_OF_BOUND) {
      break;
    }

    print_data_hash(G_BUFFER, buf_len, index, "input");
  }

  for (size_t index = 0; true; index++) {
    buf_len = reset_buffer();
    int ret = ckb_load_cell(G_BUFFER, &buf_len, 0, index, CKB_SOURCE_OUTPUT);
    if (ret == CKB_INDEX_OUT_OF_BOUND) {
      break;
    }

    print_data_hash(G_BUFFER, buf_len, index, "output");
  }

  for (size_t index = 0; true; index++) {
    buf_len = reset_buffer();
    int ret =
        ckb_load_cell(G_BUFFER, &buf_len, 0, index, CKB_SOURCE_GROUP_INPUT);
    if (ret == CKB_INDEX_OUT_OF_BOUND) {
      break;
    }

    print_data_hash(G_BUFFER, buf_len, index, "group input");
  }

  for (size_t index = 0; true; index++) {
    buf_len = reset_buffer();
    int ret =
        ckb_load_cell(G_BUFFER, &buf_len, 0, index, CKB_SOURCE_GROUP_OUTPUT);
    if (ret == CKB_INDEX_OUT_OF_BOUND) {
      break;
    }

    print_data_hash(G_BUFFER, buf_len, index, "group output");
  }

  for (size_t index = 0; true; index++) {
    buf_len = reset_buffer();
    int ret = ckb_load_cell(G_BUFFER, &buf_len, 0, index, CKB_SOURCE_CELL_DEP);
    if (ret == CKB_INDEX_OUT_OF_BOUND) {
      break;
    }

    print_data_hash(G_BUFFER, buf_len, index, "dep");
  }
}

void dump_load_cell_data() {
  uint64_t buf_len;
  for (size_t index = 0; true; index++) {
    buf_len = reset_buffer();
    int ret =
        ckb_load_cell_data(G_BUFFER, &buf_len, 0, index, CKB_SOURCE_INPUT);
    if (ret == CKB_INDEX_OUT_OF_BOUND) {
      break;
    }
    if (ret != 0) {
      printf("input data failed, index: %d", index);
      break;
    }

    print_data_hash(G_BUFFER, buf_len, index, "input data");
  }

  for (size_t index = 0; true; index++) {
    buf_len = reset_buffer();
    int ret =
        ckb_load_cell_data(G_BUFFER, &buf_len, 0, index, CKB_SOURCE_OUTPUT);
    if (ret == CKB_INDEX_OUT_OF_BOUND) {
      break;
    }
    if (ret != 0) {
      printf("output data failed, index: %d", index);
      break;
    }

    print_data_hash(G_BUFFER, buf_len, index, "output data");
  }

  for (size_t index = 0; true; index++) {
    buf_len = reset_buffer();
    int ret = ckb_load_cell_data(G_BUFFER, &buf_len, 0, index,
                                 CKB_SOURCE_GROUP_INPUT);
    if (ret == CKB_INDEX_OUT_OF_BOUND) {
      break;
    }
    if (ret != 0) {
      printf("group input data failed, index: %d", index);
      break;
    }

    print_data_hash(G_BUFFER, buf_len, index, "group input data");
  }

  for (size_t index = 0; true; index++) {
    buf_len = reset_buffer();
    int ret = ckb_load_cell_data(G_BUFFER, &buf_len, 0, index,
                                 CKB_SOURCE_GROUP_OUTPUT);
    if (ret == CKB_INDEX_OUT_OF_BOUND) {
      break;
    }
    if (ret != 0) {
      printf("group output data failed, index: %d", index);
      break;
    }

    print_data_hash(G_BUFFER, buf_len, index, "group output data");
  }

  for (size_t index = 0; true; index++) {
    buf_len = reset_buffer();
    int ret =
        ckb_load_cell_data(G_BUFFER, &buf_len, 0, index, CKB_SOURCE_CELL_DEP);
    if (ret == CKB_INDEX_OUT_OF_BOUND) {
      break;
    }
    if (ret != 0) {
      printf("dep data failed, index: %d", index);
      break;
    }

    print_data_hash(G_BUFFER, buf_len, index, "dep data");
  }
}

void dump_load_input() {
  uint64_t buf_len;
  for (size_t index = 0; true; index++) {
    buf_len = reset_buffer();
    int ret = ckb_load_input(G_BUFFER, &buf_len, 0, index, CKB_SOURCE_INPUT);
    if (ret == CKB_INDEX_OUT_OF_BOUND) {
      break;
    }
    if (ret != 0) {
      printf("input input data failed, index: %d", index);
      break;
    }

    print_data_hash(G_BUFFER, buf_len, index, "input input data");
  }

  for (size_t index = 0; true; index++) {
    buf_len = reset_buffer();
    int ret = ckb_load_input(G_BUFFER, &buf_len, 0, index, CKB_SOURCE_OUTPUT);
    if (ret == CKB_INDEX_OUT_OF_BOUND) {
      break;
    }
    if (ret != 0) {
      printf("input output data failed, index: %d", index);
      break;
    }

    print_data_hash(G_BUFFER, buf_len, index, "input output data");
  }

  for (size_t index = 0; true; index++) {
    buf_len = reset_buffer();
    int ret =
        ckb_load_input(G_BUFFER, &buf_len, 0, index, CKB_SOURCE_GROUP_INPUT);
    if (ret == CKB_INDEX_OUT_OF_BOUND) {
      break;
    }
    if (ret != 0) {
      printf("input group input data failed, index: %d", index);
      break;
    }

    print_data_hash(G_BUFFER, buf_len, index, "input group input data");
  }

  for (size_t index = 0; true; index++) {
    buf_len = reset_buffer();
    int ret =
        ckb_load_input(G_BUFFER, &buf_len, 0, index, CKB_SOURCE_GROUP_OUTPUT);
    if (ret == CKB_INDEX_OUT_OF_BOUND) {
      break;
    }
    if (ret != 0) {
      printf("input group output data failed, index: %d", index);
      break;
    }

    print_data_hash(G_BUFFER, buf_len, index, "input group output data");
  }

  for (size_t index = 0; true; index++) {
    buf_len = reset_buffer();
    int ret = ckb_load_input(G_BUFFER, &buf_len, 0, index, CKB_SOURCE_CELL_DEP);
    if (ret == CKB_INDEX_OUT_OF_BOUND) {
      break;
    }
    if (ret != 0) {
      printf("input dep data failed, index: %d", index);
      break;
    }

    print_data_hash(G_BUFFER, buf_len, index, "input dep data");
  }
}

void dump_load_witness() {
  uint64_t buf_len;
  for (size_t index = 0; true; index++) {
    buf_len = reset_buffer();
    int ret = ckb_load_witness(G_BUFFER, &buf_len, 0, index, CKB_SOURCE_INPUT);
    if (ret == CKB_INDEX_OUT_OF_BOUND) {
      break;
    }
    if (ret != 0) {
      printf("witness input data failed, index: %d\n", index);
      break;
    }

    print_data_hash(G_BUFFER, buf_len, index, "witness input data");
  }

  for (size_t index = 0; true; index++) {
    buf_len = reset_buffer();
    int ret = ckb_load_witness(G_BUFFER, &buf_len, 0, index, CKB_SOURCE_OUTPUT);
    if (ret == CKB_INDEX_OUT_OF_BOUND) {
      break;
    }
    if (ret != 0) {
      printf("witness output data failed, index: %d\n", index);
      break;
    }

    print_data_hash(G_BUFFER, buf_len, index, "witness output data");
  }

  for (size_t index = 0; true; index++) {
    buf_len = reset_buffer();
    int ret =
        ckb_load_witness(G_BUFFER, &buf_len, 0, index, CKB_SOURCE_GROUP_INPUT);
    if (ret == CKB_INDEX_OUT_OF_BOUND) {
      break;
    }
    if (ret != 0) {
      printf("witness group input data failed, index: %d\n", index);
      break;
    }

    print_data_hash(G_BUFFER, buf_len, index, "witness group input data");
  }

  for (size_t index = 0; true; index++) {
    buf_len = reset_buffer();
    int ret =
        ckb_load_witness(G_BUFFER, &buf_len, 0, index, CKB_SOURCE_GROUP_OUTPUT);
    if (ret == CKB_INDEX_OUT_OF_BOUND) {
      break;
    }
    if (ret != 0) {
      printf("witness group output data failed, index: %d\n", index);
      break;
    }

    print_data_hash(G_BUFFER, buf_len, index, "witness group output data");
  }

  for (size_t index = 0; true; index++) {
    buf_len = reset_buffer();
    int ret =
        ckb_load_witness(G_BUFFER, &buf_len, 0, index, CKB_SOURCE_CELL_DEP);
    if (ret == CKB_INDEX_OUT_OF_BOUND) {
      break;
    }
    if (ret != 0) {
      printf("witness dep data failed, index: %d\n", index);
      break;
    }

    print_data_hash(G_BUFFER, buf_len, index, "witness dep data");
  }
}

void dump_load_cell_by_field(size_t field, bool out_hash) {
  uint64_t buf_len;
  for (size_t index = 0; true; index++) {
    buf_len = reset_buffer();
    int ret = ckb_load_cell_by_field(G_BUFFER, &buf_len, 0, index,
                                     CKB_SOURCE_INPUT, field);
    if (ret == CKB_INDEX_OUT_OF_BOUND) {
      break;
    }
    if (ret != 0) {
      printf("field input data failed, ret: %d, index: %d\n", ret, index);
      break;
    }

    if (out_hash)
      print_data_hash(G_BUFFER, buf_len, index, "field input data");
    else
      print_data(G_BUFFER, buf_len, index, "field input data");
  }

  for (size_t index = 0; true; index++) {
    buf_len = reset_buffer();
    int ret = ckb_load_cell_by_field(G_BUFFER, &buf_len, 0, index,
                                     CKB_SOURCE_OUTPUT, field);
    if (ret == CKB_INDEX_OUT_OF_BOUND) {
      break;
    }
    if (ret != 0) {
      printf("field output data failed, ret: %d, index: %d\n", ret, index);
      break;
    }

    if (out_hash)
      print_data_hash(G_BUFFER, buf_len, index, "field output data");
    else
      print_data(G_BUFFER, buf_len, index, "field output data");
  }

  for (size_t index = 0; true; index++) {
    buf_len = reset_buffer();
    int ret = ckb_load_cell_by_field(G_BUFFER, &buf_len, 0, index,
                                     CKB_SOURCE_GROUP_INPUT, field);
    if (ret == CKB_INDEX_OUT_OF_BOUND) {
      break;
    }
    if (ret != 0) {
      printf("field group input data failed, ret: %d, index: %d\n", ret, index);
      break;
    }

    if (out_hash)
      print_data_hash(G_BUFFER, buf_len, index, "field group input data");
    else
      print_data(G_BUFFER, buf_len, index, "field group input data");
  }

  for (size_t index = 0; true; index++) {
    buf_len = reset_buffer();
    int ret = ckb_load_cell_by_field(G_BUFFER, &buf_len, 0, index,
                                     CKB_SOURCE_GROUP_OUTPUT, field);
    if (ret == CKB_INDEX_OUT_OF_BOUND) {
      break;
    }
    if (ret != 0) {
      printf("field group output data failed, ret: %d, index: %d\n", ret,
             index);
      break;
    }

    if (out_hash)
      print_data_hash(G_BUFFER, buf_len, index, "field group output data");
    else
      print_data(G_BUFFER, buf_len, index, "field group output data");
  }

  for (size_t index = 0; true; index++) {
    buf_len = reset_buffer();
    int ret = ckb_load_cell_by_field(G_BUFFER, &buf_len, 0, index,
                                     CKB_SOURCE_CELL_DEP, field);
    if (ret == CKB_INDEX_OUT_OF_BOUND) {
      break;
    }
    if (ret != 0) {
      printf("field dep data failed, ret: %d, index: %d\n", ret, index);
      break;
    }

    if (out_hash)
      print_data_hash(G_BUFFER, buf_len, index, "field dep data");
    else
      print_data(G_BUFFER, buf_len, index, "field dep data");
  }
}

void dump_load_input_by_field(size_t field, bool out_hash) {
  uint64_t buf_len;
  for (size_t index = 0; true; index++) {
    buf_len = reset_buffer();
    int ret = ckb_load_input_by_field(G_BUFFER, &buf_len, 0, index,
                                      CKB_SOURCE_INPUT, field);
    if (ret == CKB_INDEX_OUT_OF_BOUND) {
      break;
    }
    if (ret != 0) {
      printf("input field input data failed, ret: %d, index: %d\n", ret, index);
      break;
    }

    if (out_hash)
      print_data_hash(G_BUFFER, buf_len, index, "input field input data");
    else
      print_data(G_BUFFER, buf_len, index, "input field input data");
  }

  for (size_t index = 0; true; index++) {
    buf_len = reset_buffer();
    int ret = ckb_load_input_by_field(G_BUFFER, &buf_len, 0, index,
                                      CKB_SOURCE_OUTPUT, field);
    if (ret == CKB_INDEX_OUT_OF_BOUND) {
      break;
    }
    if (ret != 0) {
      printf("input field output data failed, ret: %d, index: %d\n", ret,
             index);
      break;
    }

    if (out_hash)
      print_data_hash(G_BUFFER, buf_len, index, "input field output data");
    else
      print_data(G_BUFFER, buf_len, index, "input field output data");
  }

  for (size_t index = 0; true; index++) {
    buf_len = reset_buffer();
    int ret = ckb_load_input_by_field(G_BUFFER, &buf_len, 0, index,
                                      CKB_SOURCE_GROUP_INPUT, field);
    if (ret == CKB_INDEX_OUT_OF_BOUND) {
      break;
    }
    if (ret != 0) {
      printf("input field group input data failed, ret: %d, index: %d\n", ret,
             index);
      break;
    }

    if (out_hash)
      print_data_hash(G_BUFFER, buf_len, index, "input field group input data");
    else
      print_data(G_BUFFER, buf_len, index, "input field group input data");
  }

  for (size_t index = 0; true; index++) {
    buf_len = reset_buffer();
    int ret = ckb_load_input_by_field(G_BUFFER, &buf_len, 0, index,
                                      CKB_SOURCE_GROUP_OUTPUT, field);
    if (ret == CKB_INDEX_OUT_OF_BOUND) {
      break;
    }
    if (ret != 0) {
      printf("input field group output data failed, ret: %d, index: %d\n", ret,
             index);
      break;
    }

    if (out_hash)
      print_data_hash(G_BUFFER, buf_len, index,
                      "input field group output data");
    else
      print_data(G_BUFFER, buf_len, index, "input field group output data");
  }

  for (size_t index = 0; true; index++) {
    buf_len = reset_buffer();
    int ret = ckb_load_input_by_field(G_BUFFER, &buf_len, 0, index,
                                      CKB_SOURCE_CELL_DEP, field);
    if (ret == CKB_INDEX_OUT_OF_BOUND) {
      break;
    }
    if (ret != 0) {
      printf("input field dep data failed, ret: %d, index: %d\n", ret, index);
      break;
    }

    if (out_hash)
      print_data_hash(G_BUFFER, buf_len, index, "input field dep data");
    else
      print_data(G_BUFFER, buf_len, index, "input field dep data");
  }
}

int main() {
  printf("------------------------------------------------------------\n");

  uint64_t buf_len = reset_buffer();
  ckb_load_tx_hash(G_BUFFER, &buf_len, 0);
  print_data(G_BUFFER, buf_len, -1, "tx hash");

  buf_len = reset_buffer();
  ckb_load_transaction(G_BUFFER, &buf_len, 0);
  print_data_hash(G_BUFFER, buf_len, -1, "tx data");

  buf_len = reset_buffer();
  ckb_load_script_hash(G_BUFFER, &buf_len, 0);
  print_data(G_BUFFER, buf_len, -1, "script hash");

  buf_len = reset_buffer();
  ckb_load_script(G_BUFFER, &buf_len, 0);
  print_data_hash(G_BUFFER, buf_len, -1, "script data");

  dump_load_cell();
  dump_load_cell_data();
  dump_load_input();
  dump_load_witness();

  printf("cell by field : FIELD_CAPACITY\n");
  dump_load_cell_by_field(CKB_CELL_FIELD_CAPACITY, false);
  printf("cell by field : FIELD_DATA_HASH\n");
  dump_load_cell_by_field(CKB_CELL_FIELD_DATA_HASH, false);
  printf("cell by field : FIELD_LOCK\n");
  dump_load_cell_by_field(CKB_CELL_FIELD_LOCK, true);
  printf("cell by field : FIELD_LOCK_HASH\n");
  dump_load_cell_by_field(CKB_CELL_FIELD_LOCK_HASH, false);
  printf("cell by field : FIELD_TYPE\n");
  dump_load_cell_by_field(CKB_CELL_FIELD_TYPE, true);
  printf("cell by field : FIELD_TYPE_HASH\n");
  dump_load_cell_by_field(CKB_CELL_FIELD_TYPE_HASH, false);
  printf("cell by field : FIELD_OCC_CAP\n");
  dump_load_cell_by_field(CKB_CELL_FIELD_OCCUPIED_CAPACITY, false);

  printf("input by field : INPUT_FIELD_OUTPOINT\n");
  dump_load_input_by_field(CKB_INPUT_FIELD_OUT_POINT, false);
  printf("input by field : INPUT_FIELD_SINCE\n");
  dump_load_input_by_field(CKB_INPUT_FIELD_SINCE, false);

  return 0;
}
