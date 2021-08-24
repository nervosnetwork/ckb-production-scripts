#ifndef _RC_LOCK_SUPPLY_H_
#define _RC_LOCK_SUPPLY_H_
#include "ckb_syscalls.h"

typedef unsigned __int128 uint128_t;

enum SupplyErrorCode {
  ERROR_EXCEED_SUPPLY = 90,
  ERROR_SUPPLY_AMOUNT,
};

// <1 byte version> <16 bytes current supply> <16 bytes max supply> <32 bytes sUDT script hash>
#define MIN_INFO_CELL_LEN 65
#define INFO_CELL_CONST_OFFSET 17

typedef struct SupplyContextType {
  size_t input_info_cell_index;
  size_t input_info_cell_count;
  size_t output_info_cell_index;
  size_t output_info_cell_count;

  uint8_t version;
  uint128_t input_current_supply;
  uint128_t output_current_supply;
  uint128_t max_supply;
  uint8_t sudt_script_hash[32];

  uint128_t input_amount;
  uint128_t output_amount;
} SupplyContextType;

int add_assign_amount(uint128_t* sum, const uint128_t* delta) {
  *sum += *delta;

  if (*sum < *delta) {
    return ERROR_SUPPLY_AMOUNT;
  } else {
    return 0;
  }
}

int minus_assign_amount(uint128_t* sum, const uint128_t* delta) {
  if (*sum < *delta)
    return ERROR_SUPPLY_AMOUNT;
  *sum -= *delta;
  return 0;
}

typedef int (iterate_func_t)(size_t index, size_t source, SupplyContextType* ctx);

int locate_info_cell(size_t index, size_t source, SupplyContextType* ctx) {
  if (source == CKB_SOURCE_INPUT) {
    ctx->input_info_cell_index = index;
    ctx->input_info_cell_count += 1;
    if (ctx->input_info_cell_count > 1) {
      return CKB_INVALID_DATA;
    } else {
      return 0;
    }
  } else if (source == CKB_SOURCE_OUTPUT) {
    ctx->output_info_cell_index = index;
    ctx->output_info_cell_count += 1;
    if (ctx->output_info_cell_count > 1) {
      return CKB_INVALID_DATA;
    } else {
      return 0;
    }
  } else {
    return CKB_INVALID_DATA;
  };
}

int accumulate_amount(size_t index, size_t source, SupplyContextType* ctx) {
  int err = 0;
  uint128_t amount = 0;
  uint64_t len = 16;
  err = ckb_checked_load_cell_data((uint8_t*)&amount, &len, 0, index, source);
  CHECK(err);
  if (source == CKB_SOURCE_INPUT) {
    err = add_assign_amount(&ctx->input_amount, &amount);
    CHECK(err);
  } else if (source == CKB_SOURCE_OUTPUT) {
    err = add_assign_amount(&ctx->output_amount, &amount);
    CHECK(err);
  } else {
    CHECK2(false, ERROR_SUPPLY_AMOUNT);
  }
exit:
  return err;
}

int compare_cells_data(size_t input_index, size_t output_index) {
  int err = 0;
  int err2 = 0;
  uint8_t input_version = 0;
  uint8_t output_version = 0;
  uint64_t input_len = 1;
  uint64_t output_len = 1;
  err = ckb_load_cell_data(&input_version, &input_len, 0, input_index, CKB_SOURCE_INPUT);
  CHECK(err);
  err = ckb_load_cell_data(&output_version, &output_len, 0, output_index, CKB_SOURCE_OUTPUT);
  CHECK(err);
  CHECK2(input_len == output_len, CKB_INVALID_DATA);
  CHECK2(input_len >= MIN_INFO_CELL_LEN, CKB_INVALID_DATA);
  CHECK2(input_version == output_version, CKB_INVALID_DATA);

  uint8_t input_buff[1024];
  uint8_t output_buff[1024];
  uint128_t offset = INFO_CELL_CONST_OFFSET;
  while (offset < input_len) {
    uint64_t input_read_len = sizeof(input_buff);
    uint64_t output_read_len = sizeof(output_buff);
    err = ckb_load_cell_data(input_buff, &input_read_len, offset, input_index, CKB_SOURCE_INPUT);
    err2 = ckb_load_cell_data(output_buff, &output_read_len, offset, output_index, CKB_SOURCE_OUTPUT);
    CHECK2(err == 0 && err == err2, CKB_INVALID_DATA);

    input_read_len =
        (input_read_len > sizeof(input_buff)) ? sizeof(input_buff) : input_read_len;
    output_read_len =
        (output_read_len > sizeof(input_buff)) ? sizeof(input_buff) : output_read_len;
    CHECK2(input_read_len == output_read_len, CKB_INVALID_DATA);
    int same = memcmp(input_buff, output_buff, input_read_len);
    CHECK2(same == 0, CKB_INVALID_DATA);
    offset += input_read_len;
  }

exit:
  return err;
}


int iterate_by_type_script_hash(uint8_t* hash, size_t source, iterate_func_t func, SupplyContextType* ctx) {
  int err = 0;
  size_t i = 0;
  uint8_t hash2[32] = {0};
  while (1) {
    uint64_t len = 32;
    err = ckb_load_cell_by_field(hash2, &len, 0, i, source, CKB_CELL_FIELD_TYPE_HASH);
    if (err == CKB_INDEX_OUT_OF_BOUND) {
      err = 0;
      break;
    }
    if (err == CKB_ITEM_MISSING) {
      i += 1;
      continue;
    }
    CHECK2(err == 0, err);

    if (memcmp(hash, hash2, 32) == 0) {
      err = func(i, source, ctx);
      CHECK(err);
    }
    i += 1;
  }

exit:
  return err;
}

int check_supply(uint8_t* cell_id) {
  int err = 0;
  SupplyContextType ctx = {0};
  // locate the input info cell
  err = iterate_by_type_script_hash(cell_id, CKB_SOURCE_INPUT, locate_info_cell, &ctx);
  CHECK(err);
  // locate the output info cell
  err = iterate_by_type_script_hash(cell_id, CKB_SOURCE_OUTPUT, locate_info_cell, &ctx);
  CHECK(err);
  // check input/output info cells are same beginning with special index
  err = compare_cells_data(ctx.input_info_cell_index, ctx.output_info_cell_index);
  CHECK(err);
  uint8_t info_cell[MIN_INFO_CELL_LEN] = {0};
  uint64_t info_cell_len = sizeof(info_cell);
  err = ckb_load_cell_data(info_cell, &info_cell_len, 0, ctx.input_info_cell_index, CKB_SOURCE_INPUT);
  CHECK(err);
  CHECK2(info_cell_len >= MIN_INFO_CELL_LEN, CKB_INVALID_DATA);
  ctx.version = info_cell[0];
  memcpy(&ctx.input_current_supply, info_cell + 1, 16);
  memcpy(&ctx.max_supply, info_cell + 17, 16);
  memcpy(ctx.sudt_script_hash, info_cell+ 33, 32);
  // check version
  CHECK2(ctx.version == 0, CKB_INVALID_DATA);

  info_cell_len = sizeof(info_cell);
  err = ckb_load_cell_data(info_cell, &info_cell_len, 0, ctx.output_info_cell_index, CKB_SOURCE_OUTPUT);
  CHECK(err);
  memcpy(&ctx.output_current_supply, info_cell + 1, 16);
  // check input/output current supply
  CHECK2(ctx.output_current_supply <= ctx.max_supply, ERROR_EXCEED_SUPPLY);
  CHECK2(ctx.input_current_supply <= ctx.max_supply, ERROR_EXCEED_SUPPLY);

  // collect issued amount, naively
  err = iterate_by_type_script_hash(ctx.sudt_script_hash, CKB_SOURCE_INPUT, accumulate_amount, &ctx);
  CHECK(err);
  err = iterate_by_type_script_hash(ctx.sudt_script_hash, CKB_SOURCE_OUTPUT, accumulate_amount, &ctx);
  CHECK(err);

  // issued sUDT amount is same to supply amount delta
  if (ctx.output_amount >= ctx.input_amount) {
    uint128_t issued_amount = ctx.output_amount - ctx.input_amount;
    uint128_t temp_amount = ctx.input_current_supply;
    err = add_assign_amount(&temp_amount, &issued_amount);
    CHECK(err);
    CHECK2(temp_amount == ctx.output_current_supply, ERROR_SUPPLY_AMOUNT);
  } else {
    uint128_t burned_amount = ctx.input_amount - ctx.output_amount;
    uint128_t temp_amount = ctx.input_current_supply;
    err = minus_assign_amount(&temp_amount, &burned_amount);
    CHECK(err);
    CHECK2(temp_amount == ctx.output_current_supply, ERROR_SUPPLY_AMOUNT);
  }

exit:
  return err;
}

#endif //_RC_LOCK_SUPPLY_H_
