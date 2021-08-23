#ifndef _RC_LOCK_SUPPLY_H_
#define _RC_LOCK_SUPPLY_H_
#include "ckb_syscalls.h"

typedef unsigned __int128 uint128_t;

enum SupplyErrorCode {
  ERROR_EXCEED_SUPPLY = 90,
};

int check_supply(uint8_t* cell_id) {
  int err = 0;
  size_t index = 0;
  err = ckb_look_for_dep_with_hash2(cell_id, 1, &index);
  CHECK(err);

  uint8_t supply_info[33];
  uint64_t len = sizeof(supply_info);
  err = ckb_checked_load_cell_data(supply_info, &len, 0, index, CKB_SOURCE_CELL_DEP);
  CHECK(err);
  uint128_t current_supply = 0;
  uint128_t max_supply = 0;
  uint8_t version = 0;
  version = supply_info[0];
  memcpy(&current_supply, supply_info+1, 16);
  memcpy(&max_supply, supply_info+17, 16);
  CHECK2(version == 0, CKB_INVALID_DATA);
  CHECK2(current_supply <= max_supply, ERROR_EXCEED_SUPPLY);

exit:
  return err;
}

#endif //_RC_LOCK_SUPPLY_H_
