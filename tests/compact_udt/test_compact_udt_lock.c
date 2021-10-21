

#include "compact_udt_lock.h"
#include "util/ckb_syscall_cudt_sim.h"
#include "util/utest.h"
#include "util/util.h"

#include <assert.h>

UTEST(args, main) {
  // cell data
  uint8_t data_smt_hash[32];
  hex2bin(data_smt_hash, "");
  sim_set_data(SIM_TYPE_SCRIPT_SUDT, 1000, data_smt_hash);
  
  // args
  uint8_t args_type_id[32] = {0};
  uint8_t args_identy[21] = {0};
  hex2bin(args_type_id, "0120203040506070809");
  hex2bin(args_identy, "0120203040506070809");

  sim_set_args(0, args_type_id, args_identy);

  // witnesses
  
  sim_set_witness();

  start_cudt();
}

/*
UTEST(args, version_failed) {
  uint8_t args_type_id[32] = {0};
  uint8_t args_identy[21] = {0};
  hex2bin(args_type_id, "");
  hex2bin(args_identy, "");

  sim_set_args(2, args_type_id, args_identy);

  assert(start_cudt() == CKBERR_INVALID_VERSION);
}
*/

UTEST_MAIN()
