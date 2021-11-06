
extern "C" {
//#include "util/update_sim_data.h"
}
#include <vector>

#include "util/utest.h"

#include "compact_udt_virtual_data.h"
#include "simulator/dump_data.h"
#include "test_compact_udt_data.h"
#include "util/util.h"

using namespace std;

UTEST(success, main) {
  GenerateTransaction transfaction;
  gen_test_data(&transfaction);

  auto virtual_data = transfaction.build();
  int ret_code = virtual_data.run_simulator();
  ASSERT_DBG(!ret_code);
}

UTEST(success, none_identity) {
  GenerateTransaction transfaction;
  gen_test_data(&transfaction);

  auto virtual_data = transfaction.build();
  int ret_code = virtual_data.run_simulator();
  ASSERT_DBG(!ret_code);
}

UTEST(success, single_cell) {
  GenerateTransaction transfaction;
  gen_test_data_single(&transfaction);

  auto virtual_data = transfaction.build();
  int ret_code = virtual_data.run_simulator();
  ASSERT_DBG(!ret_code);
}

/*
UTEST(rust_failed, dev) {
  for (int i = 0; i < CDumpData::get()->get_cell_count(); i++) {
    if (!CDumpData::get()->set_group_index(i))
      continue;
    GenerateTransaction transfaction;
    gen_test_data_single(&transfaction);

    auto virtual_data = transfaction.build();
    int ret_code = virtual_data.run_simulator();
    ASSERT_DBG(!ret_code);
  }
}
*/

UTEST_MAIN()
