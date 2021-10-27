
extern "C" {
//#include "util/update_sim_data.h"
}
#include <vector>

#include "util/utest.h"

#include "compact_udt_virtual_data.h"
#include "test_compact_udt_data.h"
#include "util/util.h"

using namespace std;

UTEST(success, main) {
  GenerateTransaction transfaction;
  gen_test_data(&transfaction);

  auto virtual_data = transfaction.build();
  ASSERT_DBG(virtual_data);

  int ret_code = virtual_data->run_simulator();
  ASSERT_DBG(!ret_code);
}

UTEST(failed_amount, cell_data) {
}

UTEST_MAIN()
