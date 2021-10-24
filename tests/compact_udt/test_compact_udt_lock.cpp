
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
  GenTx tx;
  GenTestData(&tx);
  auto vd = tx.build();
  ASSERT_DBG(vd);
  int ret_code = vd->run_simulator();
  ASSERT_DBG(!ret_code);
}

UTEST_MAIN()
