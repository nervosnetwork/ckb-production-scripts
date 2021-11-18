
extern "C" {
//#include "util/update_sim_data.h"
}
#include <dirent.h>
#include <vector>

#include "util/utest.h"

#include "compact_udt_virtual_data.h"
#include "simulator/dump_data.h"
#include "test_compact_udt_config.h"
#include "test_compact_udt_data.h"
#include "util/util.h"

using namespace std;

bool test_one_case(string case_name) {
  auto dump_ptr = CDumpData::get();
  dump_ptr->set_data(case_name);
  bool is_success = true;
  for (int i = 0; i < CDumpData::get()->get_cell_count(); i++) {
    if (!CDumpData::get()->set_group_index(i))
      continue;
    GenerateTransaction transfaction;
    gen_test_data_single(&transfaction);

    auto virtual_data = transfaction.build();
    int ret_code = virtual_data.run_simulator();
    if (ret_code != 0) {
      is_success = false;
      break;
    }
  }

  if (dump_ptr->case_success() == is_success) {
    return true;
  } else {
    assert(false);
    return false;
  }
}

//#define _DBG_UNIT_TEST

#ifndef _DBG_UNIT_TEST

UTEST(test_data, all) {
  string test_data_dir = string(COMPACT_UDT_UNITTEST_SRC_PATH);
  auto dp = opendir(test_data_dir.c_str());
  ASSERT_DBG(dp);

  struct dirent* dirp = nullptr;
  while (true) {
    dirp = readdir(dp);
    if (!dirp)
      break;
    if (dirp->d_type != DT_REG)
      continue;
    string file_name = dirp->d_name;
    test_one_case(file_name);
  }
  closedir(dp);
}

#else   // _DBG_UNIT_TEST

UTEST(test_data, dev) {
  test_one_case("success_many_transfer.json");
}

#endif  //_DBG_UNIT_TEST

UTEST_MAIN()
