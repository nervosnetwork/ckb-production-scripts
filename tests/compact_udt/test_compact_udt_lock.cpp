
extern "C" {
//#include "util/update_sim_data.h"
}
#include <dirent.h>
#include <vector>

#include "util/utest.h"

#include "compact_udt_virtual_data.h"
#include "simulator/dump_data.h"
#include "test_compact_udt_data.h"
#include "util/util.h"

using namespace std;

/*
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
*/

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

/*
UTEST(test_data, all) {
  string test_data_dir = string(COMPACT_UDT_UNITTEST_SRC_PATH) +
                         string("/../compact_udt_rust/test_data/");
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

    auto dump_ptr = CDumpData::get();
    dump_ptr->set_data(file_name);

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
    if (dump_ptr->case_success()) {
      ASSERT_DBG(is_success);
    } else {
      ASSERT_DBG(!is_success);
    }
  }
  closedir(dp);
}
*/

UTEST(test_data, all) {
  auto dump_ptr = CDumpData::get();
  dump_ptr->set_data("failed_amount_overflow.json");

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

  if (dump_ptr->case_success()) {
    ASSERT_DBG(is_success);
  } else {
    ASSERT_DBG(!is_success);
  }
}

UTEST_MAIN()
