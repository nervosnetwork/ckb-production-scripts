#ifndef _TESTS_COMPACT_UDT_COMPACT_UDT_VIRTUAL_DATA_H_
#define _TESTS_COMPACT_UDT_COMPACT_UDT_VIRTUAL_DATA_H_

#ifdef __cplusplus
extern "C" {
#endif  // __cplusplus

#include "compact_udt_lock.h"

#include <stdint.h>
#include <string.h>

#ifdef __cplusplus
}  // extern "C"
#endif  // __cplusplus

#include <algorithm>
#include <list>
#include <map>
#include <memory>
#include <vector>
#include "util/util.h"

class VDAllData;

class VDCellData {
 public:
  void set_amount(uint128_t amount);
  void set_smt_root_hash(const CHash& hash);

  enum class UDTType {
    SUDT,
    XUDT,
  };
  void set_sudt();
  void set_xudt();

  CBuffer get_cell_data();

 private:
  CBuffer get_cell_data_sudt();
  CBuffer get_cell_data_xudt();

 private:
  uint128_t amount_ = 0;
  CHash smt_root_hash_;
  UDTType udt_type_ = UDTType::SUDT;
};

class VDTransfer {
 public:
  int src_cell = 0;
  CIdentity src_user;
  int tar_cell = 0;
  CIdentity tar_user;
  uint128_t amount = 0;
  uint128_t fee = 0;
};

class VDScript {
 public:
  VDScript(const CHash& script_hash);

  void set_script_code_hash(const CHash& script);
  void set_args_version(uint8_t ver);
  void set_args_type_id(const CHash& type_id);
  void set_args_identity(unique_ptr<CIdentity> id);

  CHash get_script_hash();
  CHash* get_script_code_hash();
  CHash* get_type_id();
  CBuffer get_args_data();

  VDCellData data;

 private:
  CHash script_code_hash_;
  uint8_t args_version_ = 0;
  CHash args_type_id_;
  unique_ptr<CIdentity> args_identity_;
};

class VDUser {
 public:
  VDUser(CIdentity _id, uint128_t _am);

  CIdentity id;
  uint128_t amount = 0;
  uint32_t nonce = 0;

  CHash gen_smt_key();
  CHash gen_smt_val();
};
typedef vector<VDUser> VD_Users;

class VDTXDeposit {
 public:
  VDAllData* source = nullptr;
  CIdentity target;

  uint128_t amount = 0;
  uint128_t fee = 0;
};

class VDTXTransfer {
 public:
  CIdentity source;

  VDAllData* target_cell = nullptr;
  CIdentity target_user;
  CacheTransferSourceType target_type;

  uint128_t amount = 0;
  uint128_t fee = 0;
};

class VDAllData {
 public:
  unique_ptr<VDScript> input;
  unique_ptr<VDScript> output;
  VD_Users users;
  VD_Users users_tx_ed;

  std::list<VDTXDeposit> deposit;
  std::list<VDTXTransfer> transfer;

  CBuffer smt_proof;

  VDUser* find_user(CIdentity* id, VD_Users& users_);
  VDUser* find_user(CIdentity* id);
  VDUser* find_user_tx_ed(CIdentity* id);
  CHash get_transfer_sign(VDTXTransfer* t, AutoSBuf* raw_buf);
  CBuffer gen_witness();
  CHash update_smt_root_hash(VD_Users& us);
};

struct VDBinData {
  CHash scritp_hash;
  CBuffer script_data;
  CBuffer cell_data;
  CBuffer witness;
};

class VirtualData {
 public:
  int run_simulator();

  std::list<unique_ptr<VDBinData>> inputs, outputs;
};

class GenerateTransaction {
 public:
  int add_cell(uint128_t amount,
               const VD_Users& users,
               bool is_cudt,
               CBuffer proof);

  void add_transfer(int src_cell,
                    CIdentity src_user,
                    int tar_cell,
                    CIdentity tar_user,
                    uint128_t amount,
                    uint128_t fee);
  VirtualData* build();

 private:
  void fill_scritp_data(VDBinData* bin, VDScript* script);
  void gen_transfer_info();
  VDAllData* find(int id);

 private:
  VirtualData virtual_data_;

  map<int, VDAllData*> cells_;
  list<unique_ptr<VDAllData>> cells_data_;

  std::list<VDTransfer> transfers_;

  int cell_count_ = 0;
};

class GlobalData {
 private:
  GlobalData(){};

 public:
  static GlobalData* get();

  void set_virtual_data(VirtualData* p);
  VirtualData* get_virtual_data();

 private:
  VirtualData* virtual_data_ = NULL;

 public:
};

#endif  // _TESTS_COMPACT_UDT_COMPACT_UDT_VIRTUAL_DATA_H_
