#ifndef __TESTS_COMPACT_UDT_COMPACT_UDT_VIRTUAL_DATA_H_
#define __TESTS_COMPACT_UDT_COMPACT_UDT_VIRTUAL_DATA_H_

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

class VD_AllData;

class VD_CellData {
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

class VD_Transfer {
 public:
  int src_cell = 0;
  CIdentity src_user;
  int tar_cell = 0;
  CIdentity tar_user;
  uint128_t amount = 0;
  uint128_t fee = 0;
};

class VD_Script {
 public:
  VD_Script(const CHash& script_hash);

  void set_script_code_hash(const CHash& script);
  void set_args_version(uint8_t ver);
  void set_args_type_id(const CHash& type_id);
  void set_args_identity(unique_ptr<CIdentity> id);

  CHash get_script_hash();
  CHash* get_script_code_hash();
  CHash* get_type_id();
  CBuffer get_args_data();

  VD_CellData data;

 private:
  CHash script_code_hash_;
  uint8_t args_version_ = 0;
  CHash args_type_id_;
  unique_ptr<CIdentity> args_identity_;
};

class VD_User {
 public:
  VD_User(CIdentity _id, uint128_t _am);

  CIdentity id;
  uint128_t amount = 0;
  uint32_t nonce = 0;

  CHash gen_smt_key();
  CHash gen_smt_val();
};
typedef vector<VD_User> VD_Users;

class VD_TXDeposit {
 public:
  VD_AllData* source = nullptr;
  CIdentity target;

  uint128_t amount = 0;
  uint128_t fee = 0;
};

class VD_TXTransfer {
 public:
  CIdentity source;

  VD_AllData* target_cell = nullptr;
  CIdentity target_user;
  CacheTransferSourceType target_type;

  uint128_t amount = 0;
  uint128_t fee = 0;
};

class VD_AllData {
 public:
  unique_ptr<VD_Script> input;
  unique_ptr<VD_Script> output;
  VD_Users users;
  VD_Users users_tx_ed;

  std::list<VD_TXDeposit> deposit;
  std::list<VD_TXTransfer> transfer;

  CBuffer smt_proof;

  VD_User* find_user(CIdentity* id, VD_Users& users_);
  VD_User* find_user(CIdentity* id);
  VD_User* find_user_tx_ed(CIdentity* id);
  CHash get_transfer_sign(VD_TXTransfer* t, AutoSBuf* raw_buf);
  CBuffer gen_witness();
  CHash update_smt_root_hash(VD_Users& us);
};

struct VD_BinData {
  CHash scritp_hash;
  CBuffer script_data;
  CBuffer cell_data;
  CBuffer witness;
};

class VirtualData {
 public:
  int run_simulator();

  std::list<unique_ptr<VD_BinData>> inputs, outputs;
};

class GenTx {
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
  void fill_scritp_data(VD_BinData* bin, VD_Script* script);
  void gen_transfer_info();
  VD_AllData* find(int id);

 private:
  VirtualData virtual_data_;

  map<int, VD_AllData*> cells_;
  list<unique_ptr<VD_AllData>> cells_data_;

  std::list<VD_Transfer> transfers_;

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

#endif  // __TESTS_COMPACT_UDT_COMPACT_UDT_VIRTUAL_DATA_H_
