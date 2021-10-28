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
class VirtualData;
struct VDBinData;

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
  int src_cell_ = 0;
  CIdentity src_user_;
  int tar_cell_ = 0;
  CIdentity tar_user_;
  uint128_t amount_ = 0;
  uint128_t fee_ = 0;
};

class VDScript {
 public:
  VDScript(const CHash& script_hash);

  void set_script_code_hash(const CHash& script);
  void set_args_version(uint8_t ver);
  void set_args_type_id(const CHash& type_id);
  void using_identity();

  CHash get_script_hash();
  CHash* get_script_code_hash();
  CHash* get_type_id();
  CBuffer get_args_data();
  CKBKey* get_key();

  VDCellData data_;

 private:
  CHash script_code_hash_;
  uint8_t args_version_ = 0;
  CHash args_type_id_;
  unique_ptr<CKBKey> ckb_key_;
};

class VDUser {
 public:
  VDUser(CIdentity _id, CHash privkey, uint128_t _am);

  CIdentity id_;
  CHash privkey_;
  uint128_t amount_ = 0;
  uint32_t nonce_ = 0;

  CHash gen_smt_key();
  CHash gen_smt_val();
};
typedef vector<VDUser> VDUsers;

class VDTXDeposit {
 public:
  VDAllData* source_ = nullptr;
  CIdentity target_;

  uint128_t amount_ = 0;
  uint128_t fee_ = 0;
};

class VDTXTransfer {
 public:
  CIdentity source_;

  VDAllData* target_cell_ = nullptr;
  CIdentity target_user_;
  CacheTransferSourceType target_type_;

  uint128_t amount_ = 0;
  uint128_t fee_ = 0;
};

class VDAllData {
 public:
  unique_ptr<VDScript> input_;
  unique_ptr<VDScript> output_;
  VDUsers users_;
  VDUsers users_tx_ed_;

  std::list<VDTXDeposit> deposit_;
  std::list<VDTXTransfer> transfer_;

  CBuffer smt_proof_;

  VDUser* find_user(CIdentity* id, VDUsers& users_);
  VDUser* find_user(CIdentity* id);
  VDUser* find_user_tx_ed(CIdentity* id);
  CHash get_transfer_hash(VDTXTransfer* t, AutoSBuf* raw_buf);
  CBuffer get_transfer_sign(CHash* msg);
  CBuffer gen_signature(VirtualData* vd, VDBinData* cur_bin);
  CBuffer gen_witness(bool empty_sign, VirtualData* vd, VDBinData* cur_bin);
  CHash update_smt_root_hash(VDUsers& us);
};

struct VDBinData {
  CHash scritp_hash_;
  CBuffer script_data_;
  CBuffer cell_data_;
  CBuffer witness_;
};

class VirtualData {
 public:
  int run_simulator();

  std::list<unique_ptr<VDBinData>> inputs_, outputs_;
};

class GenerateTransaction {
 public:
  struct AddCellArgs {
    uint128_t amount = 0;
    VDUsers users;
    CBuffer proof;
    bool use_cudt_lock = true;
    bool use_xudt = false;

    CHash input_type_id, output_type_id;
  };
  int add_cell(const AddCellArgs& args);

  void add_transfer(int src_cell,
                    CIdentity src_user,
                    int tar_cell,
                    CIdentity tar_user,
                    uint128_t amount,
                    uint128_t fee);
  VirtualData build();

 private:
  void fill_scritp_data(VDBinData* bin, VDScript* script);
  void gen_transfer_info();
  VDAllData* find(int id);

 public:
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
