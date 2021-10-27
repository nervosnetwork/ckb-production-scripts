

#include "compact_udt_virtual_data.h"

#include "simulator/compact_udt_cc.h"
#include "simulator/compact_udt_lock_inc.h"
#include "test_compact_udt_data.h"

//////////////////// VDCellData ///////////////////////////

void VDCellData::set_amount(uint128_t amount) {
  amount_ = amount;
}

void VDCellData::set_smt_root_hash(const CHash& hash) {
  smt_root_hash_ = hash;
}

void VDCellData::set_sudt() {
  udt_type_ = UDTType::SUDT;
}

void VDCellData::set_xudt() {
  udt_type_ = UDTType::XUDT;
}

CBuffer VDCellData::get_cell_data() {
  if (udt_type_ == UDTType::SUDT)
    return get_cell_data_sudt();
  else if (udt_type_ == UDTType::XUDT)
    return get_cell_data_xudt();

  ASSERT_DBG(false);
  return CBuffer();
}

CBuffer VDCellData::get_cell_data_sudt() {
  struct SUDT_CellData {
    uint128_t amount;
    uint32_t flag;
    Hash smt_root_hash;
  };

  CBuffer buf;
  buf.resize(sizeof(SUDT_CellData));
  SUDT_CellData* data = (SUDT_CellData*)buf.data();

  data->amount = amount_;
  data->flag = 0xFFFFFFFF;
  smt_root_hash_.copy((uint8_t*)&(data->smt_root_hash));

  return buf;
}

CBuffer VDCellData::get_cell_data_xudt() {
  ASSERT_DBG(false);
  return CBuffer();
}

//////////////////// VDScript /////////////////////////////

VDScript::VDScript(const CHash& script_hash) {
  script_code_hash_ = script_hash;
}

void VDScript::set_script_code_hash(const CHash& script) {
  script_code_hash_ = script;
}

void VDScript::set_args_version(uint8_t ver) {
  args_version_ = ver;
}

void VDScript::set_args_type_id(const CHash& type_id) {
  args_type_id_ = type_id;
}

void VDScript::set_args_identity(unique_ptr<CIdentity> id) {
  args_identity_ = move(id);
}

CHash VDScript::get_script_hash() {
  Blake2b b2b;
  b2b.Update(&script_code_hash_);
  b2b.Update(&args_version_, 1);
  b2b.Update(&args_type_id_);
  return b2b.Final();
}

CHash* VDScript::get_script_code_hash() {
  return &script_code_hash_;
}

CHash* VDScript::get_type_id() {
  return &args_type_id_;
}

CBuffer VDScript::get_args_data() {
  CBuffer ret;

  // args
  struct ARGS {
    uint8_t ver;
    Hash type_id;
    Identity identity;
  };
  if (args_identity_) {
    ret.resize(sizeof(ARGS));
  } else {
    ret.resize(sizeof(ARGS) - sizeof(Identity));
  }

  ARGS* args_data = (ARGS*)ret.data();
  args_data->ver = args_version_;
  args_type_id_.copy((uint8_t*)&(args_data->type_id));
  if (args_identity_) {
    args_identity_->copy((uint8_t*)&(args_data->identity));
  }
  return ret;
}

//////////////////// VDUser ///////////////////////////////

VDUser::VDUser(CIdentity _id, uint128_t _am)
    : id(_id), amount(_am), nonce(rand() % 200) {}

CHash VDUser::gen_smt_key() {
  CHash hash;
  id.copy((uint8_t*)hash.get());
  return hash;
}

CHash VDUser::gen_smt_val() {
  struct SMTVal {
    uint128_t amount = 0;
    uint32_t nonce = 0;
    uint8_t flag[12] = {0};
  };

  CHash h;
  SMTVal* smt_val = (SMTVal*)h.get();
  smt_val->amount = amount;
  smt_val->nonce = nonce;
  return h;
}

//////////////////// VDAllData ////////////////////////////

VDUser* VDAllData::find_user(CIdentity* id, VD_Users& users_) {
  auto it = find_if(begin(users_), end(users_),
                    [id](const VDUser& id2) { return *id == id2.id; });
  if (it == users_.end())
    return nullptr;
  else
    return &(*it);
}

VDUser* VDAllData::find_user(CIdentity* id) {
  return find_user(id, users);
}

VDUser* VDAllData::find_user_tx_ed(CIdentity* id) {
  return find_user(id, users_tx_ed);
}

CHash VDAllData::get_transfer_sign(VDTXTransfer* t, AutoSBuf* raw_buf) {
  Blake2b b;
  b.Update(input->get_type_id());

  auto user = find_user(&(t->source));
  ASSERT_DBG(user);
  b.Update(&(user->nonce), sizeof(user->nonce));

  b.Update(raw_buf->ptr(), raw_buf->len());

  return b.Final();
}

CBuffer VDAllData::gen_witness() {
  // need use mol2

  // deposit
  auto deposit_vec = cudtmol_Deposit_Vec_Init();
  for (auto it = deposit.begin(); it != deposit.end(); it++) {
    AutoSBuf source_buf(it->source->input->get_script_hash());
    AutoSBuf target_buf(it->target);
    AutoSBuf amount_buf(it->amount);
    AutoSBuf fee_buf(it->fee);
    AutoSBuf deposit_buf = cudtmol_Deposit(source_buf.get(), target_buf.get(),
                                           amount_buf.get(), fee_buf.get());
    cudtmol_VecTemplate_Push(deposit_vec, deposit_buf.ptr(), deposit_buf.len());
  }
  AutoSBuf deposit_vec_buf = cudtmol_VecTemplate_Build(deposit_vec);

  // transfer
  auto transfer_vec = cudtmol_Transfer_Vec_Init();
  for (auto it = transfer.begin(); it != transfer.end(); it++) {
    CacheTransferSourceType target_type = 0;
    unique_ptr<AutoSBuf> target_t_buf;

    if (it->target_type == TargetType_MoveBetweenCompactSMT) {
      target_type = TargetType_MoveBetweenCompactSMT;
      AutoSBuf target_in_s(it->target_cell->input->get_script_hash());
      AutoSBuf target_in_i(it->target_user);
      target_t_buf = make_unique<AutoSBuf>(
          cudtmol_MoveBetweenCompactSMT(target_in_s.get(), target_in_i.get()));
    } else if (it->target_type == TargetType_ScriptHash) {
      target_type = TargetType_ScriptHash;
      AutoSBuf target_in_buf(it->target_cell->input->get_script_hash());
      target_t_buf = make_unique<AutoSBuf>(
          cudtmol_Bytes(target_in_buf.ptr(), target_in_buf.len()));
    } else if (it->target_type == TargetType_Identity) {
      target_type = TargetType_Identity;
      AutoSBuf target_in_buf(it->target_user);
      target_t_buf = make_unique<AutoSBuf>(
          cudtmol_Bytes(target_in_buf.ptr(), target_in_buf.len()));
    } else {
      ASSERT_DBG(false);
    }

    AutoSBuf target_buf =
        cudtmol_TransferTarget(target_type, target_t_buf->get());

    AutoSBuf source_buf(it->source);
    AutoSBuf amount_buf(it->amount);
    AutoSBuf fee_buf(it->fee);

    AutoSBuf raw_buf = cudtmol_TransferRaw(source_buf.get(), target_buf.get(),
                                           amount_buf.get(), fee_buf.get());

    //

    AutoSBuf sign_hash(get_transfer_sign(&(*it), &raw_buf));
    AutoSBuf sign_buf = cudtmol_Bytes(sign_hash.ptr(), sign_hash.len());

    AutoSBuf transfer_buf = cudtmol_Transfer(raw_buf.get(), sign_buf.get());
    cudtmol_VecTemplate_Push(transfer_vec, transfer_buf.ptr(),
                             transfer_buf.len());
  }
  AutoSBuf transfer_vec_buf = cudtmol_VecTemplate_Build(transfer_vec);

  // kv_state
  auto kv_state_vec = cudtmol_KVPair_Vec_Init();

  for (auto it = users.begin(); it != users.end(); it++) {
    AutoSBuf k = it->gen_smt_key();
    AutoSBuf v = it->gen_smt_val();

    AutoSBuf kv_pair_buf = cudtmol_KVPair(k.get(), v.get());
    cudtmol_VecTemplate_Push(kv_state_vec, kv_pair_buf.ptr(),
                             kv_pair_buf.len());
  }
  AutoSBuf kv_state_vec_buf = cudtmol_VecTemplate_Build(kv_state_vec);

  // kv proof
  AutoSBuf kv_proof_buf = cudtmol_Bytes(smt_proof.data(), smt_proof.size());

  AutoSBuf cudt_buf =
      cudtmol_CompactUDTEntries(deposit_vec_buf.get(), transfer_vec_buf.get(),
                                kv_state_vec_buf.get(), kv_proof_buf.get());

  AutoSBuf witness_buf = cudtmol_Witness(NULL, cudt_buf.get(), NULL);

  return witness_buf.copy();
}

CHash VDAllData::update_smt_root_hash(VD_Users& us) {
  SMT smt;
  for (auto it = us.begin(); it != us.end(); it++) {
    auto k = it->gen_smt_key();
    auto v = it->gen_smt_val();
    smt.insert(&k, &v);
  }
  CHash h = smt.calculate_root(smt_proof);

  return h;
}

//////////////////// VirtualData ///////////////////////////

int VirtualData::run_simulator() {
  // ser
  GlobalData::get()->set_virtual_data(this);
  auto code = compact_udt_lock_main();
  GlobalData::get()->set_virtual_data(nullptr);
  return code;
}

//////////////////// GenerateTransaction /////////////////////////////////

int GenerateTransaction::add_cell(uint128_t amount,
                    const VD_Users& users,
                    bool is_cudt,
                    CBuffer proof) {
  int id = cell_count_++;

  auto cellg = make_unique<VDAllData>();

  CHash script_hash;
  if (is_cudt)
    script_hash = get_cudt_script_code_hash();
  else
    script_hash = get_other_script_code_hash();

  cellg->input = make_unique<VDScript>(script_hash);
  cellg->output = make_unique<VDScript>(script_hash);

  auto input = cellg->input.get();
  auto output = cellg->output.get();

  input->set_args_type_id(get_new_type_id());
  output->set_args_type_id(get_new_type_id());

  input->data.set_amount(amount);
  output->data.set_amount(0);

  cellg->users = users;
  cellg->smt_proof = proof;

  cells_.insert(make_pair(id, cellg.get()));
  cells_data_.emplace_back(move(cellg));

  return id;
}

void GenerateTransaction::add_transfer(int src_cell,
                         CIdentity src_user,
                         int tar_cell,
                         CIdentity tar_user,
                         uint128_t amount,
                         uint128_t fee) {
  VDTransfer transfer;
  transfer.src_cell = src_cell;
  transfer.src_user = src_user;
  transfer.tar_cell = tar_cell;
  transfer.tar_user = tar_user;
  transfer.amount = amount;
  transfer.fee = fee;

  transfers_.push_back(transfer);
}

VirtualData* GenerateTransaction::build() {
  for (auto it = cells_data_.begin(); it != cells_data_.end(); it++) {
    it->get()->users_tx_ed = it->get()->users;
  }

  gen_transfer_info();

  for (auto it = cells_data_.begin(); it != cells_data_.end(); it++) {
    {
      auto bin = make_unique<VDBinData>();
      // get input smt root hash
      it->get()->input->data.set_smt_root_hash(
          it->get()->update_smt_root_hash(it->get()->users));

      // fill scritp and cell data
      fill_scritp_data(bin.get(), it->get()->input.get());

      bin->witness = it->get()->gen_witness();

      virtual_data_.inputs.emplace_back(move(bin));
    }
    {
      auto bin = make_unique<VDBinData>();

      // get output smt root hash
      it->get()->output->data.set_smt_root_hash(
          it->get()->update_smt_root_hash(it->get()->users_tx_ed));

      fill_scritp_data(bin.get(), it->get()->output.get());
      virtual_data_.outputs.emplace_back(move(bin));
    }
  }

  return &virtual_data_;
}

void GenerateTransaction::fill_scritp_data(VDBinData* bin, VDScript* script) {
  CHash script_hash = script->get_script_hash();
  AutoSBuf sc_code(script_hash);
  auto args = script->get_args_data();
  auto args_buf = cudtmol_Bytes(args.data(), args.size());
  AutoSBuf buf = cudtmol_Script(sc_code.get(), 0, &args_buf);
  bin->script_data = buf.copy();
  bin->scritp_hash = script_hash;

  bin->cell_data = script->data.get_cell_data();
}

void GenerateTransaction::gen_transfer_info() {
  for (auto it = transfers_.begin(); it != transfers_.end(); it++) {
    auto src_cell = find(it->src_cell);
    auto tar_cell = find(it->tar_cell);
    ASSERT_DBG(src_cell);
    ASSERT_DBG(tar_cell);

    auto scr_script_code = src_cell->input->get_script_code_hash();
    auto tar_script_code = tar_cell->input->get_script_code_hash();

    ASSERT_DBG(*scr_script_code == get_cudt_script_code_hash() ||
               *tar_script_code == get_cudt_script_code_hash());

    {
      VDTXDeposit deposit;

      deposit.amount = it->amount;
      deposit.fee = it->fee;

      deposit.source = src_cell;
      deposit.target = it->tar_user;
      tar_cell->deposit.push_back(deposit);
    }
    {
      VDTXTransfer transfer;
      transfer.amount = it->amount;
      transfer.fee = it->fee;
      transfer.source = it->src_user;
      if (*scr_script_code == *tar_script_code) {
        transfer.target_cell = tar_cell;
        transfer.target_user = it->tar_user;
        transfer.target_type = TargetType_MoveBetweenCompactSMT;
      } else if (src_cell == tar_cell) {
        transfer.target_user = it->tar_user;
        transfer.target_type = TargetType_Identity;
      } else {
        transfer.target_cell = tar_cell;
        transfer.target_type = TargetType_ScriptHash;
      }

      src_cell->transfer.push_back(transfer);
    }

    auto src_user = src_cell->find_user_tx_ed(&(it->src_user));
    ASSERT_DBG(src_user);
    src_user->amount -= (it->amount + it->fee);
    src_user->nonce += 1;

    auto tar_user = tar_cell->find_user_tx_ed(&(it->tar_user));
    ASSERT_DBG(tar_user);
    tar_user->amount += (it->amount);
  }
}

VDAllData* GenerateTransaction::find(int id) {
  auto it = cells_.find(id);
  if (it == cells_.end())
    return NULL;
  return it->second;
}

//////////////////// GlobalData ////////////////////////////

GlobalData* GlobalData::get() {
  static GlobalData g;
  return &g;
}

void GlobalData::set_virtual_data(VirtualData* p) {
  virtual_data_ = p;
}
VirtualData* GlobalData::get_virtual_data() {
  return virtual_data_;
}
