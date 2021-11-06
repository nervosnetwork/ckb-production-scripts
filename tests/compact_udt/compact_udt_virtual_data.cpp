

#include "compact_udt_virtual_data.h"

#include "simulator/compact_udt_cc.h"
#include "simulator/compact_udt_lock_inc.h"

//#include "debug.h"

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
  AutoSBuf lock_buf = cudtmol_Bytes(smt_root_hash_.get(), smt_root_hash_.len());

  size_t data_size = 2;

  vector<AutoSBuf> data_buf;
  vector<SBuffer*> data_ptr_buf;
  for (size_t i = 0; i < data_size; i++) {
    data_buf.push_back(cudtmol_Bytes(CHash::srand_fill().get(), CHash::len()));
  }
  for (size_t i = 0; i < data_size; i++) {
    data_ptr_buf.push_back(data_buf[i].get());
  }
  AutoSBuf buf = cudtmol_bytes_vec(data_ptr_buf.data(), data_ptr_buf.size());
  AutoSBuf xudt_data_buf = cudtmol_xudtdata(lock_buf.get(), buf.get());

  //AutoSBuf xudt_byte_buf = cudtmol_Bytes(xudt_data_buf.ptr(), xudt_data_buf.len());
  CBuffer ret_buf;
  ret_buf.resize(sizeof(uint128_t) + xudt_data_buf.len());
  memcpy(ret_buf.data(), &amount_, sizeof(uint128_t));
  memcpy(ret_buf.data() + sizeof(uint128_t), xudt_data_buf.ptr(), xudt_data_buf.len());

  return ret_buf;
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

void VDScript::using_identity() {
  ckb_key_ = make_unique<CKBKey>();
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
  if (ckb_key_) {
    ret.resize(sizeof(ARGS));
  } else {
    ret.resize(sizeof(ARGS) - sizeof(Identity));
  }

  ARGS* args_data = (ARGS*)ret.data();
  args_data->ver = args_version_;
  args_type_id_.copy((uint8_t*)&(args_data->type_id));
  if (ckb_key_) {
    ckb_key_->get_pubkey_hash().copy((uint8_t*)&(args_data->identity));
  }
  return ret;
}

CKBKey* VDScript::get_key() {
  return ckb_key_.get();
}

//////////////////// VDUser ///////////////////////////////

VDUser::VDUser(CIdentity _id, CHash privkey, uint128_t _am)
    : id_(_id), privkey_(privkey), amount_(_am), nonce_(rand() % 200) {}

CHash VDUser::gen_smt_key() {
  CHash hash;
  id_.copy((uint8_t*)hash.get());
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
  smt_val->amount = amount_;
  smt_val->nonce = nonce_;
  return h;
}

//////////////////// VDAllData ////////////////////////////

VDUser* VDAllData::find_user(CIdentity* id, VDUsers& users_) {
  auto it = find_if(begin(users_), end(users_),
                    [id](const VDUser& id2) { return *id == id2.id_; });
  if (it == users_.end())
    return nullptr;
  else
    return &(*it);
}

VDUser* VDAllData::find_user(CIdentity* id) {
  return find_user(id, users_);
}

VDUser* VDAllData::find_user_tx_ed(CIdentity* id) {
  return find_user(id, users_tx_ed_);
}

CHash VDAllData::get_transfer_hash(VDTXTransfer* t, AutoSBuf* raw_buf) {
  Blake2b b;
  b.Update(input_->get_type_id());

  auto user = find_user(&(t->source_));
  ASSERT_DBG(user);
  b.Update(&(user->nonce_), sizeof(user->nonce_));

  b.Update(raw_buf->ptr(), raw_buf->len());

  return b.Final();
}

CBuffer VDAllData::get_transfer_sign(CHash* msg) {
  auto key = input_->get_key();
  ASSERT_DBG(key);
  return key->signature(msg);
}

namespace {
class SigHash {
 public:
  SigHash(VirtualData* vd, VDBinData* cur_bin) : vd_(vd), cur_bin_(cur_bin) {}

 private:
  bool get_witness(uint8_t* buf,
                   uint64_t& len,
                   uint64_t offset,
                   uint64_t index,
                   bool all,
                   bool& is_out_of) {
    if (index > 0 && !all) {
      is_out_of = true;
      return false;
    }

    VDBinData* bin;
    if (all) {
      auto it = vd_->inputs_.begin();
      advance(it, index);
      if (it == vd_->inputs_.end()) {
        is_out_of = true;
        return false;
      }
      bin = it->get();
    } else {
      bin = cur_bin_;
    }

    uint64_t size = bin->witness_.size();
    len = len < size - offset ? len : size - offset;

    memcpy(buf, &bin->witness_[offset], len);
    return true;
  }

  CHash get_tx_hash() { return CHash(); }

  int calculate_inputs_len() { return 1; }

  struct MolSegT {
    uint8_t* ptr;
    uint64_t size;
  };

  bool extract_witness_lock(uint8_t* witness,
                            uint64_t len,
                            MolSegT* lock_bytes_seg) {
    if (len < 20) {
      return false;
    }
    uint32_t lock_length = *((uint32_t*)(&witness[16]));
    if (len < 20 + lock_length) {
      return false;
    } else {
      lock_bytes_seg->ptr = &witness[20];
      lock_bytes_seg->size = lock_length;
    }
    return true;
  }

  bool load_and_hash_witness(Blake2b* ctx,
                             size_t start,
                             size_t index,
                             bool all,
                             bool hash_length,
                             bool& is_out_of) {
    uint8_t temp[ONE_BATCH_SIZE] = {0};
    uint64_t len = ONE_BATCH_SIZE;

    auto ret = get_witness(temp, len, start, index, all, is_out_of);
    if (!ret) {
      return false;
    }

    if (hash_length) {
      ctx->Update((uint8_t*)&len, sizeof(uint64_t));
    }
    uint64_t offset = (len > ONE_BATCH_SIZE) ? ONE_BATCH_SIZE : len;
    ctx->Update(temp, offset);
    while (offset < len) {
      uint64_t current_len = ONE_BATCH_SIZE;
      ret =
          get_witness(temp, current_len, start + offset, index, all, is_out_of);
      if (!ret) {
        return false;
      }
      uint64_t current_read =
          (current_len > ONE_BATCH_SIZE) ? ONE_BATCH_SIZE : current_len;
      ctx->Update(temp, current_read);
      offset += current_read;
    }
    return true;
  }

 public:
  CHash generate_sighash_all() {
    uint8_t temp[MAX_WITNESS_SIZE] = {0};

    uint64_t read_len = MAX_WITNESS_SIZE;
    uint64_t witness_len = MAX_WITNESS_SIZE;

    // Load witness of first input
    bool is_out_of = false;
    auto ret = get_witness(temp, read_len, 0, 0, false, is_out_of);
    if (!ret) {
      ASSERT_DBG(false);
      return CHash();
    }

    witness_len = read_len;
    if (read_len > MAX_WITNESS_SIZE) {
      read_len = MAX_WITNESS_SIZE;
    }

    // load signature
    MolSegT lock_bytes_seg;
    ret = extract_witness_lock(temp, read_len, &lock_bytes_seg);
    if (!ret) {
      ASSERT_DBG(false);
      return CHash();
    }

    // Prepare sign message
    Blake2b ctx;

    // Load tx hash
    auto tx_hash = get_tx_hash();
    ctx.Update(&tx_hash);

    // Clear lock field to zero, then digest the first witness
    // lock_bytes_seg.ptr actually points to the memory in temp buffer
    memset((void*)lock_bytes_seg.ptr, 0, lock_bytes_seg.size);
    ctx.Update((uint8_t*)&witness_len, sizeof(uint64_t));
    ctx.Update(temp, read_len);

    // remaining of first witness
    if (read_len < witness_len) {
      ret = load_and_hash_witness(&ctx, read_len, 0, false, false, is_out_of);
      if (!ret) {
        ASSERT_DBG(false);
        return CHash();
      }
    }

    // Digest same group witnesses
    size_t i = 1;
    while (1) {
      ret = load_and_hash_witness(&ctx, 0, i, false, true, is_out_of);
      if (is_out_of) {
        break;
      }
      if (!ret) {
        ASSERT_DBG(false);
        return CHash();
      }
      i += 1;
    }

    // Digest witnesses that not covered by inputs
    /*
    i = (size_t)calculate_inputs_len();
    is_out_of = false;
    while (1) {
      ret = load_and_hash_witness(&ctx, 0, i, true, true, is_out_of);
      if (is_out_of) {
        break;
      }
      if (!ret) {
        ASSERT_DBG(false);
        return CHash();
      }
      i += 1;
    }
    */

    return ctx.Final();
  }

 private:
  VirtualData* vd_ = nullptr;
  VDBinData* cur_bin_ = nullptr;
};
}  // namespace

CBuffer VDAllData::gen_signature(VirtualData* vd, VDBinData* cur_bin) {
  CBuffer ret;
  SigHash sig_hash(vd, cur_bin);
  auto msg = sig_hash.generate_sighash_all();

  auto k = input_->get_key();
  ret = k->signature(&msg);
  return ret;
}

CBuffer VDAllData::gen_witness(bool empty_sign,
                               VirtualData* vd,
                               VDBinData* cur_bin) {
  // deposit
  auto deposit_vec = cudtmol_Deposit_Vec_Init();
  for (auto it = deposit_.begin(); it != deposit_.end(); it++) {
    AutoSBuf source_buf(it->source_->input_->get_script_hash());
    AutoSBuf target_buf(it->target_);
    AutoSBuf amount_buf(it->amount_);
    AutoSBuf fee_buf(it->fee_);
    AutoSBuf deposit_buf = cudtmol_Deposit(source_buf.get(), target_buf.get(),
                                           amount_buf.get(), fee_buf.get());
    cudtmol_VecTemplate_Push(deposit_vec, deposit_buf.ptr(), deposit_buf.len());
  }
  AutoSBuf deposit_vec_buf = cudtmol_VecTemplate_Build(deposit_vec);

  // transfer
  auto transfer_vec = cudtmol_Transfer_Vec_Init();
  for (auto it = transfer_.begin(); it != transfer_.end(); it++) {
    CacheTransferSourceType target_type = 0;
    unique_ptr<AutoSBuf> target_t_buf;

    if (it->target_type_ == TargetType_MoveBetweenCompactSMT) {
      target_type = TargetType_MoveBetweenCompactSMT;
      AutoSBuf target_in_s(it->target_cell_->input_->get_script_hash());
      AutoSBuf target_in_i(it->target_user_);
      target_t_buf = make_unique<AutoSBuf>(
          cudtmol_MoveBetweenCompactSMT(target_in_s.get(), target_in_i.get()));
    } else if (it->target_type_ == TargetType_ScriptHash) {
      target_type = TargetType_ScriptHash;
      target_t_buf =
          make_unique<AutoSBuf>(it->target_cell_->input_->get_script_hash());
    } else if (it->target_type_ == TargetType_Identity) {
      target_type = TargetType_Identity;
      AutoSBuf target_in_buf(it->target_user_);
      target_t_buf = make_unique<AutoSBuf>(
          cudtmol_Bytes(target_in_buf.ptr(), target_in_buf.len()));
    } else {
      ASSERT_DBG(false);
    }

    AutoSBuf target_buf =
        cudtmol_TransferTarget(target_type, target_t_buf->get());

    AutoSBuf source_buf(it->source_);
    AutoSBuf amount_buf(it->amount_);
    AutoSBuf fee_buf(it->fee_);

    AutoSBuf raw_buf = cudtmol_TransferRaw(source_buf.get(), target_buf.get(),
                                           amount_buf.get(), fee_buf.get());

    // signature
    CBuffer signature_buf;
    auto user = find_user(&it->source_);
    ASSERT_DBG(user);

    CKBKey key(user->privkey_);
    CHash transfer_msg = get_transfer_hash(&(*it), &raw_buf);
    signature_buf = key.signature(&transfer_msg);
    AutoSBuf sign_buf =
        cudtmol_Bytes(signature_buf.data(), signature_buf.size());

    AutoSBuf transfer_buf = cudtmol_Transfer(raw_buf.get(), sign_buf.get());
    cudtmol_VecTemplate_Push(transfer_vec, transfer_buf.ptr(),
                             transfer_buf.len());
  }
  AutoSBuf transfer_vec_buf = cudtmol_VecTemplate_Build(transfer_vec);

  // kv_state
  auto kv_state_vec = cudtmol_KVPair_Vec_Init();

  for (auto it = users_.begin(); it != users_.end(); it++) {
    AutoSBuf k = it->gen_smt_key();
    AutoSBuf v = it->gen_smt_val();

    AutoSBuf kv_pair_buf = cudtmol_KVPair(k.get(), v.get());
    cudtmol_VecTemplate_Push(kv_state_vec, kv_pair_buf.ptr(),
                             kv_pair_buf.len());
  }
  AutoSBuf kv_state_vec_buf = cudtmol_VecTemplate_Build(kv_state_vec);

  // kv proof
  AutoSBuf kv_proof_buf = cudtmol_Bytes(smt_proof_.data(), smt_proof_.size());

  // signature
  unique_ptr<AutoSBuf> sign_buf;
  if (input_->get_key()) {
    if (empty_sign) {
      CBuffer zero_buf;
      zero_buf.resize(65);
      SBuffer sign_sbuf;
      sign_sbuf.buf = zero_buf.data();
      sign_sbuf.len = zero_buf.size();
      sign_buf = make_unique<AutoSBuf>(cudtmol_OptSignature(&sign_sbuf));
    } else {
      auto temp_buf1 = gen_signature(vd, cur_bin);
      ASSERT_DBG(!temp_buf1.empty());

      SBuffer sbuf{temp_buf1.data(), (uint32_t)temp_buf1.size()};
      sign_buf = make_unique<AutoSBuf>(cudtmol_OptSignature(&sbuf));
    }
  }

  AutoSBuf cudt_buf = cudtmol_CompactUDTEntries(
      deposit_vec_buf.get(), transfer_vec_buf.get(), kv_state_vec_buf.get(),
      kv_proof_buf.get(), sign_buf->get());

  AutoSBuf witness_buf = cudtmol_Witness(cudt_buf.get(), NULL, NULL);

  return witness_buf.copy();
}

CHash VDAllData::update_smt_root_hash(VDUsers& us) {
  SMT smt;
  for (auto it = us.begin(); it != us.end(); it++) {
    auto k = it->gen_smt_key();
    auto v = it->gen_smt_val();
    smt.insert(&k, &v);
  }
  CHash h = smt.calculate_root(smt_proof_);

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

namespace {
CHash get_cudt_script_code_hash() {
  CBuffer v00 = {
      0x31, 0x04, 0x27, 0xBB, 0xEB, 0xCD, 0x6C, 0xB6, 0xDD, 0x1B, 0xDC,
      0x77, 0x20, 0xB2, 0x7C, 0x91, 0x4A, 0x14, 0xE6, 0x8E, 0xF8, 0xB2,
      0xAF, 0x66, 0xBA, 0x0E, 0x9B, 0x5C, 0xB4, 0xFB, 0xF0, 0xC3,
  };
  return v00;
}
CHash get_other_script_code_hash() {
  CBuffer v00 = {
      0x5F, 0xEB, 0x73, 0x0B, 0xEC, 0x5F, 0x9C, 0x0B, 0x4F, 0x20, 0x92,
      0x78, 0xFB, 0x23, 0xB7, 0x2E, 0xF6, 0xAE, 0xCF, 0x05, 0xB0, 0x54,
      0x20, 0x6A, 0x13, 0x74, 0x4A, 0x6C, 0x79, 0xA7, 0x76, 0x08,
  };
  return v00;
}
}  // namespace

int GenerateTransaction::add_cell(const AddCellArgs& args) {
  int id = cell_count_++;

  auto cellg = make_unique<VDAllData>();

  CHash script_hash;
  if (args.use_cudt_lock)
    script_hash = get_cudt_script_code_hash();
  else
    script_hash = get_other_script_code_hash();

  cellg->input_ = make_unique<VDScript>(script_hash);
  cellg->output_ = make_unique<VDScript>(script_hash);

  auto input = cellg->input_.get();
  auto output = cellg->output_.get();

  input->set_args_type_id(args.input_type_id);
  output->set_args_type_id(args.output_type_id);

  input->data_.set_amount(args.amount);
  output->data_.set_amount(0);

  input->using_identity();

  if (args.use_xudt) {
    input->data_.set_xudt();
    output->data_.set_xudt();
  }

  cellg->users_ = args.users;
  cellg->smt_proof_ = args.proof;

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
  transfer.src_cell_ = src_cell;
  transfer.src_user_ = src_user;
  transfer.tar_cell_ = tar_cell;
  transfer.tar_user_ = tar_user;
  transfer.amount_ = amount;
  transfer.fee_ = fee;

  transfers_.push_back(transfer);
}

VirtualData GenerateTransaction::build() {
  VirtualData vd;
  for (auto it = cells_data_.begin(); it != cells_data_.end(); it++) {
    it->get()->users_tx_ed_ = it->get()->users_;
  }

  gen_transfer_info();

  for (auto it = cells_data_.begin(); it != cells_data_.end(); it++) {
    {
      auto bin = make_unique<VDBinData>();
      // get input smt root hash
      it->get()->input_->data_.set_smt_root_hash(
          it->get()->update_smt_root_hash(it->get()->users_));

      // fill scritp and cell data
      fill_scritp_data(bin.get(), it->get()->input_.get());

      bin->witness_ = it->get()->gen_witness(true, nullptr, nullptr);

      vd.inputs_.emplace_back(move(bin));
    }
    {
      auto bin = make_unique<VDBinData>();

      // get output smt root hash
      it->get()->output_->data_.set_smt_root_hash(
          it->get()->update_smt_root_hash(it->get()->users_tx_ed_));

      fill_scritp_data(bin.get(), it->get()->output_.get());
      vd.outputs_.emplace_back(move(bin));
    }
  }

  // signature
  auto it = cells_data_.begin();
  auto it_bin = vd.inputs_.begin();
  for (; it != cells_data_.end(); it++, it_bin++) {
    it_bin->get()->witness_ = it->get()->gen_witness(false, &vd, it_bin->get());
  }

  return vd;
}

void GenerateTransaction::fill_scritp_data(VDBinData* bin, VDScript* script) {
  CHash script_hash = script->get_script_hash();
  AutoSBuf sc_code(script_hash);
  auto args = script->get_args_data();
  auto args_buf = cudtmol_Bytes(args.data(), args.size());
  AutoSBuf buf = cudtmol_Script(sc_code.get(), 0, &args_buf);
  bin->script_data_ = buf.copy();
  bin->scritp_hash_ = script_hash;

  bin->cell_data_ = script->data_.get_cell_data();
}

void GenerateTransaction::gen_transfer_info() {
  for (auto it = transfers_.begin(); it != transfers_.end(); it++) {
    auto src_cell = find(it->src_cell_);
    auto tar_cell = find(it->tar_cell_);
    ASSERT_DBG(src_cell);
    ASSERT_DBG(tar_cell);

    auto scr_script_code = src_cell->input_->get_script_code_hash();
    auto tar_script_code = tar_cell->input_->get_script_code_hash();

    ASSERT_DBG(*scr_script_code == get_cudt_script_code_hash() ||
               *tar_script_code == get_cudt_script_code_hash());

    {
      VDTXDeposit deposit;

      deposit.amount_ = it->amount_;
      deposit.fee_ = it->fee_;

      deposit.source_ = src_cell;
      deposit.target_ = it->tar_user_;
      tar_cell->deposit_.push_back(deposit);
    }
    {
      VDTXTransfer transfer;
      transfer.amount_ = it->amount_;
      transfer.fee_ = it->fee_;
      transfer.source_ = it->src_user_;
      if (*scr_script_code == *tar_script_code && tar_cell != src_cell) {
        transfer.target_cell_ = tar_cell;
        transfer.target_user_ = it->tar_user_;
        transfer.target_type_ = TargetType_MoveBetweenCompactSMT;
      } else if (src_cell == tar_cell) {
        transfer.target_user_ = it->tar_user_;
        transfer.target_type_ = TargetType_Identity;
      } else {
        transfer.target_cell_ = tar_cell;
        transfer.target_type_ = TargetType_ScriptHash;
      }

      src_cell->transfer_.push_back(transfer);
    }

    auto src_user = src_cell->find_user_tx_ed(&(it->src_user_));
    ASSERT_DBG(src_user);
    src_user->amount_ -= (it->amount_ + it->fee_);
    src_user->nonce_ += 1;

    auto tar_user = tar_cell->find_user_tx_ed(&(it->tar_user_));
    ASSERT_DBG(tar_user);
    tar_user->amount_ += (it->amount_);
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
