
#include "compact_udt_lock.h"

#include "compact_udt_lock_reader.h"

uint8_t g_tx_buffer[1024 * 32];
uint32_t g_tx_buffer_malloced_len = 0;

void* alloc_cache(uint32_t len) {
  // need 16 byte alignment
  if (len % 16 != 0) {
    len = (len / 16 + 1) * 16;
  }

  if (g_tx_buffer_malloced_len + len > sizeof(g_tx_buffer)) {
    ASSERT_DBG(false);
    ckb_exit(CKBERR_UNKNOW);
    return NULL;
  }
  void* p = g_tx_buffer + g_tx_buffer_malloced_len;
  memset(p, 0, len);
  g_tx_buffer_malloced_len += len;
  return p;
}

void clear_cache() {
  g_tx_buffer_malloced_len = 0;
  memset(g_tx_buffer, 0, sizeof(g_tx_buffer));
}

typedef struct _CacheDeposit {
  Hash* source;
  Identity target;
  uint128_t amount;
  uint128_t fee;

  struct _CacheDeposit* next;
} CacheDeposit;

typedef struct _CacheMoveBetweenCompactSMT {
  Hash script_hash;
  Identity identity;
} CacheMoveBetweenCompactSMT;

typedef struct _CacheTransfer {
  Identity source;

  // need hash type:
  CacheTransferSourceType target_type;
  uint8_t* target;

  uint128_t amount;
  uint128_t fee;

  struct _CacheTransfer* next;
} CacheTransfer;

typedef struct _CacheData {
  Hash script_hash;
  uint128_t input_amount;
  uint128_t output_amount;

  CacheDeposit* deposits;
  CacheTransfer* transfers;

  struct _CacheData* next;
} CacheData;

typedef struct _CacheKeyPair {
  Identity identity;
  uint8_t buffer[11];
} CacheKeyPair;

typedef struct _CacheValPair {
  uint128_t amount;
  uint32_t nonce;
  uint8_t buffer[12];
} CacheValPair;

typedef struct _CacheKVPair {
  CacheKeyPair key;
  CacheValPair value;
} CacheKVPair;

typedef struct _Cache {
  TypeID type_id;
  Identity* identity;

  CacheData* other_data;

  CacheData cur_data;
  Hash input_smt_hash;
  Hash output_smt_hash;

  CacheKVPair* kv_pairs;
  uint32_t kv_pairs_len;

  uint8_t* kv_proof;
  uint32_t kv_proof_len;

} Cache;
Cache* g_cudt_cache;

CKBResCode check_script_unique() {
  uint64_t len = 0;
  int ret_code = ckb_load_cell_data(NULL, &len, 0, 1, CKB_SOURCE_GROUP_INPUT);
  if (ret_code != CKB_INDEX_OUT_OF_BOUND) {
    return CUDTERR_CELL_NOT_ONLY;
  }
  return CUDT_SUCCESS;
}

CKBResCode get_scritp_hash(CacheData* data) {
  CKBResCode err = CUDT_SUCCESS;
  uint64_t len = sizeof(data->script_hash);
  CHECK(ckb_load_script_hash(&(data->script_hash), &len, 0));
exit_func:
  return err;
}

CKBResCode load_deposit_vec(CacheData* data,
                            CompactUDTEntriesType* cudt_witness) {
  CKBResCode err = CUDT_SUCCESS;
  CacheDeposit** last_cache = &(data->deposits);
  DepositVecType dvec = cudt_witness->t->deposits(cudt_witness);
  uint32_t len = dvec.t->len(&dvec);
  for (uint32_t i = 0; i < len; i++) {
    bool existing = false;
    DepositType d = dvec.t->get(&dvec, i, &existing);
    CHECK2(existing, CUDTERR_WITNESS_INVALID);

    CacheDeposit* cache = (CacheDeposit*)alloc_cache(sizeof(CacheDeposit));

    cache->source = (Hash*)alloc_cache(sizeof(Hash));
    ReadMemFromMol2(d, source, cache->source, sizeof(Hash));
    ReadMemFromMol2(d, target, &(cache->target), sizeof(cache->target));
    ReadUint128FromMol2(d, amount, cache->amount);
    ReadUint128FromMol2(d, fee, cache->fee);

    *last_cache = cache;
    last_cache = &((*last_cache)->next);
  }

exit_func:
  return err;
}

CKBResCode load_transfer_vec(CacheData* data,
                             CompactUDTEntriesType* cudt_witness) {
  CKBResCode err = CUDT_SUCCESS;

  CacheTransfer** last_cache = &(data->transfers);
  TransferVecType tvec = cudt_witness->t->transfers(cudt_witness);

  uint32_t len = tvec.t->len(&tvec);
  for (uint32_t i = 0; i < len; i++) {
    bool existing = false;
    TransferType t = tvec.t->get(&tvec, i, &existing);
    CHECK2(existing, CUDTERR_WITNESS_INVALID);

    CacheTransfer* cache = (CacheTransfer*)alloc_cache(sizeof(CacheTransfer));
    *last_cache = cache;
    last_cache = &(cache->next);

    RawTransferType raw = t.t->raw(&t);
    ReadMemFromMol2(raw, source, &(cache->source), sizeof(cache->source));
    ReadUint128FromMol2(raw, amount, cache->amount);
    ReadUint128FromMol2(raw, fee, cache->fee);

    TransferTargetType raw_target = raw.t->target(&raw);
    cache->target_type = raw_target.t->item_id(&raw_target);

    uint8_t* target_buf = NULL;
    switch (cache->target_type) {
      case TargetType_ScriptHash:
        target_buf = alloc_cache(sizeof(Hash));
        ReadMemFromMol2(raw_target, as_ScriptHash, target_buf, sizeof(Hash));
        break;
      case TargetType_Identity:
        target_buf = alloc_cache(sizeof(Identity));
        ReadMemFromMol2(raw_target, as_Identity, target_buf, sizeof(Identity));
        break;
      case TargetType_MoveBetweenCompactSMT:
        target_buf = alloc_cache(sizeof(CacheMoveBetweenCompactSMT));
        CacheMoveBetweenCompactSMT* tmp_buf =
            (CacheMoveBetweenCompactSMT*)target_buf;

        MoveBetweenCompactSMTType mbc =
            raw_target.t->as_MoveBetweenCompactSMT(&raw_target);
        ReadMemFromMol2(mbc, identity, &(tmp_buf->identity), sizeof(Identity));
        ReadMemFromMol2(mbc, script_hash, &(tmp_buf->script_hash),
                        sizeof(Hash));
        break;
      default:
        return CUDTERR_WITNESS_INVALID;
    }
    cache->target = target_buf;
  }

exit_func:
  return err;
}

CKBResCode load_kv_pairs(CacheData* data, CompactUDTEntriesType* cudt_witness) {
  CKBResCode err = CUDT_SUCCESS;
  KVPairVecType kvvec = cudt_witness->t->kv_state(cudt_witness);
  g_cudt_cache->kv_pairs_len = kvvec.t->len(&kvvec);
  if (g_cudt_cache->kv_pairs_len != 0) {
    g_cudt_cache->kv_pairs =
        alloc_cache(g_cudt_cache->kv_pairs_len * sizeof(CacheKVPair));
  }
  for (uint32_t i = 0; i < g_cudt_cache->kv_pairs_len; i++) {
    CacheKVPair* cache_kv = &(g_cudt_cache->kv_pairs[i]);
    bool existing = false;
    KVPairType kv = kvvec.t->get(&kvvec, i, &existing);
    CHECK2(existing, CUDTERR_WITNESS_INVALID);
    ReadMemFromMol2(kv, k, &(cache_kv->key), sizeof(cache_kv->key));
    ReadMemFromMol2(kv, v, &(cache_kv->value), sizeof(cache_kv->value));
  }
exit_func:
  return err;
}

CKBResCode load_kv_proof(CacheData* data, CompactUDTEntriesType* cudt_witness) {
  CKBResCode err = CUDT_SUCCESS;
  mol2_cursor_t proof_cur = cudt_witness->t->kv_proof(cudt_witness);

  uint8_t buf[2048];
  uint32_t len = mol2_read_at(&proof_cur, buf, 2048);
  CHECK2(len != 0 && len != 2048, CUDTERR_WITNESS_INVALID);
  g_cudt_cache->kv_proof = alloc_cache(len);
  memcpy(g_cudt_cache->kv_proof, buf, len);
  g_cudt_cache->kv_proof_len = len;
exit_func:
  return err;
}

CKBResCode load_cur_cell_data() {
  CKBResCode err = CUDT_SUCCESS;
  CHECK(check_script_unique());

  CacheData* data = &g_cudt_cache->cur_data;
  err = get_cell_data(0, CKB_SOURCE_GROUP_INPUT, NULL, &data->input_amount,
                      &(g_cudt_cache->input_smt_hash));
  CHECK2(err == CUDT_SUCCESS, CUDTERR_LOAD_CELL_DATA);
  err = get_cell_data(0, CKB_SOURCE_GROUP_OUTPUT, NULL, &data->output_amount,
                      &(g_cudt_cache->output_smt_hash));
  CHECK2(err == CUDT_SUCCESS, CUDTERR_LOAD_CELL_DATA);

  CHECK(get_scritp_hash(data));

  CompactUDTEntriesType cudt_witness;
  CHECK(get_cudt_witness(0, CKB_SOURCE_GROUP_INPUT, &cudt_witness));
  CHECK(load_deposit_vec(data, &cudt_witness));
  CHECK(load_transfer_vec(data, &cudt_witness));
  CHECK(load_kv_pairs(data, &cudt_witness));
  CHECK(load_kv_proof(data, &cudt_witness));

exit_func:
  return err;
}

CKBResCode load_other_cell_data(size_t index, CacheData** last, bool* goon) {
  CKBResCode err = CUDT_SUCCESS;

  Hash script_hash;
  uint64_t hash_len = sizeof(script_hash);
  int ret_code =
      ckb_load_cell_by_field(&script_hash, &hash_len, 0, index,
                             CKB_SOURCE_INPUT, CKB_CELL_FIELD_LOCK_HASH);

  if (ret_code == CKB_INDEX_OUT_OF_BOUND) {
    *goon = false;
    return CUDT_SUCCESS;
  }
  CHECK2(!ret_code, CUDTERR_LOAD_OTHER_DATA);

  // cur witness
  if (memcmp(&g_cudt_cache->cur_data.script_hash, &script_hash,
             sizeof(script_hash)) == 0)
    return CUDT_SUCCESS;

  CompactUDTEntriesType cudt_witness;
  CHECK(get_cudt_witness(index, CKB_SOURCE_INPUT, &cudt_witness));

  CacheData* cache = NULL;

  uint128_t total_deposit = 0, total_transfer = 0, total_fee = 0;

  // load deposit
  CacheDeposit** last_deposit = NULL;
  DepositVecType dvec = cudt_witness.t->deposits(&cudt_witness);
  uint32_t len = dvec.t->len(&dvec);
  for (uint32_t i = 0; i < len; i++) {
    bool existing = false;
    DepositType d = dvec.t->get(&dvec, i, &existing);
    CHECK2(existing, CUDTERR_WITNESS_OTHER_INVALID);

    uint128_t amount = 0;
    ReadUint128FromMol2(d, amount, amount);
    total_deposit += amount;

    Hash hash;
    ReadMemFromMol2(d, source, &hash, sizeof(hash));
    if (memcmp(&hash, &(g_cudt_cache->cur_data.script_hash), sizeof(hash)) !=
        0) {
      continue;
    }

    // NULL Cache
    if (cache == NULL) {
      cache = (CacheData*)alloc_cache(sizeof(CacheData));
      *last = cache;
      last_deposit = &cache->deposits;
    }

    CacheDeposit* cache = (CacheDeposit*)alloc_cache(sizeof(CacheDeposit));
    *last_deposit = cache;
    last_deposit = &((*last_deposit)->next);

    ReadMemFromMol2(d, target, &(cache->target), sizeof(cache->target));
    cache->amount = amount;
    ReadUint128FromMol2(d, fee, cache->fee);
  }

  // load transfer
  TransferVecType tvec = cudt_witness.t->transfers(&cudt_witness);
  len = tvec.t->len(&tvec);

  CacheTransfer** last_transfer = NULL;
  for (uint32_t i = 0; i < len; i++) {
    bool existing = false;
    TransferType t = tvec.t->get(&tvec, i, &existing);
    CHECK2(existing, CUDTERR_WITNESS_OTHER_INVALID);

    RawTransferType raw = t.t->raw(&t);
    TransferTargetType target = raw.t->target(&raw);

    uint128_t amount = 0, fee = 0;
    ReadUint128FromMol2(raw, amount, amount);
    ReadUint128FromMol2(raw, fee, fee);
    total_transfer += amount;
    total_fee += fee;

    CacheTransferSourceType target_type = target.t->item_id(&target);
    Hash hash;

    switch (target_type) {
      case TargetType_ScriptHash:
        ReadMemFromMol2(target, as_ScriptHash, &hash, sizeof(Hash));
        break;
      case TargetType_Identity:
        break;
      case TargetType_MoveBetweenCompactSMT: {
        MoveBetweenCompactSMTType mbc =
            target.t->as_MoveBetweenCompactSMT(&target);
        ReadMemFromMol2(mbc, script_hash, &(hash), sizeof(Hash));
        break;
      }
      default:
        return CUDTERR_WITNESS_INVALID;
    }

    if (memcmp(&hash, &(g_cudt_cache->cur_data.script_hash), sizeof(hash)) != 0)
      continue;

    if (cache == NULL) {
      cache = (CacheData*)alloc_cache(sizeof(CacheData));
      *last = cache;
      last_transfer = &cache->transfers;
    }

    CacheTransfer* cache = (CacheTransfer*)alloc_cache(sizeof(CacheTransfer));
    *last_transfer = cache;
    last_transfer = &(cache->next);

    ReadMemFromMol2(raw, source, &(cache->source), sizeof(cache->source));
    cache->amount = amount;
    cache->fee = fee;

    cache->target_type = target_type;
    cache->target = alloc_cache(sizeof(Hash));
    memcpy(cache->target, &hash, sizeof(Hash));
    // For MoveBetweenCompactSMT, other not need identity
  }

  if (cache == NULL)
    return CUDT_SUCCESS;

  CHECK(get_cell_data(0, CKB_SOURCE_GROUP_INPUT, NULL, &cache->input_amount,
                      NULL));
  CHECK(get_cell_data(0, CKB_SOURCE_GROUP_OUTPUT, NULL, &cache->output_amount,
                      NULL));
  memcpy(&(cache->script_hash), &script_hash, sizeof(script_hash));

  if (cache->input_amount + total_deposit < total_transfer + total_fee) {
    return CUDTERR_OTHER_NO_ENOUGH_UDT;
  }

exit_func:
  return err;
}

CKBResCode load_all_other_cell_data() {
  CKBResCode err = CUDT_SUCCESS;

  CacheData** last = &(g_cudt_cache->other_data);
  bool goon = true;
  for (size_t i = 0; goon; i++) {
    CHECK(load_other_cell_data(i, last, &goon));
    if ((*last) != NULL)
      last = &((*last)->next);
  }

exit_func:
  return err;
}

CKBResCode load_all_data() {
  CKBResCode err = CUDT_SUCCESS;
  g_cudt_cache = (Cache*)alloc_cache(sizeof(Cache));

  Identity identity;
  bool has_id = false;
  CHECK(get_args(&(g_cudt_cache->type_id), &identity, &has_id));
  if (has_id) {
    g_cudt_cache->identity = (Identity*)alloc_cache(sizeof(Identity));
    memcpy(g_cudt_cache->identity, &identity, sizeof(Identity));
  }

  CHECK(load_cur_cell_data());
  CHECK(load_all_other_cell_data());

exit_func:
  return err;
}

CKBResCode check_total_udt() {
  CKBResCode err = CUDT_SUCCESS;
  CacheData* cur_cache = &(g_cudt_cache->cur_data);

  // cur total deposit
  uint128_t total_deposit = 0;
  for (CacheDeposit* cache = cur_cache->deposits; cache != NULL;
       cache = cache->next) {
    total_deposit += cache->amount;
  }

  // cur total transfer (to other)
  uint128_t total_transfer = 0;
  uint128_t total_fee = 0;
  for (CacheTransfer* cache = cur_cache->transfers; cache != NULL;
       cache = cache->next) {
    total_transfer += cache->amount;
    total_fee += cache->fee;
  }

  if (cur_cache->input_amount + total_deposit <
      cur_cache->output_amount + total_transfer + total_fee) {
    return CUDTERR_NO_ENOUGH_UDT;
  }

  return err;
}

#define MAX_SMT_PAIR 2000
CKBResCode check_smt_root(Hash* hash) {
  CKBResCode err = CKBERR_UNKNOW;

  smt_state_t smt_statue;
  smt_pair_t smt_pairs[MAX_SMT_PAIR];
  smt_state_init(&smt_statue, smt_pairs, MAX_SMT_PAIR);
  CHECK2(g_cudt_cache->kv_pairs_len < MAX_SMT_PAIR, CUDTERR_KV_TOO_LONG);

  for (uint32_t i = 0; i < g_cudt_cache->kv_pairs_len; i++) {
    CacheKVPair* kv = &(g_cudt_cache->kv_pairs[i]);
    smt_state_insert(&smt_statue, (const uint8_t*)&(kv->key),
                     (const uint8_t*)&(kv->value));
  }
  smt_state_normalize(&smt_statue);
  int smt_code = smt_verify((const uint8_t*)hash, &smt_statue,
                            g_cudt_cache->kv_proof, g_cudt_cache->kv_proof_len);
  CHECK2(smt_code == 0, CUDTERR_KV_VERIFY);
  err = CUDT_SUCCESS;
exit_func:
  return err;
}

CacheData* find_other_cache(Hash* script_hash) {
  CacheData* cache = g_cudt_cache->other_data;
  for (; cache != NULL; cache = cache->next) {
    if (memcmp(script_hash, &(cache->script_hash), sizeof(Hash)) == 0) {
      return cache;
    }
  }
  return NULL;
}

CKBResCode check_deposit(CacheDeposit* cache) {
  CKBResCode err = CUDT_SUCCESS;

  CacheData* other_data = find_other_cache(cache->source);
  CHECK2(other_data, CUDTERR_DEPOSIT_INVALID);

  bool has = false;
  CacheTransfer* ct = other_data->transfers;
  CacheTransfer** last_ct = &(other_data->transfers);
  for (; ct != NULL; last_ct = &(ct->next), ct = ct->next) {
    if (ct->amount != cache->amount)
      continue;
    if (ct->fee != cache->fee)
      continue;

    // remove
    *last_ct = ct->next;
    has = true;
    break;
  }
  CHECK2(has, CUDTERR_DEPOSIT_INVALID);

exit_func:
  return err;
}

CacheKVPair* find_kv_pair(Identity* identity) {
  ASSERT_DBG(identity);
  for (uint32_t i = 0; i < g_cudt_cache->kv_pairs_len; i++) {
    if (memcmp(&(g_cudt_cache->kv_pairs[i].key), identity, sizeof(Identity)) ==
        0) {
      return &g_cudt_cache->kv_pairs[i];
    }
  }
  ASSERT_DBG(false);
  ckb_exit(CKBERR_UNKNOW);
  return NULL;
}

CKBResCode check_each_deposit() {
  CKBResCode err = CUDT_SUCCESS;

  for (CacheDeposit* cache = g_cudt_cache->cur_data.deposits; cache != NULL;
       cache = cache->next) {
    CHECK(check_deposit(cache));

    CacheKVPair* kv_pair = find_kv_pair(&(cache->target));
    CHECK2(kv_pair, CUDTERR_DEPOSIT_NO_KVPAIR);
    kv_pair->value.amount += cache->amount;
  }

exit_func:
  return err;
}

CKBResCode check_transfer(CacheTransfer* cache,
                          Hash* hash,
                          Identity* identity) {
  CKBResCode err = CUDT_SUCCESS;
  if (hash == NULL)
    return CUDT_SUCCESS;

  CacheData* other_data = find_other_cache(hash);
  CHECK2(other_data, CUDTERR_TRANSFER_INVALID);

  bool has = false;
  CacheDeposit* cd = other_data->deposits;
  CacheDeposit** last_cd = &(other_data->deposits);
  for (; cd != NULL; last_cd = &(cd->next), cd = cd->next) {
    if (cd->amount != cache->amount)
      continue;
    if (cd->fee != cache->fee)
      continue;

    if (identity) {
      if (memcmp(identity, &(cd->target), sizeof(Identity)) != 0) {
        continue;
      }
    }

    has = true;
    *last_cd = cd->next;
    break;
  }
  CHECK2(has, CUDTERR_TRANSFER_INVALID);

exit_func:
  return err;
}

CKBResCode check_each_transfer() {
  CKBResCode err = CUDT_SUCCESS;

  for (CacheTransfer* cache = g_cudt_cache->cur_data.transfers; cache != NULL;
       cache = cache->next) {
    Hash* hash = NULL;
    Identity* identity = NULL;

    switch (cache->target_type) {
      case TargetType_ScriptHash:
        hash = (Hash*)cache->target;
        break;
      case TargetType_Identity:
        identity = (Identity*)cache->target;
        break;
      case TargetType_MoveBetweenCompactSMT: {
        CacheMoveBetweenCompactSMT* cm =
            (CacheMoveBetweenCompactSMT*)cache->target;
        hash = &(cm->script_hash);
        identity = &(cm->identity);
      } break;
    }

    CHECK(check_transfer(cache, hash, identity));

    CacheKVPair* src_kv = find_kv_pair(&(cache->source));
    CHECK2(src_kv, CUDTERR_TRANSFER_NO_KVPAIR);

    CHECK2(src_kv->value.amount >= cache->amount + cache->fee,
           CUDTERR_TRANSFER_ENOUGH_UDT);
    src_kv->value.amount -= (cache->amount + cache->fee);
    src_kv->value.nonce += 1;
  }

exit_func:
  return err;
}

int CKBMAIN(int argc, char* argv[]) {
  CKBResCode err = CKBERR_UNKNOW;

  CHECK(load_all_data());
  CHECK(check_total_udt());
  CHECK(check_smt_root(&(g_cudt_cache->input_smt_hash)));
  CHECK(check_each_deposit());
  CHECK(check_each_transfer());
  CHECK(check_smt_root(&(g_cudt_cache->output_smt_hash)));
  err = CUDT_SUCCESS;
exit_func:
  return err;
}
