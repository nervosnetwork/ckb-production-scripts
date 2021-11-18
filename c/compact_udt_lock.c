//#define ENABLE_DEBUG

#ifdef ENABLE_DEBUG
#define CKB_C_STDLIB_PRINTF
#include "debug.h"
#endif  // ENABLE_DEBUG

#include "compact_udt_lock.h"
#include "compact_udt_lock_reader.h"

uint8_t g_tx_buffer[1024 * 1024 * 1];
uint32_t g_tx_buffer_malloced_len = 0;
int g_now_is_temporary_cache_ = 0;

void* alloc_cache_base(uint32_t len) {
  // need 16 byte alignment
  if (len % 16 != 0) {
    len = (len / 16 + 1) * 16;
  }

  if (g_tx_buffer_malloced_len + len > sizeof(g_tx_buffer)) {
    ASSERT_DBG(false);
    ckb_exit(CUDTERR_ALLOC_MEMORY);
    return NULL;
  }
  void* p = g_tx_buffer + g_tx_buffer_malloced_len;
  memset(p, 0, len);
  g_tx_buffer_malloced_len += len;
  return p;
}

void* alloc_cache(uint32_t len) {
  ASSERT_DBG(!g_now_is_temporary_cache_);
  return alloc_cache_base(len);
}

//#define __STDC_NO_VLA__

// clang-format off
const uint8_t g_auth_dl_cell_hash[] = {
  0xBD, 0x78, 0x78, 0xA1, 0xF8, 0xC7, 0x71, 0x50, 0x22, 0x0C, 0x76, 0xD8, 0xEE, 0x9C, 0x18, 0x01, 
  0x8B, 0xEF, 0xC2, 0xD9, 0x93, 0xCA, 0xDA, 0xC0, 0x95, 0x1B, 0xBB, 0x07, 0xCE, 0x1D, 0x5F, 0x90
};
// clang-format on

int auth_validate(const uint8_t* signature,
                  uint32_t signature_size,
                  const Hash* message,
                  const Identity* pubkey_hash) {
  CkbEntryType entry;
  memcpy(entry.code_hash, g_auth_dl_cell_hash, sizeof(Hash));
  entry.hash_type = 2;  // ScriptHashType::Data1
  entry.entry_category = EntryCategoryDynamicLinking;

  CkbAuthType auth;
  memcpy(&auth, pubkey_hash, sizeof(Identity));

  return ckb_auth(&entry, &auth, signature, signature_size,
                  (const uint8_t*)message);
}

static int extract_witness_lock(uint8_t* witness,
                                uint64_t len,
                                mol_seg_t* lock_bytes_seg) {
  if (len < 20) {
    return CKB_INVALID_DATA;
  }
  uint32_t lock_length = *((uint32_t*)(&witness[16]));
  if (len < 20 + lock_length) {
    return CKB_INVALID_DATA;
  } else {
    lock_bytes_seg->ptr = &witness[20];
    lock_bytes_seg->size = lock_length;
  }
  return CKB_SUCCESS;
}

int load_and_hash_witness(blake2b_state* ctx,
                          size_t start,
                          size_t index,
                          size_t source,
                          bool hash_length) {
  int err = 0;

  uint8_t temp[ONE_BATCH_SIZE] = {0};

  uint64_t len = ONE_BATCH_SIZE;
  err = ckb_load_witness(temp, &len, start, index, source);
  if (err != 0) {
    goto exit_func;
  }

  if (hash_length) {
    err = blake2b_update(ctx, (char*)&len, sizeof(uint64_t));
    CUDT_CHECK_BLAKE(err);
  }
  uint64_t offset = (len > ONE_BATCH_SIZE) ? ONE_BATCH_SIZE : len;
  err = blake2b_update(ctx, temp, offset);
  CUDT_CHECK_BLAKE(err);

  while (offset < len) {
    uint64_t current_len = ONE_BATCH_SIZE;
    err = ckb_load_witness(temp, &current_len, start + offset, index, source);
    if (err != CKB_SUCCESS) {
      return err;
    }
    uint64_t current_read =
        (current_len > ONE_BATCH_SIZE) ? ONE_BATCH_SIZE : current_len;
    err = blake2b_update(ctx, temp, current_read);
    CUDT_CHECK_BLAKE(err);

    offset += current_read;
  }

exit_func:
  return err;
}

int generate_sighash_all(Hash* msg) {
  int err = CUDT_SUCCESS;

  uint64_t len = 0;
  uint8_t temp[MAX_WITNESS_SIZE] = {0};

  uint64_t read_len = MAX_WITNESS_SIZE;
  uint64_t witness_len = MAX_WITNESS_SIZE;

  // Load witness of first input
  err = ckb_load_witness(temp, &read_len, 0, 0, CKB_SOURCE_GROUP_INPUT);
  if (CUDT_IS_FAILED(err))
    return CUDTERR_WITNESS_INVALID;

  witness_len = read_len;
  if (read_len > MAX_WITNESS_SIZE) {
    read_len = MAX_WITNESS_SIZE;
  }

  // load signature
  mol_seg_t lock_bytes_seg;
  err = extract_witness_lock(temp, read_len, &lock_bytes_seg);
  if (CUDT_IS_FAILED(err))
    return CUDTERR_WITNESS_INVALID;

  // Load tx hash
  unsigned char tx_hash[BLAKE2B_BLOCK_SIZE] = {0};
  len = BLAKE2B_BLOCK_SIZE;
  err = ckb_load_tx_hash(tx_hash, &len, 0);
  if (CUDT_IS_FAILED(err))
    return CUDTERR_WITNESS_INVALID;

  if (len != BLAKE2B_BLOCK_SIZE)
    return CUDTERR_WITNESS_INVALID;

  // Prepare sign message
  blake2b_state blake2b_ctx;
  err = blake2b_init(&blake2b_ctx, BLAKE2B_BLOCK_SIZE);
  CUDT_CHECK_BLAKE(err);

  err = blake2b_update(&blake2b_ctx, tx_hash, BLAKE2B_BLOCK_SIZE);
  CUDT_CHECK_BLAKE(err);

  // Clear lock field to zero, then digest the first witness
  // lock_bytes_seg.ptr actually points to the memory in temp buffer
  memset((void*)lock_bytes_seg.ptr, 0, lock_bytes_seg.size);
  err = blake2b_update(&blake2b_ctx, (char*)&witness_len, sizeof(uint64_t));
  CUDT_CHECK_BLAKE(err);

  err = blake2b_update(&blake2b_ctx, temp, read_len);
  CUDT_CHECK_BLAKE(err);

  // remaining of first witness
  if (read_len < witness_len) {
    err = load_and_hash_witness(&blake2b_ctx, read_len, 0,
                                CKB_SOURCE_GROUP_INPUT, false);
    if (CUDT_IS_FAILED(err))
      return CUDTERR_WITNESS_INVALID;
  }

  // CKB_SOURCE_GROUP_INPUT <= 1 in this cell
  // size_t i = 1;
  // while (1) {
  //   err =
  //       load_and_hash_witness(&blake2b_ctx, 0, i, CKB_SOURCE_GROUP_INPUT,
  //       true);
  //   if (err == CKB_INDEX_OUT_OF_BOUND) {
  //     break;
  //   }
  //   if (err != CKB_SUCCESS) {
  //     return CKB_INVALID_DATA;
  //   }
  //   i += 1;
  // }

  // Digest witnesses that not covered by inputs
  size_t i = (size_t)ckb_calculate_inputs_len();
  while (1) {
    err = load_and_hash_witness(&blake2b_ctx, 0, i, CKB_SOURCE_INPUT, true);
    if (err == CKB_INDEX_OUT_OF_BOUND) {
      break;
    }
    if (err != CKB_SUCCESS) {
      return CKB_INVALID_DATA;
    }
    i += 1;
  }

  err = blake2b_final(&blake2b_ctx, msg, BLAKE2B_BLOCK_SIZE);
  CUDT_CHECK_BLAKE(err);

  return CUDT_SUCCESS;
}

typedef struct _CacheDeposit {
  Hash* source;
  Identity target;
  uint128_t amount;
  uint128_t fee;

  bool flag;

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

  bool flag;  // flag when check Deposit

  struct _CacheTransfer* next;
} CacheTransfer;

typedef struct _CacheData {
  Hash script_hash;
  bool is_compact_udt;

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
  Hash compact_udt_code_hash;
  uint8_t compact_udt_hash_type;

  Hash input_smt_hash;
  Hash output_smt_hash;

  uint128_t other_cell_input_amount;
  uint128_t other_cell_output_amount;

  CacheKVPair* kv_pairs;
  uint32_t kv_pairs_len;

  uint8_t* kv_proof;
  uint32_t kv_proof_len;
} Cache;
Cache* g_cudt_cache;

CacheKVPair* find_kv_pair(const Identity* identity);

CacheData* find_other_cache(Hash* script_hash) {
  CacheData* cache = g_cudt_cache->other_data;
  for (; cache != NULL; cache = cache->next) {
    if (memcmp(script_hash, &(cache->script_hash), sizeof(Hash)) == 0) {
      return cache;
    }
  }
  return NULL;
}

ckb_res_code check_script_unique() {
  uint64_t len = 0;
  int ret_code = ckb_load_cell_data(NULL, &len, 0, 1, CKB_SOURCE_GROUP_INPUT);
  if (ret_code != CKB_INDEX_OUT_OF_BOUND) {
    return CUDTERR_CELL_NOT_ONLY;
  }
  return CUDT_SUCCESS;
}

ckb_res_code load_deposit_vec(CacheData* data,
                              CompactUDTEntriesType* cudt_witness) {
  ckb_res_code err = CUDT_SUCCESS;
  CacheDeposit** last_cache = &(data->deposits);
  DepositVecType dvec = cudt_witness->t->deposits(cudt_witness);
  uint32_t len = dvec.t->len(&dvec);

  for (uint32_t i = 0; i < len; i++) {
    bool existing = false;
    DepositType d = dvec.t->get(&dvec, i, &existing);
    CUDT_CHECK_MOL2(existing, CUDTERR_PARSE_MOL_DEPOSIT);

    CacheDeposit* cache = (CacheDeposit*)alloc_cache(sizeof(CacheDeposit));

    cache->source = (Hash*)alloc_cache(sizeof(Hash));
    ReadMemFromMol2(d, source, cache->source, sizeof(Hash),
                    CUDTERR_PARSE_MOL_DEPOSIT);
    ReadMemFromMol2(d, target, &(cache->target), sizeof(cache->target),
                    CUDTERR_PARSE_MOL_DEPOSIT);

    ReadUint128FromMol2(d, amount, cache->amount, CUDTERR_PARSE_MOL_DEPOSIT);
    ReadUint128FromMol2(d, fee, cache->fee, CUDTERR_PARSE_MOL_DEPOSIT);

    *last_cache = cache;
    last_cache = &((*last_cache)->next);
  }

  return err;
}

ckb_res_code get_transfer_hash(const TransferType* t,
                               const RawTransferType* raw,
                               const CacheTransfer* cache,
                               Hash* transfer_hash) {
  ckb_res_code err = CUDT_SUCCESS;
  uint32_t tmp_buffer_len = (raw->cur.size / 16 + 1) * 16;
  uint8_t tmp_buffer[tmp_buffer_len];
  memset(tmp_buffer, 0, tmp_buffer_len);

  blake2b_state b2 = {0};
  err = blake2b_init(&b2, sizeof(Hash));
  CUDT_CHECK_BLAKE(err);

  err = blake2b_update(&b2, &(g_cudt_cache->type_id), sizeof(Hash));
  CUDT_CHECK_BLAKE(err);

  CacheKVPair* kv_pair = find_kv_pair(&(cache->source));
  if (!kv_pair)
    return CUDTERR_TRANSFER_SRC_NO_KV_PAIR;
  err = blake2b_update(&b2, &(kv_pair->value.nonce),
                       sizeof(kv_pair->value.nonce));
  CUDT_CHECK_BLAKE(err);

  uint32_t tmp_buffer_read_len =
      mol2_read_at(&(raw->cur), tmp_buffer, raw->cur.size);
  CUDT_CHECK_MOL2((tmp_buffer_read_len == raw->cur.size),
                  CUDTERR_PARSE_MOL_TRANSFER);

  err = blake2b_update(&b2, tmp_buffer, raw->cur.size);
  CUDT_CHECK_BLAKE(err);

  err = blake2b_final(&b2, transfer_hash, sizeof(Hash));
  CUDT_CHECK_BLAKE(err);

  return err;
}

ckb_res_code check_transfer_sign(const Identity* id,
                                 const Hash* message,
                                 const uint8_t* signature,
                                 uint32_t signature_len) {
  return auth_validate(signature, signature_len, message, id);
}

ckb_res_code load_transfer_vec(CacheData* data,
                               CompactUDTEntriesType* cudt_witness) {
  ckb_res_code err = CUDT_SUCCESS;

  CacheTransfer** last_cache = &(data->transfers);
  TransferVecType tvec = cudt_witness->t->transfers(cudt_witness);

  uint32_t len = tvec.t->len(&tvec);
  for (uint32_t i = 0; i < len; i++) {
    bool existing = false;
    TransferType t = tvec.t->get(&tvec, i, &existing);
    if (!existing)
      return CUDTERR_WITNESS_INVALID;

    CacheTransfer* cache = (CacheTransfer*)alloc_cache(sizeof(CacheTransfer));
    *last_cache = cache;
    last_cache = &(cache->next);

    RawTransferType raw = t.t->raw(&t);
    ReadMemFromMol2(raw, source, &(cache->source), sizeof(cache->source),
                    CUDTERR_PARSE_MOL_TRANSFER);
    ReadUint128FromMol2(raw, amount, cache->amount, CUDTERR_PARSE_MOL_TRANSFER);
    ReadUint128FromMol2(raw, fee, cache->fee, CUDTERR_PARSE_MOL_TRANSFER);

    Hash transfer_hash;
    err = get_transfer_hash(&t, &raw, cache, &transfer_hash);
    CUDT_CHECK(err);

    mol2_cursor_t signature_seg = t.t->signature(&t);
    if (signature_seg.size == 0) {
      ASSERT_DBG(false);
      return CUDTERR_TRANSFER_INVALID;
    }

    uint32_t signature_buf_len = (signature_seg.size / 16 + 1) * 16;
    uint8_t signature_buf[signature_buf_len];
    memset(signature_buf, 0, signature_buf_len);
    uint32_t signature_len =
        mol2_read_at(&signature_seg, signature_buf, signature_seg.size);
    CUDT_CHECK_MOL2((signature_len == signature_seg.size),
                    CUDTERR_PARSE_MOL_TRANSFER);

    err = check_transfer_sign(&cache->source, &transfer_hash, signature_buf,
                              signature_len);
    CUDT_CHECK(err);

    TransferTargetType raw_target = raw.t->target(&raw);
    cache->target_type = raw_target.t->item_id(&raw_target);

    uint8_t* target_buf = NULL;
    switch (cache->target_type) {
      case TargetType_ScriptHash:
        target_buf = alloc_cache(sizeof(Hash));
        ReadMemFromMol2(raw_target, as_ScriptHash, target_buf, sizeof(Hash),
                        CUDTERR_PARSE_MOL_TRANSFER);
        break;
      case TargetType_Identity:
        target_buf = alloc_cache(sizeof(Identity));
        ReadMemFromMol2(raw_target, as_Identity, target_buf, sizeof(Identity),
                        CUDTERR_PARSE_MOL_TRANSFER);
        break;
      case TargetType_MoveBetweenCompactSMT:
        target_buf = alloc_cache(sizeof(CacheMoveBetweenCompactSMT));
        CacheMoveBetweenCompactSMT* tmp_buf =
            (CacheMoveBetweenCompactSMT*)target_buf;

        MoveBetweenCompactSMTType mbc =
            raw_target.t->as_MoveBetweenCompactSMT(&raw_target);
        ReadMemFromMol2(mbc, identity, &(tmp_buf->identity), sizeof(Identity),
                        CUDTERR_PARSE_MOL_TRANSFER);
        ReadMemFromMol2(mbc, script_hash, &(tmp_buf->script_hash), sizeof(Hash),
                        CUDTERR_PARSE_MOL_TRANSFER);
        if (memcmp(&(tmp_buf->script_hash),
                   &(g_cudt_cache->cur_data.script_hash), sizeof(Hash)) == 0) {
          ASSERT_DBG(false);
          return CUDTERR_WITNESS_INVALID;
        }
        break;
      default:
        CUDT_CHECK(CUDTERR_WITNESS_INVALID);
    }
    cache->target = target_buf;
  }

exit_func:
  return err;
}

ckb_res_code load_kv_pairs(CacheData* data,
                           CompactUDTEntriesType* cudt_witness) {
  ckb_res_code err = CUDT_SUCCESS;
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
    CUDT_CHECK_MOL2(existing, CUDTERR_WITNESS_INVALID);

    ReadMemFromMol2(kv, k, &(cache_kv->key), sizeof(cache_kv->key),
                    CUDTERR_PARSE_MOL_KV_PAIRS);

    uint8_t tmp_val[32] = {0};
    ReadMemFromMol2(kv, v, tmp_val, sizeof(tmp_val),
                    CUDTERR_PARSE_MOL_KV_PAIRS);
    cache_kv->value.amount = ((uint128_t*)tmp_val)[0];
    cache_kv->value.nonce = ((uint32_t*)(tmp_val + sizeof(uint128_t)))[0];
  }
  return err;
}

ckb_res_code load_kv_proof(CacheData* data,
                           CompactUDTEntriesType* cudt_witness) {
  mol2_cursor_t proof_cur = cudt_witness->t->kv_proof(cudt_witness);

  if (proof_cur.size == 0) {
    ASSERT_DBG(false);
    return CUDTERR_SMTPROOF_SIZE_INVALID;
  }

  g_cudt_cache->kv_proof = alloc_cache(proof_cur.size);
  uint32_t len =
      mol2_read_at(&proof_cur, g_cudt_cache->kv_proof, proof_cur.size);
  CUDT_CHECK_MOL2((len == proof_cur.size), CUDTERR_SMTPROOF_SIZE_INVALID);
  g_cudt_cache->kv_proof_len = proof_cur.size;
  return CUDT_SUCCESS;
}

ckb_res_code check_identity(CompactUDTEntriesType* cudt_witness) {
  ckb_res_code err = CUDT_SUCCESS;
  if (!g_cudt_cache->identity)
    return CUDT_SUCCESS;

  SignatureOptType signature_opt = cudt_witness->t->signature(cudt_witness);
  bool has_sign = signature_opt.t->is_some(&signature_opt);
  if (has_sign != (g_cudt_cache->identity != NULL)) {
    ASSERT_DBG(false);
    return CUDTERR_WITNESS_INVALID;
  }

  mol2_cursor_t signature_t = signature_opt.t->unwrap(&signature_opt);

  SignatureType signature = make_Signature(&signature_t);
  uint32_t signature_len = (signature.cur.size / 16 + 1) * 16;
  uint8_t signature_data[signature_len];
  memset(signature_data, 0, signature_len);

  uint32_t sign_ret_len =
      mol2_read_at(&signature.cur, signature_data, signature.cur.size);
  CUDT_CHECK_MOL2((sign_ret_len == signature.cur.size),
                  CUDTERR_WITNESS_INVALID);

  Hash message = {0};
  err = generate_sighash_all(&message);
  CUDT_CHECK(err);

  err = auth_validate(signature_data, signature.cur.size, &message,
                      g_cudt_cache->identity);
  if (CUDT_IS_FAILED(err))
    return CUDTERR_CHECK_IDENTITY_INVALID;
exit_func:
  return err;
}

ckb_res_code load_cur_cell_data() {
  ckb_res_code err = CUDT_SUCCESS;
  err = check_script_unique();
  CUDT_CHECK(err);
  CacheData* data = &g_cudt_cache->cur_data;
  data->is_compact_udt = true;

  err = get_scritp_hash(&(g_cudt_cache->cur_data.script_hash));
  CUDT_CHECK(err);

  err = get_cell_data(0, CKB_SOURCE_GROUP_INPUT, &data->input_amount,
                      &(g_cudt_cache->input_smt_hash));
  if (CUDT_IS_FAILED(err))
    return CUDTERR_LOAD_INPUT_CELL_DATA;

  int output_index = find_output_cell(&(g_cudt_cache->cur_data.script_hash));
  CUDT_CHECK2(output_index != -1, CUDTERR_LOAD_OUTPUT_CELL_DATA);

  err = get_cell_data(output_index, CKB_SOURCE_OUTPUT, &data->output_amount,
                      &(g_cudt_cache->output_smt_hash));
  if (CUDT_IS_FAILED(err))
    return CUDTERR_LOAD_OUTPUT_CELL_DATA;

  CompactUDTEntriesType cudt_witness;
  err = get_cudt_witness(0, CKB_SOURCE_GROUP_INPUT, &cudt_witness);
  CUDT_CHECK(err);

  err = check_identity(&cudt_witness);
  CUDT_CHECK(err);

  err = load_deposit_vec(data, &cudt_witness);
  CUDT_CHECK(err);

  err = load_kv_pairs(data, &cudt_witness);
  CUDT_CHECK(err);

  err = load_kv_proof(data, &cudt_witness);
  CUDT_CHECK(err);

  err = load_transfer_vec(data, &cudt_witness);
  CUDT_CHECK(err);
exit_func:
  return err;
}

ckb_res_code load_other_cudt_cell_data(size_t index, CacheData* cache) {
  ckb_res_code err = CUDT_SUCCESS;

  CompactUDTEntriesType cudt_witness;
  err = get_cudt_witness(index, CKB_SOURCE_INPUT, &cudt_witness);
  CUDT_CHECK(err);

  uint128_t total_deposit = 0, total_transfer = 0, total_fee = 0;

  // load deposit
  CacheDeposit** last_deposit = NULL;
  DepositVecType dvec = cudt_witness.t->deposits(&cudt_witness);
  uint32_t len = dvec.t->len(&dvec);
  for (uint32_t i = 0; i < len; i++) {
    bool existing = false;
    DepositType d = dvec.t->get(&dvec, i, &existing);
    CUDT_CHECK_MOL2(existing, CUDTERR_WITNESS_OTHER_INVALID);

    uint128_t amount = 0;
    ReadUint128FromMol2(d, amount, amount, CUDTERR_PARSE_MOL_DEPOSIT);
    ADD_SELF_AND_CHECK_OVERFOLW(total_deposit, amount);

    Hash hash;
    ReadMemFromMol2(d, source, &hash, sizeof(hash), CUDTERR_PARSE_MOL_DEPOSIT);

    if (memcmp(&hash, &(g_cudt_cache->cur_data.script_hash), sizeof(hash)) !=
        0) {
      continue;
    }

    if (last_deposit == NULL)
      last_deposit = &cache->deposits;

    CacheDeposit* cache_d = (CacheDeposit*)alloc_cache(sizeof(CacheDeposit));
    *last_deposit = cache_d;
    last_deposit = &((*last_deposit)->next);

    ReadMemFromMol2(d, target, &(cache_d->target), sizeof(cache_d->target),
                    CUDTERR_PARSE_MOL_DEPOSIT);
    cache_d->amount = amount;
    ReadUint128FromMol2(d, fee, cache_d->fee, CUDTERR_PARSE_MOL_DEPOSIT);
  }

  // load transfer
  TransferVecType tvec = cudt_witness.t->transfers(&cudt_witness);
  len = tvec.t->len(&tvec);

  CacheTransfer** last_transfer = NULL;
  for (uint32_t i = 0; i < len; i++) {
    bool existing = false;
    TransferType t = tvec.t->get(&tvec, i, &existing);
    CUDT_CHECK_MOL2(existing, CUDTERR_WITNESS_OTHER_INVALID);

    RawTransferType raw = t.t->raw(&t);
    TransferTargetType target = raw.t->target(&raw);

    uint128_t amount = 0, fee = 0;
    ReadUint128FromMol2(raw, amount, amount, CUDTERR_PARSE_MOL_TRANSFER);
    ReadUint128FromMol2(raw, fee, fee, CUDTERR_PARSE_MOL_TRANSFER);
    ADD_SELF_AND_CHECK_OVERFOLW(total_transfer, amount)
    ADD_SELF_AND_CHECK_OVERFOLW(total_fee, fee);

    CacheTransferSourceType target_type = target.t->item_id(&target);
    Hash hash;

    switch (target_type) {
      case TargetType_ScriptHash:
        ReadMemFromMol2(target, as_ScriptHash, &hash, sizeof(Hash),
                        CUDTERR_PARSE_MOL_TRANSFER);
        break;
      case TargetType_Identity:
        break;
      case TargetType_MoveBetweenCompactSMT: {
        MoveBetweenCompactSMTType mbc =
            target.t->as_MoveBetweenCompactSMT(&target);
        ReadMemFromMol2(mbc, script_hash, &(hash), sizeof(Hash),
                        CUDTERR_PARSE_MOL_TRANSFER);
        break;
      }
      default:
        CUDT_CHECK(CUDTERR_WITNESS_INVALID);
    }

    if (memcmp(&hash, &(g_cudt_cache->cur_data.script_hash), sizeof(hash)) != 0)
      continue;

    if (last_transfer == NULL) {
      last_transfer = &cache->transfers;
    }

    CacheTransfer* tx_cache =
        (CacheTransfer*)alloc_cache(sizeof(CacheTransfer));
    *last_transfer = tx_cache;
    last_transfer = &(tx_cache->next);

    ReadMemFromMol2(raw, source, &(tx_cache->source), sizeof(tx_cache->source),
                    CUDTERR_PARSE_MOL_TRANSFER);
    tx_cache->amount = amount;
    tx_cache->fee = fee;

    tx_cache->target_type = target_type;
    tx_cache->target = alloc_cache(sizeof(Hash));
    memcpy(tx_cache->target, &hash, sizeof(Hash));
    // For MoveBetweenCompactSMT, other not need identity
  }

  uint128_t input_res = 0, output_res = 0;
  ADD_AND_CHECK_OVERFOLW(cache->input_amount, total_deposit, input_res);
  ADD_AND_CHECK_OVERFOLW(total_transfer, total_fee, output_res);

  CUDT_CHECK2(input_res >= output_res, CUDTERR_OTHER_NO_ENOUGH_UDT);

exit_func:
  return err;
}

bool other_cell_useful(const Hash* script_hash) {
  CacheDeposit* cache_d = g_cudt_cache->cur_data.deposits;
  for (; cache_d != NULL; cache_d = cache_d->next) {
    if (memcmp(cache_d->source, script_hash, sizeof(Hash)) == 0) {
      return true;
    }
  }

  CacheTransfer* cache_t = g_cudt_cache->cur_data.transfers;
  for (; cache_t != NULL; cache_t = cache_t->next) {
    if (cache_t->target_type == TargetType_ScriptHash ||
        cache_t->target_type == TargetType_MoveBetweenCompactSMT) {
      Hash* target_src = (Hash*)(cache_t->target);
      if (memcmp(script_hash, target_src, sizeof(Hash)) == 0) {
        return true;
      }
    }
  }
  return false;
}

ckb_res_code load_other_cell(size_t index, CacheData** last, bool* goon) {
  ckb_res_code err = CUDT_SUCCESS;

  // load script hash is itself : return
  Hash script_hash = {0};
  int ret_code = get_cell_hash(&script_hash, index, CKB_SOURCE_INPUT);
  if (ret_code == CKB_INDEX_OUT_OF_BOUND) {
    *goon = false;
    return CUDT_SUCCESS;
  }
  if (ret_code)
    return CUDTERR_LOAD_OTHER_DATA;

  // is itself
  if (memcmp(&g_cudt_cache->cur_data.script_hash, &script_hash,
             sizeof(script_hash)) == 0) {
    return CUDT_SUCCESS;
  }

  // load amount
  uint128_t input_amount = 0;
  err = get_cell_udt(index, CKB_SOURCE_INPUT, &input_amount);
  CUDT_CHECK(err);
  uint128_t output_amount = 0;
  err = get_cell_udt(index, CKB_SOURCE_OUTPUT, &output_amount);
  CUDT_CHECK(err);

  // load lock script code hash
  Hash lock_code_hash = {0};
  uint8_t lock_hash_type = 0;
  err = get_scritp_code_hash(index, CKB_SOURCE_INPUT, &lock_code_hash,
                             &lock_hash_type);
  CUDT_CHECK(err);
  bool is_compact_udt_lock = true;

  ADD_SELF_AND_CHECK_OVERFOLW(g_cudt_cache->other_cell_input_amount,
                              input_amount);
  ADD_SELF_AND_CHECK_OVERFOLW(g_cudt_cache->other_cell_output_amount,
                              output_amount);

  if (memcmp(&lock_code_hash, &g_cudt_cache->compact_udt_code_hash,
             sizeof(Hash)) != 0 ||
      lock_hash_type != g_cudt_cache->compact_udt_hash_type) {
    is_compact_udt_lock = false;
  }

  if (!other_cell_useful(&script_hash)) {
    return CUDT_SUCCESS;
  }

  CacheData* cache = find_other_cache(&script_hash);
  if (cache == NULL) {
    cache = (CacheData*)alloc_cache(sizeof(CacheData));
    *last = cache;
  }
  cache->input_amount = input_amount;
  cache->output_amount = output_amount;
  cache->is_compact_udt = is_compact_udt_lock;
  memcpy(&(cache->script_hash), &script_hash, sizeof(Hash));

  // load cudt data
  if (is_compact_udt_lock) {
    err = load_other_cudt_cell_data(index, cache);
    CUDT_CHECK(err);
  }

exit_func:
  return err;
}

ckb_res_code load_all_other_cell_data() {
  ckb_res_code err = CUDT_SUCCESS;

  CacheData** last = &(g_cudt_cache->other_data);
  bool goon = true;
  for (size_t i = 0; goon; i++) {
    err = load_other_cell(i, last, &goon);
    CUDT_CHECK(err);
    if ((*last) != NULL)
      last = &((*last)->next);
  }

exit_func:
  return err;
}

ckb_res_code load_all_data() {
  ckb_res_code err = CUDT_SUCCESS;
  g_cudt_cache = (Cache*)alloc_cache(sizeof(Cache));

  Identity identity;
  bool has_id = false;
  err = get_args(&(g_cudt_cache->type_id), &identity, &has_id,
                 &(g_cudt_cache->compact_udt_code_hash),
                 &(g_cudt_cache->compact_udt_hash_type));
  CUDT_CHECK(err);
  if (has_id) {
    g_cudt_cache->identity = (Identity*)alloc_cache(sizeof(Identity));
    memcpy(g_cudt_cache->identity, &identity, sizeof(Identity));
  }

  err = load_cur_cell_data();
  CUDT_CHECK(err);

  err = load_all_other_cell_data();
  CUDT_CHECK(err);

exit_func:
  return err;
}

////////////////////////////////////////////////////////////////////////////////
// check

ckb_res_code check_total_udt() {
  ckb_res_code err = CUDT_SUCCESS;
  CacheData* cur_cache = &(g_cudt_cache->cur_data);

  // cur total deposit
  uint128_t total_deposit_other = 0;
  for (CacheDeposit* cache = cur_cache->deposits; cache != NULL;
       cache = cache->next) {
    if (cache->source &&
        memcmp(cache->source, &(g_cudt_cache->cur_data.script_hash),
               sizeof(Hash)) != 0) {
      ADD_SELF_AND_CHECK_OVERFOLW(total_deposit_other, cache->amount);
    } else {
      CUDT_CHECK(CUDTERR_DEPOSIT_INVALID);
    }
  }

  // cur total transfer (to other)
  uint128_t total_transfer = 0, total_transfer_other = 0;
  uint128_t total_fee = 0, total_fee_other = 0;
  for (CacheTransfer* cache = cur_cache->transfers; cache != NULL;
       cache = cache->next) {
    Hash* target_cell = NULL;
    if (cache->target_type == TargetType_ScriptHash) {
      if (memcmp(cache->target, &(g_cudt_cache->cur_data.script_hash),
                 sizeof(Hash)) != 0)
        target_cell = (Hash*)cache->target;
    } else if (cache->target_type == TargetType_MoveBetweenCompactSMT) {
      if (memcmp(&(cache->target[sizeof(Identity)]),
                 &(g_cudt_cache->cur_data.script_hash), sizeof(Hash)) != 0)
        target_cell = (Hash*)&(cache->target[sizeof(Identity)]);
    }
    if (target_cell) {
      ADD_SELF_AND_CHECK_OVERFOLW(total_transfer_other, cache->amount);
      ADD_SELF_AND_CHECK_OVERFOLW(total_fee_other, cache->fee);
    } else {
      ADD_SELF_AND_CHECK_OVERFOLW(total_transfer, cache->amount);
      ADD_SELF_AND_CHECK_OVERFOLW(total_fee, cache->fee);
    }
  }

  uint128_t cur_cache_input_amount = 0, total_fee_all = 0;
  ADD_AND_CHECK_OVERFOLW(cur_cache->input_amount, total_deposit_other,
                         cur_cache_input_amount);
  ADD_AND_CHECK_OVERFOLW(total_fee, total_fee_other, total_fee_all);
  if (cur_cache_input_amount < total_fee_all)
    return CUDTERR_NO_ENOUGH_UDT;
  if (cur_cache_input_amount - total_fee_all < cur_cache->output_amount)
    return CUDTERR_NO_ENOUGH_UDT;

  ADD_AND_CHECK_OVERFOLW(g_cudt_cache->other_cell_input_amount,
                         total_transfer_other, cur_cache_input_amount);
  if (cur_cache_input_amount < total_deposit_other)
    return CUDTERR_NO_ENOUGH_UDT;
  if (cur_cache_input_amount - total_deposit_other <
      g_cudt_cache->other_cell_output_amount)
    return CUDTERR_NO_ENOUGH_UDT;

exit_func:
  return err;
}

#define MAX_SMT_PAIR 2000
ckb_res_code check_smt_root(Hash* hash) {
  ckb_res_code err = CKBERR_UNKNOW;

  smt_state_t smt_statue = {0};
  smt_pair_t smt_pairs[MAX_SMT_PAIR] = {0};
  smt_state_init(&smt_statue, smt_pairs, MAX_SMT_PAIR);
  CUDT_CHECK2(g_cudt_cache->kv_pairs_len < MAX_SMT_PAIR, CUDTERR_KV_TOO_LONG);

  for (uint32_t i = 0; i < g_cudt_cache->kv_pairs_len; i++) {
    CacheKVPair* kv = &(g_cudt_cache->kv_pairs[i]);
    smt_state_insert(&smt_statue, (const uint8_t*)&(kv->key),
                     (const uint8_t*)&(kv->value));
  }

  smt_state_normalize(&smt_statue);
  Hash out_hash = {0};
  smt_calculate_root((uint8_t*)&out_hash, &smt_statue, g_cudt_cache->kv_proof,
                     g_cudt_cache->kv_proof_len);
  int mem_ret = memcmp(&out_hash, hash, sizeof(Hash));
  if (mem_ret != 0)
    return CUDTERR_KV_VERIFY;

  err = CUDT_SUCCESS;
exit_func:
  return err;
}

ckb_res_code check_deposit(CacheDeposit* cache) {
  ckb_res_code err = CUDT_SUCCESS;

  CacheData* source_cache = NULL;

  int ret_code = memcmp(cache->source, &(g_cudt_cache->cur_data.script_hash),
                        sizeof(Hash));
  CUDT_CHECK2(ret_code != 0, CUDTERR_DEPOSIT_INVALID);
  source_cache = find_other_cache(cache->source);

  if (!source_cache)
    return CUDTERR_DEPOSIT_INVALID;
  if (!source_cache->is_compact_udt) {
    return CUDT_SUCCESS;
  }

  bool has = false;
  CacheTransfer* ct = source_cache->transfers;
  for (; ct != NULL; ct = ct->next) {
    if (ct->amount != cache->amount)
      continue;
    if (ct->fee != cache->fee)
      continue;
    if (ct->flag)
      continue;

    ct->flag = true;
    has = true;
    break;
  }
  if (!has)
    return CUDTERR_DEPOSIT_INVALID;

exit_func:
  return err;
}

CacheKVPair* find_kv_pair(const Identity* identity) {
  ASSERT_DBG(identity);
  for (uint32_t i = 0; i < g_cudt_cache->kv_pairs_len; i++) {
    if (memcmp(&(g_cudt_cache->kv_pairs[i].key), identity, sizeof(Identity)) ==
        0) {
      return &g_cudt_cache->kv_pairs[i];
    }
  }
  ASSERT_DBG(false);
  return NULL;
}

ckb_res_code check_each_deposit() {
  ckb_res_code err = CUDT_SUCCESS;

  for (CacheDeposit* cache = g_cudt_cache->cur_data.deposits; cache != NULL;
       cache = cache->next) {
    err = check_deposit(cache);
    CUDT_CHECK(err);

    CacheKVPair* kv_pair = find_kv_pair(&(cache->target));
    if (!kv_pair)
      return CUDTERR_DEPOSIT_NO_KVPAIR;
    ADD_SELF_AND_CHECK_OVERFOLW(kv_pair->value.amount, cache->amount);
  }

exit_func:
  return err;
}

ckb_res_code check_transfer(CacheTransfer* cache,
                            Hash* hash,
                            Identity* identity) {
  ckb_res_code err = CUDT_SUCCESS;
  if (hash == NULL)
    return CUDT_SUCCESS;

  CacheData* other_data = find_other_cache(hash);
  if (!other_data)
    return CUDTERR_TRANSFER_INVALID;
  if (!other_data->is_compact_udt) {
    return CUDT_SUCCESS;
  }

  bool has = false;
  CacheDeposit* cd = other_data->deposits;
  for (; cd != NULL; cd = cd->next) {
    if (cd->amount != cache->amount)
      continue;
    if (cd->fee != cache->fee)
      continue;
    if (cd->flag)
      continue;

    if (identity) {
      if (memcmp(identity, &(cd->target), sizeof(Identity)) != 0) {
        continue;
      }
    }

    cd->flag = true;
    has = true;
    break;
  }
  if (!has)
    return CUDTERR_TRANSFER_INVALID;
  return err;
}

ckb_res_code check_each_transfer() {
  ckb_res_code err = CUDT_SUCCESS;

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

    err = check_transfer(cache, hash, identity);
    CUDT_CHECK(err);

    CacheKVPair* src_kv = find_kv_pair(&(cache->source));
    if (!src_kv)
      return CUDTERR_TRANSFER_NO_KVPAIR;

    uint128_t cache_amount = 0;
    ADD_AND_CHECK_OVERFOLW(cache->amount, cache->fee, cache_amount);
    if (src_kv->value.amount < cache_amount)
      return CUDTERR_TRANSFER_ENOUGH_UDT;
    uint128_t val_amount = src_kv->value.amount - cache_amount;
    if (src_kv->value.amount <= val_amount)
      return CUDTERR_AMOUNT_OVERFLOW;
    src_kv->value.amount = val_amount;

    src_kv->value.nonce += 1;
    if (src_kv->value.nonce == 0)
      return CUDTERR_NONCE_OVERFLOW;

    if (identity && !hash) {
      CacheKVPair* tar_kv = find_kv_pair(identity);
      if (!tar_kv)
        return CUDTERR_TRANSFER_NO_KVPAIR;

      ADD_SELF_AND_CHECK_OVERFOLW(tar_kv->value.amount, cache->amount);
    }
  }

exit_func:
  return err;
}

int CKBMAIN(int argc, char* argv[]) {
  ckb_res_code err = CKBERR_UNKNOW;
#ifdef ENABLE_DEBUG
  printf("\n\n------------------------Begin------------------------\n");
#endif  // ENABLE_DEBUG

  err = load_all_data();
  CUDT_CHECK(err);

  err = check_total_udt();
  CUDT_CHECK(err);

  err = check_smt_root(&(g_cudt_cache->input_smt_hash));
  CUDT_CHECK(err);

  err = check_each_deposit();
  CUDT_CHECK(err);

  err = check_each_transfer();
  CUDT_CHECK(err);

  err = check_smt_root(&(g_cudt_cache->output_smt_hash));
  CUDT_CHECK(err);

  err = CUDT_SUCCESS;
exit_func:
#ifdef ENABLE_DEBUG
  printf("------------------------End------------------------\n");
#endif  // ENABLE_DEBUG
  return err;
}
