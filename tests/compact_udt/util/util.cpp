#include "util.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>

extern "C" {
#include "simulator/compact_udt_lock_inc.h"

#include "secp256k1.h"
#include "secp256k1_recovery.h"
}

int getbin(int x) {
  if (x >= '0' && x <= '9')
    return x - '0';
  if (x >= 'A' && x <= 'F')
    return x - 'A' + 10;
  return x - 'a' + 10;
}

int hex2bin(uint8_t* buf, const char* src) {
  size_t length = strlen(src) / 2;
  if (src[0] == '0' && (src[1] == 'x' || src[1] == 'X')) {
    src += 2;
    length--;
  }
  for (size_t i = 0; i < length; i++) {
    buf[i] = (getbin(src[i * 2]) << 4) | getbin(src[i * 2 + 1]);
  }
  return length;
}

void random_mem(uint8_t* data, uint32_t len) {
  srand((unsigned)time(NULL));

  int lp = len / sizeof(int);
  for (int i = 0; i < lp; i++) {
    ((int*)data)[i] = rand();
  }
  int cp = len % sizeof(int);
  for (int i = 0; i < cp; i++) {
    data[i + lp * sizeof(int)] = (uint8_t)rand();
  }
}

void script_hash_randfull(Hash* hash) {
  random_mem((uint8_t*)hash, sizeof(Hash));
}

CIdentity CHashToCId(const CHash* h) {
  CIdentity id;
  memcpy(id.get(), h->ptr(), 21);
  return id;
}

void script_hash_str(Hash* hash, const char* src) {
  hex2bin((uint8_t*)hash, src);
}

Blake2b::Blake2b() {
  state_ = cudt_blake2b_init(CHash::len());
}
Blake2b::~Blake2b() {
  cudt_blake2b_uninit(state_);
}
void Blake2b::Update(void* d, size_t l) {
  cudt_blake2b_update(state_, d, l);
}
void Blake2b::Update(CHash* h) {
  cudt_blake2b_update(state_, h->get(), h->len());
}
CHash Blake2b::Final() {
  CHash ret;
  cudt_blake2b_final(state_, ret.get(), ret.len());
  return ret;
}

SMT::SMT() : smt_h_(cudt_smt_init(64)) {}
SMT::~SMT() {
  cudt_smt_uninit(smt_h_);
}
void SMT::insert(CHash* key, CHash* val) {
  cudt_smt_insert(smt_h_, key->get(), val->get());
}
bool SMT::verify(CBuffer& proof, CHash& root) {
  return cudt_smt_verify(smt_h_, root.get(), proof.data(), proof.size());
}
CHash SMT::calculate_root(const CBuffer& proof) {
  CHash ret;
  cudt_smt_calculate_root(smt_h_, ret.get(), proof.data(), proof.size());
  return ret;
}

uint8_t SECP256k1_SECKEY[32] = {1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11,
                                12, 13, 14, 15, 16, 1,  2,  3,  4,  5,  6,
                                7,  8,  9,  10, 11, 12, 13, 14, 15, 16};

CKBKey::CKBKey() : priv_key_(SECP256k1_SECKEY, 32) {
  ctx_ = secp256k1_context_create(SECP256K1_CONTEXT_SIGN |
                                  SECP256K1_CONTEXT_VERIFY);
}
CKBKey::CKBKey(CHash pri) : priv_key_(pri) {
  ctx_ = secp256k1_context_create(SECP256K1_CONTEXT_SIGN |
                                  SECP256K1_CONTEXT_VERIFY);
}
CKBKey::~CKBKey() {
  secp256k1_context_destroy((secp256k1_context*)ctx_);
}
CIdentity CKBKey::get_pubkey_hash() {
  uint8_t serialized_pubkey[33];
  secp256k1_pubkey pubkey = {0};
  size_t serialized_pubkey_len = 33;
  Blake2b b2;

  auto err = secp256k1_ec_pubkey_create((secp256k1_context*)ctx_, &pubkey,
                                        priv_key_.get());
  if (err == 0) {
    ASSERT_DBG(false);
    return CIdentity();
  }
  err = secp256k1_ec_pubkey_serialize((secp256k1_context*)ctx_,
                                      serialized_pubkey, &serialized_pubkey_len,
                                      &pubkey, SECP256K1_EC_COMPRESSED);
  if (err == 0) {
    ASSERT_DBG(false);
    return CIdentity();
  }

  b2.Update(serialized_pubkey, serialized_pubkey_len);

  CIdentity ret;
  auto ret_ptr = ret.get();
  ret_ptr[0] = 0;
  memcpy(ret_ptr + 1, b2.Final().get(), 20);
  return ret;
}
CBuffer CKBKey::signature(const CHash* msg) {
  secp256k1_ecdsa_recoverable_signature sig;

  secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN |
                                                    SECP256K1_CONTEXT_VERIFY);
  auto ret = secp256k1_ecdsa_sign_recoverable(ctx, &sig, msg->ptr(),
                                              priv_key_.get(), NULL, NULL);
  if (ret == 0) {
    ASSERT_DBG(false);
    return CBuffer();
  }

  CBuffer raw_sig;
  raw_sig.resize(65);

  int recid = 0;
  ret = secp256k1_ecdsa_recoverable_signature_serialize_compact(
      (secp256k1_context*)ctx_, raw_sig.data(), &recid, &sig);
  if (ret == 0) {
    ASSERT_DBG(false);
    return CBuffer();
  }
  raw_sig[64] = (uint8_t)recid;

  return raw_sig;
}
