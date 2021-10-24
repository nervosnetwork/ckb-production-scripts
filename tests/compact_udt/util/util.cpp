#include "util.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>

extern "C" {
#include "simulator/compact_udt_lock_inc.h"
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
