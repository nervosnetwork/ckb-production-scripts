#ifndef CKB_PRODUCTION_SCRIPTS_CKB_AUTH_H_
#define CKB_PRODUCTION_SCRIPTS_CKB_AUTH_H_

// TODO: when ready, move it into ckb-c-stdlib
typedef struct CkbAuthType {
  uint8_t algorithm_id;
  uint8_t content[20];
} CkbAuthType;

typedef struct CkbEntryType {
  uint8_t code_hash[32];
  uint8_t hash_type;
  uint8_t entry_category;
} CkbEntryType;

enum AuthAlgorithmIdType {
  AuthAlgorithmIdCkb = 0,
  AuthAlgorithmIdEthereum = 1,
  AuthAlgorithmIdEos = 2,
  AuthAlgorithmIdTron = 3,
  AuthAlgorithmIdBitcoin = 4,
  AuthAlgorithmIdDogecoin = 5,
  AuthAlgorithmIdSchnorr = 6,
  AuthAlgorithmIdIso97962 = 7,
  AuthAlgorithmIdRsa = 8,
  AuthAlgorithmIdOwnerLock = 0xFC,
};

int ckb_auth(CkbEntryType *entry, CkbAuthType *id, uint8_t *signature,
             size_t signature_size, const uint8_t *message32) {
  return 0;
}

#endif  // CKB_PRODUCTION_SCRIPTS_CKB_AUTH_H_
