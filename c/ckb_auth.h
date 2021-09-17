#ifndef CKB_PRODUCTION_SCRIPTS_CKB_AUTH_H_
#define CKB_PRODUCTION_SCRIPTS_CKB_AUTH_H_

#include "ckb_consts.h"

// TODO: when ready, move it into ckb-c-stdlib
typedef struct CkbAuthType {
  uint8_t algorithm_id;
  uint8_t content[20];
} CkbAuthType;

enum EntryCategoryType {
  EntryCategoryExec = 0,
  EntryCategoryDynamicLinking = 1,
};

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
  AuthAlgorithmIdCkbMultisig = 6,
  AuthAlgorithmIdSchnorr = 7,
  AuthAlgorithmIdRsa = 8,
  AuthAlgorithmIdIso97962 = 9,
  AuthAlgorithmIdOwnerLock = 0xFC,
};

typedef int (*ckb_auth_validate_t)(uint8_t auth_algorithm_id,
                                   const uint8_t *signature,
                                   uint32_t signature_size,
                                   const uint8_t *message,
                                   uint32_t message_size, uint8_t *pubkey_hash,
                                   uint32_t pubkey_hash_size);

static uint8_t g_code_buff[120 * 1024];

int ckb_auth(CkbEntryType *entry, CkbAuthType *id, uint8_t *signature,
             uint32_t signature_size, const uint8_t *message32) {
  if (entry->entry_category == EntryCategoryDynamicLinking) {
    int err = 0;
    void *handle = NULL;
    size_t consumed_size = 0;
    err = ckb_dlopen2(entry->code_hash, entry->hash_type, g_code_buff,
                      sizeof(g_code_buff), &handle, &consumed_size);
    if (err != 0) return err;

    ckb_auth_validate_t func =
        (ckb_auth_validate_t)ckb_dlsym(handle, "ckb_auth_validate");
    if (func == 0) {
      return CKB_INVALID_DATA;
    }
    return func(id->algorithm_id, signature, signature_size, message32, 32,
                id->content, 20);
  } else if (entry->entry_category == EntryCategoryExec) {
    // TODO
    return CKB_INVALID_DATA;
  } else {
    return CKB_INVALID_DATA;
  }
}

#endif  // CKB_PRODUCTION_SCRIPTS_CKB_AUTH_H_
