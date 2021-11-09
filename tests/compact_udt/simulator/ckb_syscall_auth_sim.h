
#ifndef CKB_C_STDLIB_CKB_SYSCALLS_H_
#define CKB_C_STDLIB_CKB_SYSCALLS_H_

#include <stddef.h>
#include <stdint.h>

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

int ckb_auth(CkbEntryType* entry,
             CkbAuthType* id,
             const uint8_t* signature,
             uint32_t signature_size,
             const uint8_t* message32);

int ckb_exec_cell(const uint8_t* code_hash, uint8_t hash_type, uint32_t offset,
                  uint32_t length, int argc, const char* argv[]);
int ckb_dlopen2(const uint8_t* dep_cell_hash, uint8_t hash_type,
                uint8_t* aligned_addr, size_t aligned_size, void** handle,
                size_t* consumed_size);
void* ckb_dlsym(void* handle, const char* symbol);

#endif  // CKB_C_STDLIB_CKB_SYSCALLS_H_
