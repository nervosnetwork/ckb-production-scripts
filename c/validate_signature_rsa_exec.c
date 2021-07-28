
// clang-format off
#include "validate_signature_rsa.c"
#include "ckb_consts.h"
#include "ckb_exec.h"
#include "ckb_syscalls.h"
#include "string.h"
// clang-format on

enum ValidateSignatureRsaErrorCode {
  ERROR_EXEC_INVALID_LENGTH = 90,
  ERROR_EXEC_INVALID_PARAM,
  ERROR_EXEC_NOT_PAIRED,
  ERROR_EXEC_INVALID_SIG,
  ERROR_EXEC_INVALID_MSG,
};

#define MAX_ENTRY_SIZE 128
typedef struct ValidationEntry {
  uint8_t* pubkey_hash;
  uint32_t pubkey_hash_len;

  uint8_t* msg;
  uint32_t msg_len;
  uint8_t* sig;
  uint32_t sig_len;
} ValidationEntry;

int chained_continue(int argc, char* argv[]) {
  int err = 0;
  char* next = NULL;
  uint8_t* param_ptr = NULL;
  uint32_t param_len = 0;

  size_t param_index = 0;
  uint8_t next_code_hash[32] = {0};

  // don't change argv[1] in place
  char argv1[256] = {0};
  size_t argv1_len = strlen(argv[1]);
  if (argv1_len >= 255) {
    memcpy(argv1, argv[1], 255);
  } else {
    memcpy(argv1, argv[1], argv1_len);
  }

  next = argv1;
  while (true) {
    CHECK2(next != NULL, ERROR_EXEC_INVALID_LENGTH);
    err = ckb_exec_decode_params(next, &param_ptr, &param_len, &next);
    CHECK(err);
    CHECK2(param_len > 0, ERROR_EXEC_INVALID_LENGTH);
    if (param_index == 0) {
      CHECK2(param_len == 32, ERROR_EXEC_INVALID_LENGTH);
      memcpy(next_code_hash, param_ptr, 32);
    } else if (param_index == 1) {
      CHECK2(param_len == 1, ERROR_EXEC_INVALID_LENGTH);
      return ckb_exec_cell(next_code_hash, *param_ptr, 0, 0, argc - 1,
                           (const char**)(argv + 1));
    }
    param_index++;
  }

exit:
  return err;
}

// https://talk.nervos.org/t/ideas-on-chained-locks/5887
// argv format:
// <code hash in hex>:<hash type in hex>:<pubkey hash 1>:<message 1>:<signature
// 1>:<pubkey hash 2>:<message 2>:<signature 2>:...:<pubkey hash n>:<message
// n>:<signature n>
int main(int argc, char* argv[]) {
  int err = 0;
  uint8_t* param_ptr = NULL;
  uint32_t param_len = 0;

  if (argc <= 0) {
    // TODO: should work like RSA lock
    return -1;
  }

  char* next = argv[0];
  int param_index = 0;
  ValidationEntry entries[MAX_ENTRY_SIZE] = {0};
  size_t entry_index = 0;
  while (true) {
    // pattern to use "ckb_exec_decode_params":
    // if next is NULL, in last iterator, it encounters \0.
    // when error is returned, there must be an error in call
    if (next == NULL) break;
    err = ckb_exec_decode_params(next, &param_ptr, &param_len, &next);
    CHECK(err);

    if (param_index == 0) {
      // code hash
      CHECK2(param_len == 32, ERROR_EXEC_INVALID_LENGTH);
    } else if (param_index == 1) {
      // hash type
      CHECK2(param_len == 1, ERROR_EXEC_INVALID_LENGTH);
    } else if ((param_index - 2) % 3 == 0) {
      // pubkey hash
      CHECK2(param_len == 20, ERROR_EXEC_INVALID_LENGTH);
      entry_index = (param_index - 2) / 3;
      CHECK2(entry_index < MAX_ENTRY_SIZE, CKB_INDEX_OUT_OF_BOUND);
      entries[entry_index].pubkey_hash = param_ptr;
      entries[entry_index].pubkey_hash_len = param_len;
    } else if ((param_index - 2) % 3 == 1) {
      // message
      CHECK2(param_len == 32, ERROR_EXEC_INVALID_MSG);
      entry_index = (param_index - 2) / 3;
      CHECK2(entry_index < MAX_ENTRY_SIZE, CKB_INDEX_OUT_OF_BOUND);
      entries[entry_index].msg = param_ptr;
      entries[entry_index].msg_len = param_len;
    } else if ((param_index - 2) % 3 == 2) {
      // signature
      CHECK2(param_len == 264, ERROR_EXEC_INVALID_SIG);
      entry_index = (param_index - 2) / 3;
      CHECK2(entry_index < MAX_ENTRY_SIZE, CKB_INDEX_OUT_OF_BOUND);
      entries[entry_index].sig = param_ptr;
      entries[entry_index].sig_len = param_len;
    } else {
      // code error
      CHECK2(false, ERROR_EXEC_INVALID_PARAM);
    }
    param_index++;
  }
  // All of sig, msg, pubkey_hash must be present
  CHECK2(entries[entry_index].sig_len > 0, ERROR_EXEC_NOT_PAIRED);
  CHECK2(entries[entry_index].pubkey_hash_len > 0, ERROR_EXEC_NOT_PAIRED);
  CHECK2(entries[entry_index].msg_len > 0, ERROR_EXEC_NOT_PAIRED);

  for (size_t i = 0; i <= entry_index; i++) {
    ValidationEntry* entry = entries + i;
    uint8_t output[20];
    size_t output_len = 20;
    err = validate_signature_rsa(NULL, entry->sig, entry->sig_len, entry->msg,
                                 entry->msg_len, output, &output_len);
    CHECK(err);
    int same = memcmp(output, entry->pubkey_hash, entry->pubkey_hash_len);
    CHECK2(same == 0, ERROR_RSA_VERIFY_FAILED);
  }

  if (argc > 1) {
    // The chained lock script would locate the cell using code hash and hash
    // type included in argv[1]. It will then remove argv[0] from argvs, then
    // use the remaining arguments to invoke exec syscall using binary provided
    // by the located cell.
    err = chained_continue(argc, argv);
    CHECK(err);
  }

exit:
  return err;
}
