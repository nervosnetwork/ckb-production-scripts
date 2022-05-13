// uncomment to enable printf in CKB-VM
#define CKB_C_STDLIB_PRINTF

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// reuse some code in taproot_lock.
#define main removed_main
#include "taproot_lock.c"
#undef main

int getbin(int x) {
  if (x >= '0' && x <= '9') return x - '0';
  if (x >= 'A' && x <= 'F') return x - 'A' + 10;
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

enum ExampleErrorCode {
  ERROR_WRONG_ARGS = 90,
  ERROR_WRONG_ARGS2,
  ERROR_WRONG_ARGS3,
  ERROR_WRONG_ARGS4,
  ERROR_WRONG_ARGS5,
};

int main(int argc, char* argv[]) {
  int length = 0;
  int err = 0;
  CHECK2(argc >= 2, ERROR_WRONG_ARGS);

  uint8_t auth[21] = {0};
  uint8_t signature[SCHNORR_SIGNATURE_SIZE] = {0};
  length = strlen(argv[0]);
  printf("argc = %d", argc);
  printf("length = %d", length);
  CHECK2(length == sizeof(auth) * 2, ERROR_WRONG_ARGS2);

  length = hex2bin(auth, argv[0]);
  CHECK2(length == sizeof(auth), ERROR_WRONG_ARGS2);

  length = strlen(argv[1]);
  CHECK2(length == sizeof(signature) * 2, ERROR_WRONG_ARGS3);

  length = hex2bin(signature, argv[1]);
  CHECK2(length == sizeof(signature), ERROR_WRONG_ARGS3);

  err = verify_sighash_all(auth + 1, signature, SCHNORR_SIGNATURE_SIZE,
                           validate_signature_schnorr, _ckb_convert_copy);
  CHECK(err);
exit:
  return err;
}
