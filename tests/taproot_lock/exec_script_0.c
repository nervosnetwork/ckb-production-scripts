// uncomment to enable printf in CKB-VM
#define CKB_C_STDLIB_PRINTF

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "ckb_syscalls.h"

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

// if first byte decoded by `args` is 0xFF, then return 1 (failed)
int main(int argc, char* argv[]) {
  if (argc >= 2) {
    const char* src = argv[1];
    size_t length = strlen(src);
    if (length > 1024) {
      return -1;
    }
    uint8_t buf[length / 2 + 1];
    size_t real_length = hex2bin(buf, src);
    if (real_length > 0 && buf[0] == 0xFF) {
      printf("taproot script returns with failed\n");
      return 1;  // failed
    }
  }
  printf("taproot script returns with success\n");
  return 0;
}
