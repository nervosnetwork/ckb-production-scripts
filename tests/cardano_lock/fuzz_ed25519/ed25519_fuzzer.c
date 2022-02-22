#include <ed25519.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifndef MOL2_EXIT
#define MOL2_EXIT ckb_exit
#endif
#define CKB_SUCCESS 0

int LLVMFuzzerTestOneInput(uint8_t *data, size_t size) {
  uint8_t sign[64] = {0};
  const size_t sign_len = sizeof(sign);

  uint8_t pub_key[32] = {0};
  const size_t pub_key_len = sizeof(pub_key);

  uint8_t tmp_new_msg[1] = {0};
  uint8_t *new_msg = tmp_new_msg;
  size_t new_msg_len = sizeof(tmp_new_msg);

  if (size == 0) {
    // pass
  } else if (size <= sign_len) {
    memcpy(sign, data, size);
  } else if (size > sign_len && size <= sign_len + pub_key_len) {
    memcpy(sign, data, sign_len);
    memcpy(pub_key, &data[sign_len], size - sign_len);
  } else {
    memcpy(sign, data, sign_len);
    memcpy(pub_key, &data[sign_len], pub_key_len);
    new_msg = &data[sign_len + pub_key_len];
    new_msg_len = size - sign_len - pub_key_len;
  }

  int suc = ed25519_verify(sign, new_msg, new_msg_len, pub_key);

  return 0;
}